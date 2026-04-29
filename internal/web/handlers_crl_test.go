package web

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/store"
)

func TestCRL_Endpoint_ServesCachedDER(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	w := c.get("/crl/" + interID + ".crl")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pkix-crl", w.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=300, must-revalidate", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Header().Get("Warning"), "fresh CRL should not carry a Warning header")
	// Body should parse as a valid CRL.
	_, err := x509.ParseRevocationList(w.Body.Bytes())
	assert.NoError(t, err, "body does not parse as CRL")
}

func TestCRL_Endpoint_404OnUnknownIssuer(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/crl/no-such-id.crl")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCRL_Endpoint_404OnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// Leaves don't have CRLs (they don't issue anything).
	w := c.get("/crl/" + leafID + ".crl")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCRL_Endpoint_RejectsMissingSuffix(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Without the .crl suffix it's not a real CRL URL.
	w := c.get("/crl/" + interID)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCRL_Endpoint_StaleWithLockedKeystore(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Force the existing CRL to look stale by rewriting next_update into
	// the past directly in the DB.
	_, err := db.Exec(
		`UPDATE crls SET next_update = datetime('now', '-1 hour') WHERE issuer_cert_id = ?`,
		interID,
	)
	require.NoError(t, err)
	srv.keystore.Lock()

	w := c.get("/crl/" + interID + ".crl")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Warning"), "CRL past nextUpdate")
	// Body still parses (it's the original cached CRL).
	_, err = x509.ParseRevocationList(w.Body.Bytes())
	assert.NoError(t, err, "stale body does not parse")
}

func TestCRL_Endpoint_RegeneratesWhenStaleAndUnlocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Pretend the cached CRL is stale.
	_, err := db.Exec(
		`UPDATE crls SET next_update = datetime('now', '-1 hour') WHERE issuer_cert_id = ?`,
		interID,
	)
	require.NoError(t, err)

	w := c.get("/crl/" + interID + ".crl")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Warning"), "unlocked + regen should not carry Warning header")

	// CRL number bumped and the new row's next_update is in the future.
	got, err := store.GetLatestCRL(db, interID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.CRLNumber, "CRL number should be 2 (regenerated)")
	assert.True(t, got.NextUpdate.After(time.Now()), "regenerated CRL next_update is not in the future")
}

func TestCRL_Endpoint_NoAuthRequired(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Now drop the session cookie — the CRL endpoint must work for an
	// unauthenticated client (curl, openssl, etc.).
	delete(c.cookies, SessionCookieName)

	w := c.get("/crl/" + interID + ".crl")
	assert.Equal(t, http.StatusOK, w.Code, "unauthenticated CRL fetch")
}

func TestCRL_Endpoint_BareCurl(t *testing.T) {
	// Sanity: a request with NO cookies at all (a fresh curl-style hit)
	// gets the CRL bytes without going through any auth flow.
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Synthesize a cookieless request (skip the clientLite cookie threading).
	req := httptest.NewRequest(http.MethodGet, "/crl/"+interID+".crl", nil)
	req.Header.Set("Referer", "https://example.com/")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	_, err := x509.ParseRevocationList(w.Body.Bytes())
	assert.NoError(t, err, "body does not parse")
}

// Sanity that the unused url import in earlier tests doesn't drift.
var _ = url.Values{}
