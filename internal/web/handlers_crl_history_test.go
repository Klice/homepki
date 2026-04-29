package web

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/store"
)

// crlHistoryFixture issues a chain and revokes the leaf so the intermediate
// has at least 2 CRLs (initial + post-revocation). Returns server, primed
// client, and the intermediate id (the CA whose history is interesting).
func crlHistoryFixture(t *testing.T) (*Server, *clientLite, string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, leafID := issueChain(t, c)

	// Trigger a second CRL by revoking the leaf.
	c.get("/certs/" + leafID)
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	require.Equal(t, http.StatusSeeOther, w.Code, "revoke setup failed")

	// Sanity: store has exactly 2 CRLs for the intermediate.
	crls, err := store.ListCRLs(db, interID)
	require.NoError(t, err)
	require.Len(t, crls, 2, "setup CRLs")
	return srv, c, interID
}

// ============== history page ==============

func TestCRLHistory_PageRendersAllRowsNewestFirst(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)

	w := c.get("/certs/" + interID + "/crls")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	for _, want := range []string{
		"CRL history",
		"Revoke Intermediate",
		"latest", // pill on the newest row
		"/crl/" + interID + "/2.crl",
		"/crl/" + interID + "/1.crl",
	} {
		assert.Contains(t, body, want)
	}
	// CRL #2 should appear before CRL #1 (newest first).
	idx2 := strings.Index(body, "/crl/"+interID+"/2.crl")
	idx1 := strings.Index(body, "/crl/"+interID+"/1.crl")
	assert.True(t, idx2 >= 0 && idx1 >= 0 && idx2 < idx1, "CRL #2 should appear before CRL #1; got idx2=%d idx1=%d", idx2, idx1)
}

func TestCRLHistory_404OnUnknownCert(t *testing.T) {
	_, c, _ := crlHistoryFixture(t)
	w := c.get("/certs/nope/crls")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCRLHistory_404OnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	_ = srv

	w := c.get("/certs/" + leafID + "/crls")
	assert.Equal(t, http.StatusNotFound, w.Code, "leaf history")
	_ = db
}

func TestCRLHistory_RedirectsWhenLocked(t *testing.T) {
	srv, c, interID := crlHistoryFixture(t)
	srv.keystore.Lock()

	w := c.get("/certs/" + interID + "/crls")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

func TestCertDetail_LinksToCRLHistoryForCAs(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	rootID, interID, leafID := issueChain(t, c)
	_ = srv

	for _, id := range []string{rootID, interID} {
		body := c.get("/certs/" + id).Body.String()
		assert.Contains(t, body, "/certs/"+id+"/crls", "CA %s detail missing CRL history link", id)
	}
	body := c.get("/certs/" + leafID).Body.String()
	assert.NotContains(t, body, "/crls", "leaf detail should not link to CRL history")
	_ = db
}

// ============== historical CRL download ==============

func TestCRLByNumber_RoundTrip(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)

	// CRL #1 should be the empty initial CRL (entries == 0).
	w := c.get("/crl/" + interID + "/1.crl")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pkix-crl", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "immutable")
	parsed, err := x509.ParseRevocationList(w.Body.Bytes())
	require.NoError(t, err, "ParseRevocationList")
	assert.Empty(t, parsed.RevokedCertificateEntries, "CRL #1 should be empty")

	// CRL #2 has the revoked leaf.
	w = c.get("/crl/" + interID + "/2.crl")
	require.Equal(t, http.StatusOK, w.Code)
	parsed, err = x509.ParseRevocationList(w.Body.Bytes())
	require.NoError(t, err, "ParseRevocationList")
	assert.Len(t, parsed.RevokedCertificateEntries, 1, "CRL #2 entries")
}

func TestCRLByNumber_PublicAccess(t *testing.T) {
	// Public endpoint — works without a session cookie, matching the
	// existing /crl/{id}.crl behaviour.
	srv, _, interID := crlHistoryFixture(t)
	c := newClient(t, srv) // no installSession
	w := c.get("/crl/" + interID + "/1.crl")
	assert.Equal(t, http.StatusOK, w.Code, "unauthenticated GET")
}

func TestCRLByNumber_404OnNonNumericSegment(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/abc.crl")
	assert.Equal(t, http.StatusNotFound, w.Code, "non-numeric")
}

func TestCRLByNumber_404OnMissingCRL(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/99.crl")
	assert.Equal(t, http.StatusNotFound, w.Code, "missing CRL")
}

func TestCRLByNumber_404OnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	_ = srv
	_ = db

	w := c.get("/crl/" + leafID + "/1.crl")
	assert.Equal(t, http.StatusNotFound, w.Code, "leaf historical CRL")
}

func TestCRLByNumber_404OnMissingSuffix(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/1")
	assert.Equal(t, http.StatusNotFound, w.Code, "no .crl suffix")
}
