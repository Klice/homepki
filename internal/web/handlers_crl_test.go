package web

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Klice/homepki/internal/store"
)

func TestCRL_Endpoint_ServesCachedDER(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	w := c.get("/crl/" + interID + ".crl")
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type: got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300, must-revalidate" {
		t.Errorf("Cache-Control: got %q", cc)
	}
	if w.Header().Get("Warning") != "" {
		t.Errorf("fresh CRL should not carry a Warning header, got %q", w.Header().Get("Warning"))
	}
	// Body should parse as a valid CRL.
	if _, err := x509.ParseRevocationList(w.Body.Bytes()); err != nil {
		t.Errorf("body does not parse as CRL: %v", err)
	}
}

func TestCRL_Endpoint_404OnUnknownIssuer(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/crl/no-such-id.crl")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestCRL_Endpoint_404OnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// Leaves don't have CRLs (they don't issue anything).
	w := c.get("/crl/" + leafID + ".crl")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestCRL_Endpoint_RejectsMissingSuffix(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Without the .crl suffix it's not a real CRL URL.
	w := c.get("/crl/" + interID)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestCRL_Endpoint_StaleWithLockedKeystore(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Force the existing CRL to look stale by rewriting next_update into
	// the past directly in the DB.
	if _, err := db.Exec(
		`UPDATE crls SET next_update = datetime('now', '-1 hour') WHERE issuer_cert_id = ?`,
		interID,
	); err != nil {
		t.Fatal(err)
	}
	srv.keystore.Lock()

	w := c.get("/crl/" + interID + ".crl")
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Warning"), "CRL past nextUpdate") {
		t.Errorf("expected Warning header on stale-locked response, got %q", w.Header().Get("Warning"))
	}
	// Body still parses (it's the original cached CRL).
	if _, err := x509.ParseRevocationList(w.Body.Bytes()); err != nil {
		t.Errorf("stale body does not parse: %v", err)
	}
}

func TestCRL_Endpoint_RegeneratesWhenStaleAndUnlocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, _ := issueChain(t, c)

	// Pretend the cached CRL is stale.
	if _, err := db.Exec(
		`UPDATE crls SET next_update = datetime('now', '-1 hour') WHERE issuer_cert_id = ?`,
		interID,
	); err != nil {
		t.Fatal(err)
	}

	w := c.get("/crl/" + interID + ".crl")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if w.Header().Get("Warning") != "" {
		t.Errorf("unlocked + regen should not carry Warning header, got %q", w.Header().Get("Warning"))
	}

	// CRL number bumped and the new row's next_update is in the future.
	got, err := store.GetLatestCRL(db, interID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CRLNumber != 2 {
		t.Errorf("CRL number: got %d, want 2 (regenerated)", got.CRLNumber)
	}
	if !got.NextUpdate.After(time.Now()) {
		t.Errorf("regenerated CRL next_update is not in the future: %v", got.NextUpdate)
	}
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
	if w.Code != http.StatusOK {
		t.Errorf("unauthenticated CRL fetch: got %d, want 200", w.Code)
	}
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
	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
	if _, err := x509.ParseRevocationList(w.Body.Bytes()); err != nil {
		t.Errorf("body does not parse: %v", err)
	}
}

// Sanity that the unused url import in earlier tests doesn't drift.
var _ = url.Values{}
