package web

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"

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
	if w.Code != http.StatusSeeOther {
		t.Fatalf("revoke setup failed: %d body=%q", w.Code, w.Body.String())
	}

	// Sanity: store has exactly 2 CRLs for the intermediate.
	crls, err := store.ListCRLs(db, interID)
	if err != nil {
		t.Fatal(err)
	}
	if len(crls) != 2 {
		t.Fatalf("setup CRLs: got %d, want 2", len(crls))
	}
	return srv, c, interID
}

// ============== history page ==============

func TestCRLHistory_PageRendersAllRowsNewestFirst(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)

	w := c.get("/certs/" + interID + "/crls")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"CRL history",
		"Revoke Intermediate",
		"latest", // pill on the newest row
		"/crl/" + interID + "/2.crl",
		"/crl/" + interID + "/1.crl",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// CRL #2 should appear before CRL #1 (newest first).
	idx2 := strings.Index(body, "/crl/"+interID+"/2.crl")
	idx1 := strings.Index(body, "/crl/"+interID+"/1.crl")
	if idx2 < 0 || idx1 < 0 || idx2 >= idx1 {
		t.Errorf("CRL #2 should appear before CRL #1; got idx2=%d idx1=%d", idx2, idx1)
	}
}

func TestCRLHistory_404OnUnknownCert(t *testing.T) {
	_, c, _ := crlHistoryFixture(t)
	w := c.get("/certs/nope/crls")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestCRLHistory_404OnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	_ = srv

	w := c.get("/certs/" + leafID + "/crls")
	if w.Code != http.StatusNotFound {
		t.Errorf("leaf history: got %d, want 404", w.Code)
	}
	_ = db
}

func TestCRLHistory_RedirectsWhenLocked(t *testing.T) {
	srv, c, interID := crlHistoryFixture(t)
	srv.keystore.Lock()

	w := c.get("/certs/" + interID + "/crls")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
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
		if !strings.Contains(body, "/certs/"+id+"/crls") {
			t.Errorf("CA %s detail missing CRL history link", id)
		}
	}
	body := c.get("/certs/" + leafID).Body.String()
	if strings.Contains(body, "/crls") {
		t.Errorf("leaf detail should not link to CRL history")
	}
	_ = db
}

// ============== historical CRL download ==============

func TestCRLByNumber_RoundTrip(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)

	// CRL #1 should be the empty initial CRL (entries == 0).
	w := c.get("/crl/" + interID + "/1.crl")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type: %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("expected immutable Cache-Control, got %q", cc)
	}
	parsed, err := x509.ParseRevocationList(w.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Errorf("CRL #1 should be empty, got %d entries", len(parsed.RevokedCertificateEntries))
	}

	// CRL #2 has the revoked leaf.
	w = c.get("/crl/" + interID + "/2.crl")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	parsed, err = x509.ParseRevocationList(w.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 {
		t.Errorf("CRL #2: got %d entries, want 1", len(parsed.RevokedCertificateEntries))
	}
}

func TestCRLByNumber_PublicAccess(t *testing.T) {
	// Public endpoint — works without a session cookie, matching the
	// existing /crl/{id}.crl behaviour.
	srv, _, interID := crlHistoryFixture(t)
	c := newClient(t, srv) // no installSession
	w := c.get("/crl/" + interID + "/1.crl")
	if w.Code != http.StatusOK {
		t.Errorf("unauthenticated GET: got %d, want 200", w.Code)
	}
}

func TestCRLByNumber_404OnNonNumericSegment(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/abc.crl")
	if w.Code != http.StatusNotFound {
		t.Errorf("non-numeric: got %d, want 404", w.Code)
	}
}

func TestCRLByNumber_404OnMissingCRL(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/99.crl")
	if w.Code != http.StatusNotFound {
		t.Errorf("missing CRL: got %d, want 404", w.Code)
	}
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
	if w.Code != http.StatusNotFound {
		t.Errorf("leaf historical CRL: got %d, want 404", w.Code)
	}
}

func TestCRLByNumber_404OnMissingSuffix(t *testing.T) {
	_, c, interID := crlHistoryFixture(t)
	w := c.get("/crl/" + interID + "/1")
	if w.Code != http.StatusNotFound {
		t.Errorf("no .crl suffix: got %d, want 404", w.Code)
	}
}
