package web

import (
	"crypto/x509"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
)

// issueChain runs the GET-then-POST cycle for root → intermediate → leaf
// using the actual issuance handlers, returning their IDs. Lets revoke
// tests start from real signed certs (so the CRL signatures verify).
func issueChain(t *testing.T, c *clientLite) (rootID, interID, leafID string) {
	t.Helper()
	rootID = mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Revoke Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})
	interID = mustIssue(t, c, "/certs/new/intermediate", url.Values{
		"parent_id":       {rootID},
		"subject_cn":      {"Revoke Intermediate"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"1825"},
	})
	leafID = mustIssue(t, c, "/certs/new/leaf", url.Values{
		"parent_id":       {interID},
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
	})
	return
}

func TestRevoke_LeafUpdatesIssuerCRL(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	_, interID, leafID := issueChain(t, c)

	// Initial CRL on intermediate is empty (the issuance flow created it).
	cached, err := store.GetLatestCRL(db, interID)
	if err != nil {
		t.Fatalf("GetLatestCRL initial: %v", err)
	}
	if cached.CRLNumber != 1 {
		t.Errorf("initial CRL number: got %d, want 1", cached.CRLNumber)
	}

	// Look up the leaf's serial so we can assert it appears on the new CRL.
	leafCert, err := store.GetCert(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	wantSerial, _ := new(big.Int).SetString(leafCert.SerialNumber, 16)

	// Visit the detail page first so the CSRF token is in the client jar.
	c.get("/certs/" + leafID)

	// Revoke with reason 1 (keyCompromise).
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/certs/"+leafID {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}

	// Cert is now revoked.
	got, err := store.GetCert(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" {
		t.Errorf("status: got %q, want revoked", got.Status)
	}

	// Intermediate's CRL has bumped to number 2 and lists the leaf serial.
	regen, err := store.GetLatestCRL(db, interID)
	if err != nil {
		t.Fatal(err)
	}
	if regen.CRLNumber != 2 {
		t.Errorf("CRL number after revoke: got %d, want 2", regen.CRLNumber)
	}
	parsedCRL, err := x509.ParseRevocationList(regen.DER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(parsedCRL.RevokedCertificateEntries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(parsedCRL.RevokedCertificateEntries))
	}
	if parsedCRL.RevokedCertificateEntries[0].SerialNumber.Cmp(wantSerial) != 0 {
		t.Errorf("revoked serial: got %s, want %s",
			parsedCRL.RevokedCertificateEntries[0].SerialNumber, wantSerial)
	}
	if parsedCRL.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("reason code: got %d, want 1", parsedCRL.RevokedCertificateEntries[0].ReasonCode)
	}

	// And the CRL signature verifies under the intermediate.
	interStoreCert, err := store.GetCert(db, interID)
	if err != nil {
		t.Fatal(err)
	}
	interParsed, err := x509.ParseCertificate(interStoreCert.DERCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsedCRL.CheckSignatureFrom(interParsed); err != nil {
		t.Errorf("CRL signature does not verify under intermediate: %v", err)
	}
}

func TestRevoke_IdempotentReplay(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, leafID := issueChain(t, c)

	c.get("/certs/" + leafID)

	// First revoke: regular 303.
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first revoke: %d", w.Code)
	}
	crlAfter1, _ := store.GetLatestCRL(db, interID)

	// Second revoke on same cert: should still 303 (no error), CRL number
	// should NOT bump (we no-op when the cert is already revoked).
	w = c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusSeeOther {
		t.Errorf("replay: got %d, want 303", w.Code)
	}
	crlAfter2, _ := store.GetLatestCRL(db, interID)
	if crlAfter2.CRLNumber != crlAfter1.CRLNumber {
		t.Errorf("CRL bumped on replay: %d -> %d", crlAfter1.CRLNumber, crlAfter2.CRLNumber)
	}
}

func TestRevoke_RejectsBadReason(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	c.get("/certs/" + leafID)

	// Reason code 6 (certificateHold) is excluded per LIFECYCLE.md §5.2.
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"6"}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	// And empty reason fails too.
	w = c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {""}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty reason: got %d, want 400", w.Code)
	}
}

func TestRevoke_RejectsCAReasonOnLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	c.get("/certs/" + leafID)

	// cACompromise (2) is CA-only.
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"2"}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestRevoke_NotFound(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	c.get("/") // prime CSRF

	w := c.postForm("/certs/no-such-id/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestRevoke_RedirectsWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	c.get("/certs/" + leafID) // grab CSRF token before lock

	srv.keystore.Lock()

	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestDetailHidesRevokeOnAlreadyRevoked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)
	c.get("/certs/" + leafID)
	c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})

	// Detail page should no longer offer to revoke.
	w := c.get("/certs/" + leafID)
	if strings.Contains(w.Body.String(), "Revoke this certificate") {
		t.Error("revoke form still shown on already-revoked cert")
	}
	if !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("status not displayed as revoked")
	}
	_ = db
}
