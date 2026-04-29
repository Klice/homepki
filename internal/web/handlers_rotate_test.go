package web

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
)

func TestRotate_GetRendersPrefilledForm(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	w := c.get("/certs/" + leafID + "/rotate")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`action="/certs/` + leafID + `/rotate"`,
		`name="subject_cn" required autofocus value="revoke.leaf.test"`,
		`Rotate revoke.leaf.test`,
		`name="form_token"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestRotate_GetRefusesNonActive(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// Revoke first.
	c.get("/certs/" + leafID)
	c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})

	w := c.get("/certs/" + leafID + "/rotate")
	if w.Code != http.StatusConflict {
		t.Errorf("rotate revoked: got %d, want 409", w.Code)
	}
}

func TestRotate_LeafFullFlow(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, leafID := issueChain(t, c)

	// Capture old cert serial so we can confirm the successor differs.
	oldCert, err := store.GetCert(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := oldCert.SerialNumber

	// Drive the rotate flow through the actual GET → POST cycle.
	newID := mustIssue(t, c, "/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
		"parent_id":       {interID}, // matches the locked parent
	})

	if newID == leafID {
		t.Errorf("new id should differ from old: both = %s", newID)
	}

	// Old cert is now superseded with replaced_by_id pointing at the new one.
	old, err := store.GetCert(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != "superseded" {
		t.Errorf("old status: got %q, want superseded", old.Status)
	}
	if old.ReplacedByID == nil || *old.ReplacedByID != newID {
		t.Errorf("old.ReplacedByID: got %v, want %s", old.ReplacedByID, newID)
	}

	// New cert is active with replaces_id back-link, fresh serial, same SANs/CN.
	got, err := store.GetCert(db, newID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" {
		t.Errorf("new status: got %q", got.Status)
	}
	if got.ReplacesID == nil || *got.ReplacesID != leafID {
		t.Errorf("new.ReplacesID: got %v, want %s", got.ReplacesID, leafID)
	}
	if got.SerialNumber == oldSerial {
		t.Error("new serial should differ from old")
	}
	if got.SubjectCN != "revoke.leaf.test" {
		t.Errorf("new CN: got %q", got.SubjectCN)
	}
	if got.ParentID == nil || *got.ParentID != interID {
		t.Errorf("new parent: got %v, want %s", got.ParentID, interID)
	}

	// The new leaf chains under the same intermediate via x509.Verify.
	root, _ := store.GetCert(db, "") // sentinel below; load root via chain walk
	chain, err := store.GetChain(db, newID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length: got %d, want 3", len(chain))
	}
	root = chain[2]
	rootCert, _ := x509.ParseCertificate(root.DERCert)
	intermediateCert, _ := x509.ParseCertificate(chain[1].DERCert)
	leafCert, _ := x509.ParseCertificate(chain[0].DERCert)
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		DNSName:       "revoke.leaf.test",
	}); err != nil {
		t.Errorf("verify rotated leaf: %v", err)
	}
}

func TestRotate_RootFullFlow(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	rootID := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Old Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	newID := mustIssue(t, c, "/certs/"+rootID+"/rotate", url.Values{
		"subject_cn":      {"Old Root"}, // same CN
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	if newID == rootID {
		t.Fatal("rotated root has same id as original")
	}

	// New root is self-signed (no parent), active, with replaces_id link.
	newRoot, err := store.GetCert(db, newID)
	if err != nil {
		t.Fatal(err)
	}
	if newRoot.ParentID != nil {
		t.Errorf("new root should have no parent; got %v", newRoot.ParentID)
	}
	if newRoot.ReplacesID == nil || *newRoot.ReplacesID != rootID {
		t.Errorf("new root ReplacesID: got %v", newRoot.ReplacesID)
	}

	// New root has its OWN initial CRL with number 1 (not part of old's series).
	crl, err := store.GetLatestCRL(db, newID)
	if err != nil {
		t.Fatalf("new root CRL: %v", err)
	}
	if crl.CRLNumber != 1 {
		t.Errorf("new root CRL number: got %d, want 1", crl.CRLNumber)
	}
}

func TestRotate_FormTokenReplay(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// First rotate via the normal cycle.
	w := c.get("/certs/" + leafID + "/rotate")
	formTok := extractFormToken(t, w.Body.String())
	form := url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
		"form_token":      {formTok},
	}
	w = c.postForm("/certs/"+leafID+"/rotate", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first rotate: %d body=%q", w.Code, w.Body.String())
	}
	firstLoc := w.Header().Get("Location")

	// Replay: same token POSTed again. Per API.md §6.5 it should 303 to the
	// same successor, NOT create a second one.
	w = c.postForm("/certs/"+leafID+"/rotate", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("replay: %d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("Location") != firstLoc {
		t.Errorf("replay location: got %q, want %q", w.Header().Get("Location"), firstLoc)
	}

	// Sanity: only one successor exists. Two leaves total (the superseded
	// original + the active successor). Three or more would mean the
	// replay double-issued.
	leaves, err := store.ListLeaves(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Errorf("expected 2 leaves after rotate replay, got %d", len(leaves))
	}
}

func TestRotate_PostRefusesNonActive(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// Pre-revoke directly so the POST can't even acquire a fresh form_token
	// the legitimate way; we manually obtain one via the GET-when-active route
	// before revoking.
	w := c.get("/certs/" + leafID + "/rotate")
	formTok := extractFormToken(t, w.Body.String())

	// Now revoke.
	c.get("/certs/" + leafID)
	c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})

	// Submit the previously-acquired token — POST handler refuses because
	// status is no longer active.
	w = c.postForm("/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
		"form_token":      {formTok},
	})
	if w.Code != http.StatusConflict {
		t.Errorf("got %d, want 409", w.Code)
	}
}

func TestRotate_NotFound(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	c.get("/")

	w := c.get("/certs/no-such-id/rotate")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestRotate_RedirectsWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	srv.keystore.Lock()

	w := c.get("/certs/" + leafID + "/rotate")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestDetailHidesRotateOnRevoked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	c.get("/certs/" + leafID)
	c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})

	w := c.get("/certs/" + leafID)
	if strings.Contains(w.Body.String(), "Rotate this certificate") {
		t.Error("rotate link still shown on revoked cert")
	}
	_ = db
}

func TestDetailShowsRevokeOnSuperseded(t *testing.T) {
	// After rotation the old cert is "superseded". The revoke form must
	// still be available so an operator can put the old serial on the
	// CRL — useful when the rotation was triggered by key compromise.
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	// Rotate the leaf — the original now becomes superseded.
	mustIssue(t, c, "/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
	})

	w := c.get("/certs/" + leafID)
	body := w.Body.String()
	if !strings.Contains(body, "Revoke this certificate") {
		t.Error("revoke form should still be available on superseded cert")
	}
	if !strings.Contains(body, `action="/certs/`+leafID+`/revoke"`) {
		t.Error("revoke form action missing")
	}
	// Rotate is hidden — the cert is no longer active.
	if strings.Contains(body, "Rotate this certificate") {
		t.Error("rotate link should be hidden on superseded cert")
	}
	_ = db
}
