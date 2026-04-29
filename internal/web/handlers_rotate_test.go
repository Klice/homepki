package web

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/Klice/homepki/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotate_GetRendersPrefilledForm(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	w := c.get("/certs/" + leafID + "/rotate")
	require.Equal(t, http.StatusOK, w.Code, "status body=%q", w.Body.String())
	body := w.Body.String()
	for _, want := range []string{
		`action="/certs/` + leafID + `/rotate"`,
		`name="subject_cn" required autofocus value="revoke.leaf.test"`,
		`Rotate revoke.leaf.test`,
		`name="form_token"`,
	} {
		assert.Contains(t, body, want)
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
	assert.Equal(t, http.StatusConflict, w.Code, "rotate revoked")
}

func TestRotate_LeafFullFlow(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, interID, leafID := issueChain(t, c)

	// Capture old cert serial so we can confirm the successor differs.
	oldCert, err := store.GetCert(db, leafID)
	require.NoError(t, err)
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

	assert.NotEqual(t, leafID, newID, "new id should differ from old")

	// Old cert is now superseded with replaced_by_id pointing at the new one.
	old, err := store.GetCert(db, leafID)
	require.NoError(t, err)
	assert.Equal(t, "superseded", old.Status, "old status")
	if assert.NotNil(t, old.ReplacedByID, "old.ReplacedByID") {
		assert.Equal(t, newID, *old.ReplacedByID, "old.ReplacedByID")
	}

	// New cert is active with replaces_id back-link, fresh serial, same SANs/CN.
	got, err := store.GetCert(db, newID)
	require.NoError(t, err)
	assert.Equal(t, "active", got.Status, "new status")
	if assert.NotNil(t, got.ReplacesID, "new.ReplacesID") {
		assert.Equal(t, leafID, *got.ReplacesID, "new.ReplacesID")
	}
	assert.NotEqual(t, oldSerial, got.SerialNumber, "new serial should differ from old")
	assert.Equal(t, "revoke.leaf.test", got.SubjectCN, "new CN")
	if assert.NotNil(t, got.ParentID, "new parent") {
		assert.Equal(t, interID, *got.ParentID, "new parent")
	}

	// The new leaf chains under the same intermediate via x509.Verify.
	root, _ := store.GetCert(db, "") // sentinel below; load root via chain walk
	chain, err := store.GetChain(db, newID)
	require.NoError(t, err)
	require.Len(t, chain, 3, "chain length")
	root = chain[2]
	rootCert, _ := x509.ParseCertificate(root.DERCert)
	intermediateCert, _ := x509.ParseCertificate(chain[1].DERCert)
	leafCert, _ := x509.ParseCertificate(chain[0].DERCert)
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		DNSName:       "revoke.leaf.test",
	})
	assert.NoError(t, err, "verify rotated leaf")
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

	require.NotEqual(t, rootID, newID, "rotated root has same id as original")

	// New root is self-signed (no parent), active, with replaces_id link.
	newRoot, err := store.GetCert(db, newID)
	require.NoError(t, err)
	assert.Nil(t, newRoot.ParentID, "new root should have no parent")
	if assert.NotNil(t, newRoot.ReplacesID, "new root ReplacesID") {
		assert.Equal(t, rootID, *newRoot.ReplacesID, "new root ReplacesID")
	}

	// New root has its OWN initial CRL with number 1 (not part of old's series).
	crl, err := store.GetLatestCRL(db, newID)
	require.NoError(t, err, "new root CRL")
	assert.Equal(t, int64(1), crl.CRLNumber, "new root CRL number")
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
	require.Equal(t, http.StatusSeeOther, w.Code, "first rotate body=%q", w.Body.String())
	firstLoc := w.Header().Get("Location")

	// Replay: same token POSTed again. Per API.md §6.5 it should 303 to the
	// same successor, NOT create a second one.
	w = c.postForm("/certs/"+leafID+"/rotate", form)
	require.Equal(t, http.StatusSeeOther, w.Code, "replay body=%q", w.Body.String())
	assert.Equal(t, firstLoc, w.Header().Get("Location"), "replay location")

	// Sanity: only one successor exists. Two leaves total (the superseded
	// original + the active successor). Three or more would mean the
	// replay double-issued.
	leaves, err := store.ListLeaves(db)
	require.NoError(t, err)
	assert.Len(t, leaves, 2, "expected 2 leaves after rotate replay")
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
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestRotate_NotFound(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	c.get("/")

	w := c.get("/certs/no-such-id/rotate")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotate_RedirectsWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID := issueChain(t, c)

	srv.keystore.Lock()

	w := c.get("/certs/" + leafID + "/rotate")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
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
	assert.NotContains(t, w.Body.String(), "Rotate this certificate", "rotate link still shown on revoked cert")
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
	assert.Contains(t, body, "Revoke this certificate", "revoke form should still be available on superseded cert")
	assert.Contains(t, body, `action="/certs/`+leafID+`/revoke"`, "revoke form action missing")
	// Rotate is hidden — the cert is no longer active.
	assert.NotContains(t, body, "Rotate this certificate", "rotate link should be hidden on superseded cert")
	_ = db
}
