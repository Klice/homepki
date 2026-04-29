package web

import (
	"crypto/x509"
	"math/big"
	"net/http"
	"net/url"
	"testing"

	"github.com/Klice/homepki/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "GetLatestCRL initial")
	assert.Equal(t, int64(1), cached.CRLNumber, "initial CRL number")

	// Look up the leaf's serial so we can assert it appears on the new CRL.
	leafCert, err := store.GetCert(db, leafID)
	require.NoError(t, err)
	wantSerial, _ := new(big.Int).SetString(leafCert.SerialNumber, 16)

	// Visit the detail page first so the CSRF token is in the client jar.
	c.get("/certs/" + leafID)

	// Revoke with reason 1 (keyCompromise).
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/certs/"+leafID, w.Header().Get("Location"))

	// Cert is now revoked.
	got, err := store.GetCert(db, leafID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got.Status)

	// Intermediate's CRL has bumped to number 2 and lists the leaf serial.
	regen, err := store.GetLatestCRL(db, interID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), regen.CRLNumber, "CRL number after revoke")
	parsedCRL, err := x509.ParseRevocationList(regen.DER)
	require.NoError(t, err, "ParseRevocationList")
	require.Len(t, parsedCRL.RevokedCertificateEntries, 1, "entries")
	assert.Equal(t, 0, parsedCRL.RevokedCertificateEntries[0].SerialNumber.Cmp(wantSerial), "revoked serial")
	assert.Equal(t, 1, parsedCRL.RevokedCertificateEntries[0].ReasonCode, "reason code")

	// And the CRL signature verifies under the intermediate.
	interStoreCert, err := store.GetCert(db, interID)
	require.NoError(t, err)
	interParsed, err := x509.ParseCertificate(interStoreCert.DERCert)
	require.NoError(t, err)
	assert.NoError(t, parsedCRL.CheckSignatureFrom(interParsed), "CRL signature does not verify under intermediate")
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
	require.Equal(t, http.StatusSeeOther, w.Code, "first revoke")
	crlAfter1, _ := store.GetLatestCRL(db, interID)

	// Second revoke on same cert: should still 303 (no error), CRL number
	// should NOT bump (we no-op when the cert is already revoked).
	w = c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	assert.Equal(t, http.StatusSeeOther, w.Code, "replay")
	crlAfter2, _ := store.GetLatestCRL(db, interID)
	assert.Equal(t, crlAfter1.CRLNumber, crlAfter2.CRLNumber, "CRL bumped on replay")
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
	assert.Equal(t, http.StatusBadRequest, w.Code)
	// And empty reason fails too.
	w = c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {""}})
	assert.Equal(t, http.StatusBadRequest, w.Code, "empty reason")
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
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevoke_NotFound(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	c.get("/") // prime CSRF

	w := c.postForm("/certs/no-such-id/revoke", url.Values{"reason": {"1"}})
	assert.Equal(t, http.StatusNotFound, w.Code)
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
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
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
	assert.NotContains(t, w.Body.String(), "Revoke this certificate", "revoke form still shown on already-revoked cert")
	assert.Contains(t, w.Body.String(), "revoked", "status not displayed as revoked")
	_ = db
}
