package web

import (
	stdcrypto "crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/store"
)

// seedCertsForBrowse inserts a self-signed root + intermediate + leaf so the
// index and detail handlers have something to render. Returns their IDs.
func seedCertsForBrowse(t *testing.T, db *sql.DB) (rootID, interID, leafID string) {
	t.Helper()
	rootID, interID, leafID = "root-1", "inter-1", "leaf-1"
	now := time.Now()

	root := minimalCert(t, rootID, "root_ca", nil, "Test Root", now, 365*24*time.Hour)
	require.NoError(t, store.InsertCert(db, root.cert, root.key), "InsertCert root")
	rid := rootID
	inter := minimalCert(t, interID, "intermediate_ca", &rid, "Test Intermediate", now, 180*24*time.Hour)
	require.NoError(t, store.InsertCert(db, inter.cert, inter.key), "InsertCert intermediate")
	iid := interID
	leaf := minimalCert(t, leafID, "leaf", &iid, "leaf.test", now, 90*24*time.Hour)
	leaf.cert.SANDNS = []string{"leaf.test", "alt.leaf.test"}
	leaf.cert.SANIPs = []string{"10.0.0.1"}
	require.NoError(t, store.InsertCert(db, leaf.cert, leaf.key), "InsertCert leaf")
	return rootID, interID, leafID
}

type insertable struct {
	cert *store.Cert
	key  *store.CertKey
}

// minimalCert builds a cert+key pair with valid (but trivial) DER bytes.
// We bypass real PKI issuance — these handlers don't care whether DERCert
// is a real signed cert, only that the row exists.
func minimalCert(t *testing.T, id, ctype string, parentID *string, cn string, now time.Time, validity time.Duration) insertable {
	t.Helper()
	// Construct a tiny but parseable self-signed DER blob so anything that
	// later tries to x509.ParseCertificate(DERCert) doesn't blow up. For
	// browse-only tests we only need *something* in the column.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.Add(validity),
	}
	priv := mustEd25519Key(t)
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err, "CreateCertificate")
	hash := sha256Hex(der)
	c := &store.Cert{
		ID:                id,
		Type:              ctype,
		ParentID:          parentID,
		SerialNumber:      "01",
		SubjectCN:         cn,
		IsCA:              ctype != "leaf",
		KeyAlgo:           "ed25519",
		KeyAlgoParams:     "",
		NotBefore:         now,
		NotAfter:          now.Add(validity),
		DERCert:           der,
		FingerprintSHA256: hash,
		Status:            "active",
	}
	k := &store.CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  []byte{0x00},
		DEKNonce:    make([]byte, 12),
		CipherNonce: make([]byte, 12),
		Ciphertext:  []byte{0x00},
	}
	return insertable{cert: c, key: k}
}

func mustEd25519Key(t *testing.T) stdcrypto.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "ed25519 keygen")
	return priv
}

// ---- index ----

func TestIndex_RendersCAsAndLeavesFromStore(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	rootID, interID, leafID := seedCertsForBrowse(t, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	for _, want := range []string{
		`href="/certs/` + rootID + `"`,
		`href="/certs/` + interID + `"`,
		`href="/certs/` + leafID + `"`,
		"Test Root",
		"Test Intermediate",
		"leaf.test",
		"leaf.test, alt.leaf.test, 10.0.0.1",
		"Authorities",
		"Leaf certificates",
	} {
		assert.Contains(t, body, want)
	}
}

func TestIndex_EmptyState(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "No authorities yet")
	assert.Contains(t, body, "No leaf certificates yet")
}

// ---- detail ----

func TestCertDetail_RendersChain(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	rootID, interID, leafID := seedCertsForBrowse(t, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/" + leafID)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	for _, want := range []string{
		"leaf.test",
		"alt.leaf.test",
		"10.0.0.1",
		// Chain links to ancestors.
		`href="/certs/` + interID + `"`,
		`href="/certs/` + rootID + `"`,
		// Issuer header rendered as a link to the parent.
		"Test Intermediate",
		// Fingerprint formatted with colons.
		":",
	} {
		assert.Contains(t, body, want)
	}
}

func TestCertDetail_RootShowsSelfSigned(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	rootID, _, _ := seedCertsForBrowse(t, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/" + rootID)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "self-signed")
}

func TestCertDetail_NotFound(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/no-such-id")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCertDetail_RedirectsWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	_, _, leafID := seedCertsForBrowse(t, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/certs/" + leafID)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

// ---- helpers ----

// installSession primes the cookie-jar client with a valid session cookie
// derived from the unlocked keystore, simulating "user has unlocked".
func installSession(t *testing.T, srv *Server, c *clientLite) {
	t.Helper()
	secret, err := srv.keystore.DeriveSessionSecret()
	require.NoError(t, err)
	value, err := SignSession(secret)
	require.NoError(t, err)
	c.cookies[SessionCookieName] = &http.Cookie{Name: SessionCookieName, Value: value}
}

func sha256Hex(b []byte) string {
	// Deliberately not using sha256.Sum256 to keep imports minimal here —
	// the value isn't checked, only its presence and format.
	const hexC = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexC[x>>4]
		out[i*2+1] = hexC[x&0x0f]
	}
	return string(out)
}
