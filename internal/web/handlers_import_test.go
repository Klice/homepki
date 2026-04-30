package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/store"
)

// makeImportableRoot mints a self-signed root cert + matching key in
// PKCS#8 PEM, ready to feed into the import form. Defaults to ECDSA
// P-256 because it's the cheapest to generate; tests that care about
// algorithm parity build their own.
func makeImportableRoot(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	return certPEM, keyPEM
}

// importRootFixture sets up an unlocked server + primed client and
// returns them along with a freshly-minted root + matching key PEM.
func importRootFixture(t *testing.T, cn string) (*Server, *clientLite, string, string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	certPEM, keyPEM := makeImportableRoot(t, cn)
	return srv, c, certPEM, keyPEM
}

// ============== happy path ==============

func TestImportRoot_GETFormRenders(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/import/root")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	for _, want := range []string{
		`name="cert_pem"`,
		`name="key_pem"`,
		`name="form_token"`,
		`name="csrf_token"`,
		"Import root",
	} {
		assert.Contains(t, body, want)
	}
}

func TestImportRoot_GETRedirectsWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/certs/import/root")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

func TestImportRoot_POSTHappyPath(t *testing.T) {
	srv, c, certPEM, keyPEM := importRootFixture(t, "Imported Test Root")

	w := c.get("/certs/import/root")
	require.Equal(t, http.StatusOK, w.Code)
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusSeeOther, resp.Code, "body=%q", resp.Body.String())
	loc := resp.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "/certs/"), "Location: %q", loc)

	id := strings.TrimPrefix(loc, "/certs/")

	// Row exists with Source=imported, Type=root_ca.
	cert, err := store.GetCert(srv.db, id)
	require.NoError(t, err)
	assert.Equal(t, "imported", cert.Source)
	assert.Equal(t, "root_ca", cert.Type)
	assert.True(t, cert.IsCA)
	assert.Nil(t, cert.ParentID)

	// CertView's source surfaces in ListCAs (used by the index).
	cas, err := store.ListCAs(srv.db)
	require.NoError(t, err)
	var found bool
	for _, c := range cas {
		if c.ID == id {
			found = true
			assert.Equal(t, "imported", c.Source)
		}
	}
	assert.True(t, found, "imported root should appear under ListCAs")

	// Initial CRL is present + parses.
	crl, err := store.GetLatestCRL(srv.db, id)
	require.NoError(t, err)
	assert.Equal(t, int64(1), crl.CRLNumber)
	parsed, err := x509.ParseRevocationList(crl.DER)
	require.NoError(t, err)
	assert.Empty(t, parsed.RevokedCertificateEntries)

	// key.pem download round-trips.
	w = c.get("/certs/" + id + "/key.pem")
	require.Equal(t, http.StatusOK, w.Code)
	block, _ := pem.Decode(w.Body.Bytes())
	require.NotNil(t, block)
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)
}

func TestImportRoot_DetailPageShowsImportedBadge(t *testing.T) {
	srv, c, certPEM, keyPEM := importRootFixture(t, "Detail Badge Root")

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusSeeOther, resp.Code)
	id := strings.TrimPrefix(resp.Header().Get("Location"), "/certs/")
	_ = srv

	w = c.get("/certs/" + id)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "imported")
	assert.Contains(t, body, "This certificate was imported")
}

// ============== idempotency ==============

func TestImportRoot_DuplicateUploadResolvesToSameID(t *testing.T) {
	srv, c, certPEM, keyPEM := importRootFixture(t, "Idempotent Root")

	post := func() string {
		w := c.get("/certs/import/root")
		require.Equal(t, http.StatusOK, w.Code)
		form := url.Values{
			"cert_pem":   {certPEM},
			"key_pem":    {keyPEM},
			"form_token": {extractFormToken(t, w.Body.String())},
		}
		resp := c.postForm("/certs/import/root", form)
		require.Equal(t, http.StatusSeeOther, resp.Code, "body=%q", resp.Body.String())
		return strings.TrimPrefix(resp.Header().Get("Location"), "/certs/")
	}
	id1 := post()
	id2 := post()
	assert.Equal(t, id1, id2, "re-uploading the same cert must resolve to the same id")

	cas, err := store.ListCAs(srv.db)
	require.NoError(t, err)
	matches := 0
	for _, c := range cas {
		if c.ID == id1 {
			matches++
		}
	}
	assert.Equal(t, 1, matches, "exactly one CA row for the imported cert")
}

func TestImportRoot_FormTokenReplayReturnsSameRedirect(t *testing.T) {
	_, c, certPEM, keyPEM := importRootFixture(t, "Replay Root")

	w := c.get("/certs/import/root")
	require.Equal(t, http.StatusOK, w.Code)
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	first := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusSeeOther, first.Code)
	firstLoc := first.Header().Get("Location")

	// Replay the exact same form (same token). Must 303 to the same id
	// without re-doing the work.
	replay := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusSeeOther, replay.Code)
	assert.Equal(t, firstLoc, replay.Header().Get("Location"))
}

// ============== validation rejections ==============

func TestImportRoot_RejectsLeafCert(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// Mint a self-signed *non-CA* cert.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf"},
		Issuer:                pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "not a CA")
}

func TestImportRoot_RejectsNonSelfSignedCA(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// Mint a root + a real intermediate signed by it. The intermediate
	// is a CA but Issuer != Subject so ValidateRootCert must reject.
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		Issuer:                pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPriv.Public(), rootPriv)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, intPriv.Public(), rootPriv)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(intPriv)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "not self-signed")
}

func TestImportRoot_RejectsKeyMismatch(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// Cert minted with key A, paired with key B in the form.
	certPEM, _ := makeImportableRoot(t, "Mismatch Root A")
	_, otherKeyPEM := makeImportableRoot(t, "Mismatch Root B")

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {otherKeyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "key does not match")
}

func TestImportRoot_RejectsGarbageCertPEM(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {"this is not pem"},
		"key_pem":    {"also not pem"},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "Certificate:")
}

func TestImportRoot_RejectsLegacyPKCS1Key(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rsa-root"},
		Issuer:                pkix.Name{CommonName: "rsa-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	// PKCS#1 (legacy "RSA PRIVATE KEY") block — handler should reject
	// with the openssl pkcs8 -topk8 hint.
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	body := resp.Body.String()
	assert.Contains(t, body, "RSA PRIVATE KEY")
	assert.Contains(t, body, "pkcs8 -topk8")
}

// ============== state preservation ==============

func TestImportRoot_RejectionPreservesPastedPEM(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {"clearly invalid PEM string"},
		"key_pem":    {"another invalid string"},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	body := resp.Body.String()
	// Both pasted values must round-trip back into the textareas so
	// the operator doesn't lose their upload to a typo.
	assert.Contains(t, body, "clearly invalid PEM string")
	assert.Contains(t, body, "another invalid string")
}

// ============== cross-import workflows ==============

func TestImportRoot_AllowsIntermediateUnderImportedRoot(t *testing.T) {
	// Once a root is imported, the existing /certs/new/intermediate
	// flow should treat it as a valid parent.
	srv, c, certPEM, keyPEM := importRootFixture(t, "Parent Root")

	// Import the root.
	w := c.get("/certs/import/root")
	form := url.Values{
		"cert_pem":   {certPEM},
		"key_pem":    {keyPEM},
		"form_token": {extractFormToken(t, w.Body.String())},
	}
	resp := c.postForm("/certs/import/root", form)
	require.Equal(t, http.StatusSeeOther, resp.Code)
	rootID := strings.TrimPrefix(resp.Header().Get("Location"), "/certs/")

	// Issue an intermediate under it.
	interID := mustIssue(t, c, "/certs/new/intermediate", url.Values{
		"parent_id":       {rootID},
		"subject_cn":      {"Child of Imported"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"180"},
	})
	require.NotEqual(t, rootID, interID)

	inter, err := store.GetCert(srv.db, interID)
	require.NoError(t, err)
	assert.Equal(t, "issued", inter.Source) // child is homepki-issued
	require.NotNil(t, inter.ParentID)
	assert.Equal(t, rootID, *inter.ParentID)

	// And the new intermediate's CRL DP references homepki's CRL endpoint
	// for the *imported root's id* — i.e., crl-distribution mismatch
	// fades for everything new.
	parsed, err := x509.ParseCertificate(inter.DERCert)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.CRLDistributionPoints,
		"homepki-issued intermediate must have a CRL DP")
	dp := parsed.CRLDistributionPoints[0]
	assert.Contains(t, dp, "/crl/"+rootID)
}

