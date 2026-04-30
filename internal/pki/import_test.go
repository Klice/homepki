package pki

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== ParseSingleCertPEM =====

func TestParseSingleCertPEM_RoundTrips(t *testing.T) {
	root := mustRoot(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.DER})

	got, err := ParseSingleCertPEM(pemBytes)
	require.NoError(t, err)
	assert.Equal(t, root.Cert.SubjectKeyId, got.SubjectKeyId)
	assert.True(t, got.IsCA)
}

func TestParseSingleCertPEM_RejectsEmpty(t *testing.T) {
	_, err := ParseSingleCertPEM(nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "empty")
}

func TestParseSingleCertPEM_RejectsWrongBlockType(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x00}})
	_, err := ParseSingleCertPEM(bad)
	require.Error(t, err)
	assert.ErrorContains(t, err, "CERTIFICATE")
}

func TestParseSingleCertPEM_RejectsMultipleBlocks(t *testing.T) {
	root := mustRoot(t)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.DER})
	doubled := append(cert, cert...)

	_, err := ParseSingleCertPEM(doubled)
	require.Error(t, err)
	assert.ErrorContains(t, err, "more than one")
}

func TestParseSingleCertPEM_RejectsBadDER(t *testing.T) {
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a real cert")})
	_, err := ParseSingleCertPEM(junk)
	require.Error(t, err)
	assert.ErrorContains(t, err, "parse certificate DER")
}

// ===== ParsePrivateKeyPEM =====

func TestParsePrivateKeyPEM_PKCS8RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := ParsePrivateKeyPEM(pemBytes)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, signer)
}

func TestParsePrivateKeyPEM_PKCS8ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := ParsePrivateKeyPEM(pemBytes)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, signer)
}

func TestParsePrivateKeyPEM_PKCS8Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := ParsePrivateKeyPEM(pemBytes)
	require.NoError(t, err)
	assert.IsType(t, ed25519.PrivateKey{}, signer)
}

func TestParsePrivateKeyPEM_RejectsPKCS1RSAWithHint(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	_, err = ParsePrivateKeyPEM(pemBytes)
	require.Error(t, err)
	assert.ErrorContains(t, err, "RSA PRIVATE KEY")
	assert.ErrorContains(t, err, "pkcs8 -topk8")
}

func TestParsePrivateKeyPEM_RejectsECPrivateKeyWithHint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	_, err = ParsePrivateKeyPEM(pemBytes)
	require.Error(t, err)
	assert.ErrorContains(t, err, "EC PRIVATE KEY")
	assert.ErrorContains(t, err, "pkcs8 -topk8")
}

func TestParsePrivateKeyPEM_RejectsEmpty(t *testing.T) {
	_, err := ParsePrivateKeyPEM(nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "empty")
}

func TestParsePrivateKeyPEM_RejectsBadPEM(t *testing.T) {
	_, err := ParsePrivateKeyPEM([]byte("not pem"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "no PEM block")
}

// ===== MatchKeyToCert =====

func TestMatchKeyToCert_RSAMatch(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv)
	assert.NoError(t, MatchKeyToCert(cert, priv))
}

func TestMatchKeyToCert_RSAMismatch(t *testing.T) {
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv1)
	err = MatchKeyToCert(cert, priv2)
	require.Error(t, err)
	assert.ErrorContains(t, err, "RSA mismatch")
}

func TestMatchKeyToCert_ECDSAMatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv)
	assert.NoError(t, MatchKeyToCert(cert, priv))
}

func TestMatchKeyToCert_Ed25519Match(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv)
	assert.NoError(t, MatchKeyToCert(cert, priv))
}

func TestMatchKeyToCert_AlgoMismatch(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCert(t, rsaPriv)

	err = MatchKeyToCert(cert, edPriv)
	require.Error(t, err)
	assert.ErrorContains(t, err, "RSA mismatch")
}

func TestMatchKeyToCert_NilGuards(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv)

	assert.Error(t, MatchKeyToCert(nil, priv))
	assert.Error(t, MatchKeyToCert(cert, nil))
}

// ===== ValidateRootCert =====

func TestValidateRootCert_AcceptsSelfSignedCA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCert(t, priv)
	assert.NoError(t, ValidateRootCert(cert))
}

func TestValidateRootCert_RejectsLeaf(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := selfSignedTemplate("leaf")
	tmpl.IsCA = false
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	err = ValidateRootCert(cert)
	require.Error(t, err)
	assert.ErrorContains(t, err, "not a CA")
}

func TestValidateRootCert_RejectsNonSelfSigned(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCert := selfSignedCert(t, rootPriv)

	intPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := selfSignedTemplate("intermediate")
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, intPriv.Public(), rootPriv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	err = ValidateRootCert(cert)
	require.Error(t, err)
	assert.ErrorContains(t, err, "not self-signed")
}

func TestValidateRootCert_RejectsMissingBasicConstraints(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := selfSignedTemplate("no-bc")
	// Override the helper: drop both flags so x509.CreateCertificate
	// emits no BasicConstraints extension at all.
	tmpl.IsCA = false
	tmpl.BasicConstraintsValid = false
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	err = ValidateRootCert(cert)
	require.Error(t, err)
	assert.ErrorContains(t, err, "BasicConstraints")
}

func TestValidateRootCert_ExpiredReturnsTypedSentinel(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := selfSignedTemplate("expired")
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.NotBefore = time.Now().Add(-2 * time.Hour)
	tmpl.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	err = ValidateRootCert(cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertExpired), "expected ErrCertExpired, got %v", err)
}

func TestValidateRootCert_NilGuard(t *testing.T) {
	assert.Error(t, ValidateRootCert(nil))
}

// ===== test helpers =====

// selfSignedTemplate builds a minimal self-signed CA template the helpers
// can override field-by-field. Same DN for Subject and Issuer so it
// passes the self-signed check by default.
func selfSignedTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// selfSignedCert generates a self-signed CA from the provided key for use
// in MatchKeyToCert and ValidateRootCert tests. crypto.Signer is the
// interface every {*rsa,*ecdsa,ed25519}.PrivateKey satisfies.
func selfSignedCert(t *testing.T, key stdcrypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := selfSignedTemplate("test-self-signed")
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
