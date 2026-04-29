package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastSpec is the key spec used throughout the tests — ECDSA P-256
// generates ~10x faster than RSA 2048 and ~1000x faster than RSA 4096.
var fastSpec = KeySpec{Algo: ECDSA, Params: "P-256"}

func TestGenerateKey_AllAlgos(t *testing.T) {
	cases := []struct {
		name string
		spec KeySpec
		want string // type name expected
	}{
		{"rsa-2048", KeySpec{RSA, "2048"}, "*rsa.PrivateKey"},
		{"ecdsa-P256", KeySpec{ECDSA, "P-256"}, "*ecdsa.PrivateKey"},
		{"ecdsa-P384", KeySpec{ECDSA, "P-384"}, "*ecdsa.PrivateKey"},
		{"ed25519", KeySpec{Ed25519, ""}, "ed25519.PrivateKey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := GenerateKey(tc.spec)
			require.NoError(t, err, "GenerateKey")
			switch k.(type) {
			case *rsa.PrivateKey:
				assert.Equal(t, "*rsa.PrivateKey", tc.want)
			case *ecdsa.PrivateKey:
				assert.Equal(t, "*ecdsa.PrivateKey", tc.want)
			case ed25519.PrivateKey:
				assert.Equal(t, "ed25519.PrivateKey", tc.want)
			default:
				t.Errorf("unexpected key type %T", k)
			}
		})
	}
}

func TestGenerateKey_RejectsBadParams(t *testing.T) {
	cases := []struct {
		name    string
		spec    KeySpec
		wantSub string
	}{
		{"rsa too small", KeySpec{RSA, "1024"}, "unsupported"},
		{"rsa garbage", KeySpec{RSA, "abc"}, "invalid"},
		{"ecdsa unknown curve", KeySpec{ECDSA, "P-521"}, "unsupported curve"},
		{"unknown algo", KeySpec{KeyAlgo("dh"), ""}, "unsupported key algo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateKey(tc.spec)
			assert.ErrorContains(t, err, tc.wantSub)
		})
	}
}

func TestNewSerial_NonNegativeAndDistinct(t *testing.T) {
	a, err := NewSerial()
	require.NoError(t, err)
	b, err := NewSerial()
	require.NoError(t, err)
	assert.False(t, a.Sign() < 0 || b.Sign() < 0, "serials must be non-negative")
	assert.NotEqual(t, 0, a.Cmp(b), "two serials should be different")
	// 159-bit upper bound: BitLen is at most 159.
	assert.LessOrEqual(t, a.BitLen(), 159, "serial too long")
	assert.LessOrEqual(t, b.BitLen(), 159, "serial too long")
}

func TestIssueRoot_Basic(t *testing.T) {
	root, err := IssueRoot(RootRequest{
		Subject:  Subject{CN: "Test Root"},
		Key:      fastSpec,
		Validity: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err, "IssueRoot")
	assert.True(t, root.Cert.IsCA && root.Cert.BasicConstraintsValid, "root must have IsCA + BasicConstraintsValid")
	assert.Equal(t, "Test Root", root.Cert.Subject.CommonName)
	assert.Empty(t, root.Cert.CRLDistributionPoints, "root must not have CRL DP")
	assert.NotZero(t, root.Cert.KeyUsage&x509.KeyUsageCertSign, "root must have KeyUsageCertSign")
	assert.NotZero(t, root.Cert.KeyUsage&x509.KeyUsageCRLSign, "root must have KeyUsageCRLSign")

	// Self-signed: parent fields equal subject.
	assert.Equal(t, root.Cert.Subject.String(), root.Cert.Issuer.String(), "self-signed: issuer must equal subject")
}

func TestIssueRoot_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		req  RootRequest
	}{
		{"missing CN", RootRequest{Key: fastSpec, Validity: time.Hour}},
		{"zero validity", RootRequest{Subject: Subject{CN: "x"}, Key: fastSpec}},
		{"bad key spec", RootRequest{Subject: Subject{CN: "x"}, Key: KeySpec{RSA, "1024"}, Validity: time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IssueRoot(tc.req)
			assert.Error(t, err)
		})
	}
}

func TestIssueIntermediate_BakesCRLDP(t *testing.T) {
	root := mustRoot(t)
	parentID := "11111111-2222-3333-4444-555555555555"

	inter, err := IssueIntermediate(IntermediateRequest{
		Subject:    Subject{CN: "Test Intermediate"},
		Key:        fastSpec,
		Parent:     &Signer{Cert: root.Cert, Key: root.Key},
		ParentID:   parentID,
		CRLBaseURL: "https://certs.lan",
		Validity:   5 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err, "IssueIntermediate")
	assert.True(t, inter.Cert.IsCA, "intermediate must be CA")
	wantCRL := "https://certs.lan/crl/" + parentID + ".crl"
	assert.Equal(t, []string{wantCRL}, inter.Cert.CRLDistributionPoints)
	assert.Equal(t, root.Cert.Subject.CommonName, inter.Cert.Issuer.CommonName)
}

func TestIssueIntermediate_PathLen(t *testing.T) {
	root := mustRoot(t)
	zero := 0
	inter, err := IssueIntermediate(IntermediateRequest{
		Subject:    Subject{CN: "intermediate-pathlen0"},
		Key:        fastSpec,
		Parent:     &Signer{Cert: root.Cert, Key: root.Key},
		ParentID:   "id",
		CRLBaseURL: "https://x.test",
		PathLen:    &zero,
		Validity:   time.Hour,
	})
	require.NoError(t, err)
	assert.True(t, inter.Cert.MaxPathLenZero, "MaxPathLenZero")
	assert.Equal(t, 0, inter.Cert.MaxPathLen)
}

func TestIssueLeaf_BasicAndChainVerify(t *testing.T) {
	root := mustRoot(t)
	parentID := "11111111-2222-3333-4444-555555555555"
	inter, err := IssueIntermediate(IntermediateRequest{
		Subject:    Subject{CN: "Issuing CA"},
		Key:        fastSpec,
		Parent:     &Signer{Cert: root.Cert, Key: root.Key},
		ParentID:   parentID,
		CRLBaseURL: "https://certs.lan",
		Validity:   2 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)
	leaf, err := IssueLeaf(LeafRequest{
		Subject:    Subject{CN: "leaf.test"},
		Key:        fastSpec,
		Parent:     &Signer{Cert: inter.Cert, Key: inter.Key},
		ParentID:   "intermediate-id",
		CRLBaseURL: "https://certs.lan",
		SANDNS:     []string{"leaf.test", "alt.leaf.test"},
		SANIPs:     []net.IP{net.ParseIP("10.0.0.1")},
		Validity:   90 * 24 * time.Hour,
	})
	require.NoError(t, err)

	// Sanity checks on leaf shape.
	assert.False(t, leaf.Cert.IsCA, "leaf must not be CA")
	assert.True(t, sliceContains(leaf.Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth), "leaf ext key usage: got %v, want ServerAuth", leaf.Cert.ExtKeyUsage)
	assert.Equal(t, []string{"leaf.test", "alt.leaf.test"}, leaf.Cert.DNSNames)
	require.Len(t, leaf.Cert.IPAddresses, 1)
	assert.True(t, leaf.Cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")), "IP SANs: got %v", leaf.Cert.IPAddresses)

	// Build the trust pool and verify the leaf via x509.
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter.Cert)
	_, err = leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "leaf.test",
	})
	require.NoError(t, err, "Verify")

	// And reject a name that's not in the SANs.
	_, err = leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "not-in-sans.test",
	})
	assert.Error(t, err, "Verify should reject unknown DNS name")
}

func TestIssueLeaf_RejectsMissingSAN(t *testing.T) {
	root := mustRoot(t)
	inter, err := IssueIntermediate(IntermediateRequest{
		Subject:    Subject{CN: "I"},
		Key:        fastSpec,
		Parent:     &Signer{Cert: root.Cert, Key: root.Key},
		ParentID:   "id",
		CRLBaseURL: "https://x.test",
		Validity:   time.Hour,
	})
	require.NoError(t, err)
	_, err = IssueLeaf(LeafRequest{
		Subject:  Subject{CN: "leaf"},
		Key:      fastSpec,
		Parent:   &Signer{Cert: inter.Cert, Key: inter.Key},
		Validity: time.Hour,
	})
	assert.ErrorContains(t, err, "SAN")
}

func TestCRLURL(t *testing.T) {
	cases := []struct {
		base, id, want string
	}{
		{"https://certs.lan", "abc", "https://certs.lan/crl/abc.crl"},
		{"https://certs.lan/", "abc", "https://certs.lan/crl/abc.crl"},
		{"https://certs.lan//", "abc", "https://certs.lan/crl/abc.crl"},
	}
	for _, tc := range cases {
		got := crlURL(tc.base, tc.id)
		assert.Equal(t, tc.want, got, "crlURL(%q, %q)", tc.base, tc.id)
	}
}

// ---- helpers ----

func mustRoot(t *testing.T) *Issued {
	t.Helper()
	root, err := IssueRoot(RootRequest{
		Subject:  Subject{CN: "Test Root"},
		Key:      fastSpec,
		Validity: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err, "IssueRoot")
	return root
}

func sliceContains[T comparable](haystack []T, needle T) bool {
	for _, x := range haystack {
		if x == needle {
			return true
		}
	}
	return false
}
