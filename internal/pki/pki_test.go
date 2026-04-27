package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"
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
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			switch k.(type) {
			case *rsa.PrivateKey:
				if tc.want != "*rsa.PrivateKey" {
					t.Errorf("got *rsa.PrivateKey, want %s", tc.want)
				}
			case *ecdsa.PrivateKey:
				if tc.want != "*ecdsa.PrivateKey" {
					t.Errorf("got *ecdsa.PrivateKey, want %s", tc.want)
				}
			case ed25519.PrivateKey:
				if tc.want != "ed25519.PrivateKey" {
					t.Errorf("got ed25519.PrivateKey, want %s", tc.want)
				}
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
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("got %v, want error containing %q", err, tc.wantSub)
			}
		})
	}
}

func TestNewSerial_NonNegativeAndDistinct(t *testing.T) {
	a, err := NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	if a.Sign() < 0 || b.Sign() < 0 {
		t.Error("serials must be non-negative")
	}
	if a.Cmp(b) == 0 {
		t.Error("two serials should be different")
	}
	// 159-bit upper bound: BitLen is at most 159.
	if a.BitLen() > 159 || b.BitLen() > 159 {
		t.Errorf("serial too long: %d, %d bits", a.BitLen(), b.BitLen())
	}
}

func TestIssueRoot_Basic(t *testing.T) {
	root, err := IssueRoot(RootRequest{
		Subject:  Subject{CN: "Test Root"},
		Key:      fastSpec,
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueRoot: %v", err)
	}
	if !root.Cert.IsCA || !root.Cert.BasicConstraintsValid {
		t.Error("root must have IsCA + BasicConstraintsValid")
	}
	if root.Cert.Subject.CommonName != "Test Root" {
		t.Errorf("CN: got %q", root.Cert.Subject.CommonName)
	}
	if len(root.Cert.CRLDistributionPoints) != 0 {
		t.Errorf("root must not have CRL DP, got %v", root.Cert.CRLDistributionPoints)
	}
	if root.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root must have KeyUsageCertSign")
	}
	if root.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("root must have KeyUsageCRLSign")
	}

	// Self-signed: parent fields equal subject.
	if root.Cert.Issuer.String() != root.Cert.Subject.String() {
		t.Errorf("self-signed: issuer %q != subject %q", root.Cert.Issuer, root.Cert.Subject)
	}
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
			if _, err := IssueRoot(tc.req); err == nil {
				t.Error("expected error, got nil")
			}
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
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	if !inter.Cert.IsCA {
		t.Error("intermediate must be CA")
	}
	wantCRL := "https://certs.lan/crl/" + parentID + ".crl"
	if got := inter.Cert.CRLDistributionPoints; len(got) != 1 || got[0] != wantCRL {
		t.Errorf("CRL DP: got %v, want [%s]", got, wantCRL)
	}
	if inter.Cert.Issuer.CommonName != root.Cert.Subject.CommonName {
		t.Errorf("issuer: got %q, want %q", inter.Cert.Issuer.CommonName, root.Cert.Subject.CommonName)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if !inter.Cert.MaxPathLenZero || inter.Cert.MaxPathLen != 0 {
		t.Errorf("path len: got MaxPathLen=%d MaxPathLenZero=%v", inter.Cert.MaxPathLen, inter.Cert.MaxPathLenZero)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}

	// Sanity checks on leaf shape.
	if leaf.Cert.IsCA {
		t.Error("leaf must not be CA")
	}
	if !sliceContains(leaf.Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Errorf("leaf ext key usage: got %v, want ServerAuth", leaf.Cert.ExtKeyUsage)
	}
	if got := leaf.Cert.DNSNames; len(got) != 2 || got[0] != "leaf.test" {
		t.Errorf("DNS SANs: got %v", got)
	}
	if len(leaf.Cert.IPAddresses) != 1 || !leaf.Cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP SANs: got %v", leaf.Cert.IPAddresses)
	}

	// Build the trust pool and verify the leaf via x509.
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter.Cert)
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "leaf.test",
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// And reject a name that's not in the SANs.
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "not-in-sans.test",
	}); err == nil {
		t.Error("Verify should reject unknown DNS name")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	_, err = IssueLeaf(LeafRequest{
		Subject:  Subject{CN: "leaf"},
		Key:      fastSpec,
		Parent:   &Signer{Cert: inter.Cert, Key: inter.Key},
		Validity: time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "SAN") {
		t.Errorf("got %v, want SAN error", err)
	}
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
		if got != tc.want {
			t.Errorf("crlURL(%q, %q) = %q, want %q", tc.base, tc.id, got, tc.want)
		}
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
	if err != nil {
		t.Fatalf("IssueRoot: %v", err)
	}
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
