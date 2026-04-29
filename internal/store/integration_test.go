package store_test

// integration_test.go lives in the package_test (not internal store_test)
// so it can import both pki and crypto without creating import cycles.
// It exercises the seam from "issue a cert" through "encrypt + persist"
// through "retrieve + decrypt" and verifies the chain end to end.

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

func TestIntegration_IssueEncryptStoreRetrieveDecryptVerify(t *testing.T) {
	db := openDB(t)

	// One KEK shared across the test, mimicking the unlocked keystore.
	kek := make([]byte, crypto.KeyLen)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}

	// 1. Issue a self-signed root.
	rootIssued, err := pki.IssueRoot(pki.RootRequest{
		Subject:  pki.Subject{CN: "Test Root", O: "Acme"},
		Key:      pki.KeySpec{Algo: pki.ECDSA, Params: "P-256"},
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueRoot: %v", err)
	}
	rootID := "11111111-1111-1111-1111-111111111111"
	if err := persist(t, db, kek, rootIssued, "root_ca", rootID, nil); err != nil {
		t.Fatal(err)
	}

	// 2. Issue an intermediate signed by the root.
	intermediateIssued, err := pki.IssueIntermediate(pki.IntermediateRequest{
		Subject:    pki.Subject{CN: "Test Intermediate"},
		Key:        pki.KeySpec{Algo: pki.ECDSA, Params: "P-256"},
		Parent:     &pki.Signer{Cert: rootIssued.Cert, Key: rootIssued.Key},
		ParentID:   rootID,
		CRLBaseURL: "https://certs.lan",
		Validity:   5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	intID := "22222222-2222-2222-2222-222222222222"
	if err := persist(t, db, kek, intermediateIssued, "intermediate_ca", intID, &rootID); err != nil {
		t.Fatal(err)
	}

	// 3. Issue a leaf signed by the intermediate.
	leafIssued, err := pki.IssueLeaf(pki.LeafRequest{
		Subject:    pki.Subject{CN: "leaf.test"},
		Key:        pki.KeySpec{Algo: pki.ECDSA, Params: "P-256"},
		Parent:     &pki.Signer{Cert: intermediateIssued.Cert, Key: intermediateIssued.Key},
		ParentID:   intID,
		CRLBaseURL: "https://certs.lan",
		SANDNS:     []string{"leaf.test"},
		SANIPs:     []net.IP{net.ParseIP("10.0.0.1")},
		Validity:   90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leafID := "33333333-3333-3333-3333-333333333333"
	if err := persist(t, db, kek, leafIssued, "leaf", leafID, &intID); err != nil {
		t.Fatal(err)
	}

	// 4. Reload the leaf cert and key from the DB.
	got, err := store.GetCert(db, leafID)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	gotKey, err := store.GetCertKey(db, leafID)
	if err != nil {
		t.Fatalf("GetCertKey: %v", err)
	}

	// Cert DER should round-trip exactly.
	if !bytes.Equal(got.DERCert, leafIssued.DER) {
		t.Errorf("DER mismatch on leaf round-trip")
	}

	// 5. Decrypt the leaf's private key and verify it matches the public
	// key in the cert (proves the encrypted material is the right key).
	pkcs8, err := crypto.OpenPrivateKey(kek, leafID, &crypto.SealedPrivateKey{
		WrappedDEK:  gotKey.WrappedDEK,
		DEKNonce:    gotKey.DEKNonce,
		CipherNonce: gotKey.CipherNonce,
		Ciphertext:  gotKey.Ciphertext,
	})
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	defer crypto.Zero(pkcs8)
	priv, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	signer, ok := priv.(stdcrypto.Signer)
	if !ok {
		t.Fatalf("decrypted key %T does not implement crypto.Signer", priv)
	}
	if !reflect.DeepEqual(signer.Public(), leafIssued.Cert.PublicKey) {
		t.Errorf("decrypted private key does not match cert public key")
	}

	// 6. Build a trust pool from the persisted root + intermediate, then
	// verify the persisted leaf chains correctly.
	rootGot, err := store.GetCert(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	intGot, err := store.GetCert(db, intID)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootGot.DERCert)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intGot.DERCert)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(got.DERCert)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		DNSName:       "leaf.test",
	}); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

// persist marshals issued.Key as PKCS#8, seals it under kek with the
// per-cert AAD, and writes both rows to the DB. Mirrors what an issuance
// HTTP handler will do in Phase 3c.
func persist(t *testing.T, db *sql.DB, kek []byte, issued *pki.Issued, ctype, id string, parentID *string) error {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(issued.Key)
	if err != nil {
		return err
	}
	defer crypto.Zero(pkcs8)
	sealed, err := crypto.SealPrivateKey(kek, id, pkcs8)
	if err != nil {
		return err
	}

	fp := sha256.Sum256(issued.DER)
	cert := &store.Cert{
		ID:                id,
		Type:              ctype,
		ParentID:          parentID,
		SerialNumber:      issued.Cert.SerialNumber.Text(16),
		SubjectCN:         issued.Cert.Subject.CommonName,
		IsCA:              issued.Cert.IsCA,
		KeyAlgo:           keyAlgoFromCert(issued.Cert),
		KeyAlgoParams:     "",
		NotBefore:         issued.Cert.NotBefore,
		NotAfter:          issued.Cert.NotAfter,
		DERCert:           issued.DER,
		FingerprintSHA256: hex.EncodeToString(fp[:]),
		Status:            "active",
	}
	for _, dns := range issued.Cert.DNSNames {
		cert.SANDNS = append(cert.SANDNS, dns)
	}
	for _, ip := range issued.Cert.IPAddresses {
		cert.SANIPs = append(cert.SANIPs, ip.String())
	}
	key := &store.CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}
	return store.InsertCert(db, cert, key)
}

func keyAlgoFromCert(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "rsa"
	case x509.ECDSA:
		return "ecdsa"
	case x509.Ed25519:
		return "ed25519"
	default:
		return ""
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}
