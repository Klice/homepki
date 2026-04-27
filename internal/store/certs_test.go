package store

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

func sampleCert(id string) *Cert {
	return &Cert{
		ID:                id,
		Type:              "leaf",
		ParentID:          ptrStr("parent-id"),
		SerialNumber:      "01",
		SubjectCN:         "leaf.test",
		SubjectO:          "Acme",
		SANDNS:            []string{"leaf.test", "alt.leaf.test"},
		SANIPs:            []string{"10.0.0.1"},
		IsCA:              false,
		KeyAlgo:           "ecdsa",
		KeyAlgoParams:     "P-256",
		KeyUsage:          []string{"DigitalSignature"},
		ExtKeyUsage:       []string{"ServerAuth"},
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DERCert:           []byte{0x30, 0x82, 0x01},
		FingerprintSHA256: "deadbeef",
		Status:            "active",
	}
}

func sampleKey(id string) *CertKey {
	return &CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  []byte{1, 2, 3},
		DEKNonce:    bytes.Repeat([]byte{4}, 12),
		CipherNonce: bytes.Repeat([]byte{5}, 12),
		Ciphertext:  []byte{6, 7, 8, 9},
	}
}

func TestInsertAndGet_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	// Insert the parent first to satisfy the FK.
	parent := sampleCert("parent-id")
	parent.Type = "intermediate_ca"
	parent.ParentID = nil
	parent.IsCA = true
	parent.SubjectCN = "parent"
	if err := InsertCert(db, parent, sampleKey("parent-id")); err != nil {
		t.Fatalf("Insert parent: %v", err)
	}

	leafID := "leaf-id"
	in := sampleCert(leafID)
	inKey := sampleKey(leafID)
	if err := InsertCert(db, in, inKey); err != nil {
		t.Fatalf("Insert leaf: %v", err)
	}

	got, err := GetCert(db, leafID)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	// Fields the DB sets default values for; copy them over for comparison.
	in.CreatedAt = got.CreatedAt
	if !reflect.DeepEqual(in, got) {
		t.Errorf("cert mismatch:\n got %+v\nwant %+v", got, in)
	}

	gotKey, err := GetCertKey(db, leafID)
	if err != nil {
		t.Fatalf("GetCertKey: %v", err)
	}
	if !reflect.DeepEqual(inKey, gotKey) {
		t.Errorf("key mismatch:\n got %+v\nwant %+v", gotKey, inKey)
	}
}

func TestGet_NotFound(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := GetCert(db, "no-such"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("GetCert: got %v, want ErrCertNotFound", err)
	}
	if _, err := GetCertKey(db, "no-such"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("GetCertKey: got %v, want ErrCertNotFound", err)
	}
}

func TestInsertCert_AtomicOnFK(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	// parent-id doesn't exist → FK violation rolls back, both rows absent.
	c := sampleCert("orphan")
	c.ParentID = ptrStr("does-not-exist")
	if err := InsertCert(db, c, sampleKey("orphan")); err == nil {
		t.Error("expected FK violation, got nil")
	}
	if _, err := GetCert(db, "orphan"); !errors.Is(err, ErrCertNotFound) {
		t.Error("certificates row should not have been written")
	}
	if _, err := GetCertKey(db, "orphan"); !errors.Is(err, ErrCertNotFound) {
		t.Error("cert_keys row should not have been written")
	}
}

func TestInsertCert_RejectsMismatchedIDs(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	c := sampleCert("a")
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	k := sampleKey("b") // mismatch
	if err := InsertCert(db, c, k); err == nil {
		t.Error("expected mismatched-ID error, got nil")
	}
}

func TestInsertCert_DefaultsAndCascade(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	c := sampleCert("root-id")
	c.Status = "" // exercise the "active" default
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	k := sampleKey("root-id")
	k.KEKTier = "" // exercise the "main" default
	if err := InsertCert(db, c, k); err != nil {
		t.Fatal(err)
	}

	got, err := GetCert(db, "root-id")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" {
		t.Errorf("status default: got %q, want active", got.Status)
	}
	gotKey, err := GetCertKey(db, "root-id")
	if err != nil {
		t.Fatal(err)
	}
	if gotKey.KEKTier != "main" {
		t.Errorf("kek_tier default: got %q, want main", gotKey.KEKTier)
	}
}

func ptrStr(s string) *string { return &s }
