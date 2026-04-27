package store

import (
	"bytes"
	"database/sql"
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

// makeCert builds a minimal cert for list/chain tests with all required
// fields populated. Caller overrides type, parent, ID as needed.
func makeCert(id, ctype string, parentID *string, cn string) *Cert {
	return &Cert{
		ID:                id,
		Type:              ctype,
		ParentID:          parentID,
		SerialNumber:      "01",
		SubjectCN:         cn,
		IsCA:              ctype != "leaf",
		KeyAlgo:           "ecdsa",
		KeyAlgoParams:     "P-256",
		NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DERCert:           []byte{0x30, 0x82, 0x01},
		FingerprintSHA256: "fp-" + id,
	}
}

// seed inserts a small chain — root → intermediate → leaf — with stable IDs.
func seed(t *testing.T, db *sql.DB) (rootID, interID, leafID string) {
	t.Helper()
	rootID, interID, leafID = "root-id", "inter-id", "leaf-id"
	if err := InsertCert(db, makeCert(rootID, "root_ca", nil, "Root"), sampleKey(rootID)); err != nil {
		t.Fatalf("seed root: %v", err)
	}
	rid := rootID
	if err := InsertCert(db, makeCert(interID, "intermediate_ca", &rid, "Intermediate"), sampleKey(interID)); err != nil {
		t.Fatalf("seed intermediate: %v", err)
	}
	iid := interID
	if err := InsertCert(db, makeCert(leafID, "leaf", &iid, "leaf.test"), sampleKey(leafID)); err != nil {
		t.Fatalf("seed leaf: %v", err)
	}
	return rootID, interID, leafID
}

func TestListCAs(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, interID, _ := seed(t, db)

	cas, err := ListCAs(db)
	if err != nil {
		t.Fatalf("ListCAs: %v", err)
	}
	gotIDs := map[string]bool{}
	for _, c := range cas {
		gotIDs[c.ID] = true
	}
	if !gotIDs[rootID] || !gotIDs[interID] {
		t.Errorf("ListCAs missing entries: got %v", gotIDs)
	}
	if len(cas) != 2 {
		t.Errorf("ListCAs len: got %d, want 2", len(cas))
	}
}

func TestListLeaves(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	_, _, leafID := seed(t, db)

	leaves, err := ListLeaves(db)
	if err != nil {
		t.Fatalf("ListLeaves: %v", err)
	}
	if len(leaves) != 1 || leaves[0].ID != leafID {
		t.Errorf("ListLeaves: got %d entries", len(leaves))
	}
}

func TestListCAs_EmptyOnFreshDB(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	cas, err := ListCAs(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 0 {
		t.Errorf("expected empty, got %d", len(cas))
	}
}

func TestGetChain_LeafToRoot(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, interID, leafID := seed(t, db)

	chain, err := GetChain(db, leafID)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length: got %d, want 3", len(chain))
	}
	if chain[0].ID != leafID || chain[1].ID != interID || chain[2].ID != rootID {
		t.Errorf("chain order: got %s -> %s -> %s, want %s -> %s -> %s",
			chain[0].ID, chain[1].ID, chain[2].ID, leafID, interID, rootID)
	}
}

func TestGetChain_RootIsSingleton(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, _, _ := seed(t, db)
	chain, err := GetChain(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0].ID != rootID {
		t.Errorf("chain: got %d entries", len(chain))
	}
}

func TestGetChain_NotFound(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := GetChain(db, "no-such"); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("got %v, want ErrCertNotFound", err)
	}
}
