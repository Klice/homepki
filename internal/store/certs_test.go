package store

import (
	"bytes"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, Migrate(db))
	// Insert the parent first to satisfy the FK.
	parent := sampleCert("parent-id")
	parent.Type = "intermediate_ca"
	parent.ParentID = nil
	parent.IsCA = true
	parent.SubjectCN = "parent"
	require.NoError(t, InsertCert(db, parent, sampleKey("parent-id")), "Insert parent")

	leafID := "leaf-id"
	in := sampleCert(leafID)
	inKey := sampleKey(leafID)
	require.NoError(t, InsertCert(db, in, inKey), "Insert leaf")

	got, err := GetCert(db, leafID)
	require.NoError(t, err, "GetCert")
	// Fields the DB sets default values for; copy them over for comparison.
	in.CreatedAt = got.CreatedAt
	assert.Equal(t, in, got)

	gotKey, err := GetCertKey(db, leafID)
	require.NoError(t, err, "GetCertKey")
	assert.Equal(t, inKey, gotKey)
}

func TestGet_NotFound(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := GetCert(db, "no-such")
	assert.ErrorIs(t, err, ErrCertNotFound)
	_, err = GetCertKey(db, "no-such")
	assert.ErrorIs(t, err, ErrCertNotFound)
}

func TestInsertCert_AtomicOnFK(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	// parent-id doesn't exist → FK violation rolls back, both rows absent.
	c := sampleCert("orphan")
	c.ParentID = ptrStr("does-not-exist")
	err := InsertCert(db, c, sampleKey("orphan"))
	assert.Error(t, err, "expected FK violation")
	_, err = GetCert(db, "orphan")
	assert.ErrorIs(t, err, ErrCertNotFound, "certificates row should not have been written")
	_, err = GetCertKey(db, "orphan")
	assert.ErrorIs(t, err, ErrCertNotFound, "cert_keys row should not have been written")
}

func TestInsertCert_RejectsMismatchedIDs(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	c := sampleCert("a")
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	k := sampleKey("b") // mismatch
	assert.Error(t, InsertCert(db, c, k), "expected mismatched-ID error")
}

func TestInsertCert_DefaultsAndCascade(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	c := sampleCert("root-id")
	c.Status = "" // exercise the "active" default
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	k := sampleKey("root-id")
	k.KEKTier = "" // exercise the "main" default
	require.NoError(t, InsertCert(db, c, k))

	got, err := GetCert(db, "root-id")
	require.NoError(t, err)
	assert.Equal(t, "active", got.Status)
	gotKey, err := GetCertKey(db, "root-id")
	require.NoError(t, err)
	assert.Equal(t, "main", gotKey.KEKTier)
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
	require.NoError(t, InsertCert(db, makeCert(rootID, "root_ca", nil, "Root"), sampleKey(rootID)), "seed root")
	rid := rootID
	require.NoError(t, InsertCert(db, makeCert(interID, "intermediate_ca", &rid, "Intermediate"), sampleKey(interID)), "seed intermediate")
	iid := interID
	require.NoError(t, InsertCert(db, makeCert(leafID, "leaf", &iid, "leaf.test"), sampleKey(leafID)), "seed leaf")
	return rootID, interID, leafID
}

func TestListCAs(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, interID, _ := seed(t, db)

	cas, err := ListCAs(db)
	require.NoError(t, err, "ListCAs")
	gotIDs := map[string]bool{}
	for _, c := range cas {
		gotIDs[c.ID] = true
	}
	assert.True(t, gotIDs[rootID] && gotIDs[interID], "ListCAs missing entries: got %v", gotIDs)
	assert.Len(t, cas, 2)
}

func TestListLeaves(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, _, leafID := seed(t, db)

	leaves, err := ListLeaves(db)
	require.NoError(t, err, "ListLeaves")
	require.Len(t, leaves, 1)
	assert.Equal(t, leafID, leaves[0].ID)
}

func TestListCAs_EmptyOnFreshDB(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	cas, err := ListCAs(db)
	require.NoError(t, err)
	assert.Empty(t, cas)
}

func TestGetChain_LeafToRoot(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, interID, leafID := seed(t, db)

	chain, err := GetChain(db, leafID)
	require.NoError(t, err, "GetChain")
	require.Len(t, chain, 3)
	assert.Equal(t, leafID, chain[0].ID)
	assert.Equal(t, interID, chain[1].ID)
	assert.Equal(t, rootID, chain[2].ID)
}

func TestGetChain_RootIsSingleton(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)
	chain, err := GetChain(db, rootID)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, rootID, chain[0].ID)
}

func TestGetChain_NotFound(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := GetChain(db, "no-such")
	assert.ErrorIs(t, err, ErrCertNotFound)
}
