package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInsertAndGetLatestCRL(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)

	now := time.Now().UTC().Truncate(time.Second)
	crl := &CRL{
		IssuerCertID: rootID,
		CRLNumber:    1,
		ThisUpdate:   now,
		NextUpdate:   now.Add(7 * 24 * time.Hour),
		DER:          []byte{0x01, 0x02, 0x03},
	}
	require.NoError(t, InsertCRL(db, crl), "InsertCRL")

	got, err := GetLatestCRL(db, rootID)
	require.NoError(t, err, "GetLatestCRL")
	assert.Equal(t, int64(1), got.CRLNumber)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, got.DER)
}

func TestGetLatestCRL_NotFound(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := GetLatestCRL(db, "no-such-issuer")
	assert.ErrorIs(t, err, ErrCRLNotFound)
}

func TestGetLatestCRL_PicksHighestNumber(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)

	now := time.Now().UTC()
	for _, n := range []int64{1, 3, 2} {
		c := &CRL{
			IssuerCertID: rootID,
			CRLNumber:    n,
			ThisUpdate:   now,
			NextUpdate:   now.Add(time.Hour),
			DER:          []byte{byte(n)},
		}
		require.NoError(t, InsertCRL(db, c))
	}
	got, err := GetLatestCRL(db, rootID)
	require.NoError(t, err)
	assert.Equal(t, int64(3), got.CRLNumber)
}

func TestNextCRLNumber(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)

	// No CRLs yet → 1.
	n, err := NextCRLNumber(db, rootID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "first")

	require.NoError(t, InsertCRL(db, &CRL{
		IssuerCertID: rootID, CRLNumber: 7,
		ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		DER: []byte{0xff},
	}))
	n, err = NextCRLNumber(db, rootID)
	require.NoError(t, err)
	assert.Equal(t, int64(8), n, "after 7")
}

func TestInsertCRL_PKConflict(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)

	c := &CRL{
		IssuerCertID: rootID, CRLNumber: 1,
		ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		DER: []byte{0x00},
	}
	require.NoError(t, InsertCRL(db, c))
	assert.Error(t, InsertCRL(db, c), "expected PK conflict on duplicate (issuer, number)")
}

func TestListRevokedChildren(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, interID, leafID := seed(t, db)
	_ = interID

	// Initially no revocations.
	children, err := ListRevokedChildren(db, rootID)
	require.NoError(t, err)
	assert.Empty(t, children)

	// Revoke the intermediate (which is a child of root).
	_, err = MarkRevoked(db, interID, 4, time.Now())
	require.NoError(t, err)
	children, err = ListRevokedChildren(db, rootID)
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "01", children[0].SerialNumber)
	assert.Equal(t, 4, children[0].ReasonCode, "reason: want 4 (superseded)")

	// Revoke the leaf (child of intermediate, not root) — should not appear
	// in root's CRL.
	_, err = MarkRevoked(db, leafID, 1, time.Now())
	require.NoError(t, err)
	children, err = ListRevokedChildren(db, rootID)
	require.NoError(t, err)
	assert.Len(t, children, 1, "root CRL should still have 1 entry (the intermediate)")
}

func TestMarkRevoked_Idempotent(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, _, leafID := seed(t, db)

	n, err := MarkRevoked(db, leafID, 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "first")

	// Second call returns 0 — the cert is already revoked.
	n, err = MarkRevoked(db, leafID, 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "second: already revoked")

	got, err := GetCert(db, leafID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got.Status)
}

func TestMarkRevoked_Nonexistent(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	n, err := MarkRevoked(db, "no-such-id", 0, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}
