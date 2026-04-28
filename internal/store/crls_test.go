package store

import (
	"errors"
	"testing"
	"time"
)

func TestInsertAndGetLatestCRL(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, _, _ := seed(t, db)

	now := time.Now().UTC().Truncate(time.Second)
	crl := &CRL{
		IssuerCertID: rootID,
		CRLNumber:    1,
		ThisUpdate:   now,
		NextUpdate:   now.Add(7 * 24 * time.Hour),
		DER:          []byte{0x01, 0x02, 0x03},
	}
	if err := InsertCRL(db, crl); err != nil {
		t.Fatalf("InsertCRL: %v", err)
	}

	got, err := GetLatestCRL(db, rootID)
	if err != nil {
		t.Fatalf("GetLatestCRL: %v", err)
	}
	if got.CRLNumber != 1 {
		t.Errorf("CRLNumber: got %d, want 1", got.CRLNumber)
	}
	if string(got.DER) != "\x01\x02\x03" {
		t.Errorf("DER mismatch: got %x", got.DER)
	}
}

func TestGetLatestCRL_NotFound(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := GetLatestCRL(db, "no-such-issuer"); !errors.Is(err, ErrCRLNotFound) {
		t.Errorf("got %v, want ErrCRLNotFound", err)
	}
}

func TestGetLatestCRL_PicksHighestNumber(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
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
		if err := InsertCRL(db, c); err != nil {
			t.Fatal(err)
		}
	}
	got, err := GetLatestCRL(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CRLNumber != 3 {
		t.Errorf("got %d, want 3", got.CRLNumber)
	}
}

func TestNextCRLNumber(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, _, _ := seed(t, db)

	// No CRLs yet → 1.
	n, err := NextCRLNumber(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("first: got %d, want 1", n)
	}

	if err := InsertCRL(db, &CRL{
		IssuerCertID: rootID, CRLNumber: 7,
		ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		DER: []byte{0xff},
	}); err != nil {
		t.Fatal(err)
	}
	n, err = NextCRLNumber(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Errorf("after 7: got %d, want 8", n)
	}
}

func TestInsertCRL_PKConflict(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, _, _ := seed(t, db)

	c := &CRL{
		IssuerCertID: rootID, CRLNumber: 1,
		ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		DER: []byte{0x00},
	}
	if err := InsertCRL(db, c); err != nil {
		t.Fatal(err)
	}
	if err := InsertCRL(db, c); err == nil {
		t.Error("expected PK conflict on duplicate (issuer, number), got nil")
	}
}

func TestListRevokedChildren(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	rootID, interID, leafID := seed(t, db)
	_ = interID

	// Initially no revocations.
	children, err := ListRevokedChildren(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 0 {
		t.Errorf("got %d, want 0", len(children))
	}

	// Revoke the intermediate (which is a child of root).
	if _, err := MarkRevoked(db, interID, 4, time.Now()); err != nil {
		t.Fatal(err)
	}
	children, err = ListRevokedChildren(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 1 {
		t.Fatalf("got %d, want 1", len(children))
	}
	if children[0].SerialNumber != "01" {
		t.Errorf("serial: got %q, want 01", children[0].SerialNumber)
	}
	if children[0].ReasonCode != 4 {
		t.Errorf("reason: got %d, want 4 (superseded)", children[0].ReasonCode)
	}

	// Revoke the leaf (child of intermediate, not root) — should not appear
	// in root's CRL.
	if _, err := MarkRevoked(db, leafID, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	children, err = ListRevokedChildren(db, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if len(children) != 1 {
		t.Errorf("root CRL should still have 1 entry (the intermediate); got %d", len(children))
	}
}

func TestMarkRevoked_Idempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	_, _, leafID := seed(t, db)

	n, err := MarkRevoked(db, leafID, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("first: got %d, want 1", n)
	}

	// Second call returns 0 — the cert is already revoked.
	n, err = MarkRevoked(db, leafID, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second: got %d, want 0 (already revoked)", n)
	}

	got, err := GetCert(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "revoked" {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

func TestMarkRevoked_Nonexistent(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	n, err := MarkRevoked(db, "no-such-id", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}
