package store

import (
	"errors"
	"testing"
	"time"
)

func TestCreateAndLookup_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatalf("CreateIdemToken: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("token length: got %d, want 64 (32 bytes hex)", len(tok))
	}

	got, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatalf("LookupIdemToken: %v", err)
	}
	if got.Token != tok {
		t.Errorf("token mismatch: got %q, want %q", got.Token, tok)
	}
	if got.UsedAt != nil {
		t.Errorf("fresh token should have nil UsedAt, got %v", *got.UsedAt)
	}
	if got.ResultURL != nil {
		t.Errorf("fresh token should have nil ResultURL, got %q", *got.ResultURL)
	}
	if !got.ExpiresAt.After(got.CreatedAt) {
		t.Errorf("ExpiresAt %v should be after CreatedAt %v", got.ExpiresAt, got.CreatedAt)
	}
}

func TestCreateUniqueness(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	a, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two consecutive CreateIdemToken calls returned the same token")
	}
}

func TestLookup_MissingReturnsSentinel(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := LookupIdemToken(db, "no-such-token"); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("got %v, want ErrIdemTokenNotFound", err)
	}
	if _, err := LookupIdemToken(db, ""); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("empty token: got %v, want ErrIdemTokenNotFound", err)
	}
}

func TestMarkUsed_RoundTripAndIdempotency(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}

	if err := MarkIdemTokenUsed(db, tok, "/certs/abc"); err != nil {
		t.Fatalf("MarkIdemTokenUsed: %v", err)
	}

	got, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedAt == nil {
		t.Error("UsedAt should be set after MarkIdemTokenUsed")
	}
	if got.ResultURL == nil || *got.ResultURL != "/certs/abc" {
		t.Errorf("ResultURL: got %v, want '/certs/abc'", got.ResultURL)
	}

	// A second mark on the same token must fail — the WHERE clause
	// "used_at IS NULL" filters it out, so RowsAffected = 0.
	if err := MarkIdemTokenUsed(db, tok, "/somewhere/else"); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("second mark: got %v, want ErrIdemTokenNotFound", err)
	}

	// And the original ResultURL is preserved.
	got, err = LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResultURL == nil || *got.ResultURL != "/certs/abc" {
		t.Errorf("after second mark, ResultURL was overwritten: got %v", got.ResultURL)
	}
}

func TestMarkUsed_UnknownToken(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := MarkIdemTokenUsed(db, "no-such", "/x"); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("got %v, want ErrIdemTokenNotFound", err)
	}
	if err := MarkIdemTokenUsed(db, "", "/x"); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("empty token: got %v, want ErrIdemTokenNotFound", err)
	}
}

func TestIssueCertWithToken_AtomicSuccess(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}

	c := sampleCert("issued-id")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	k := sampleKey("issued-id")

	if err := IssueCertWithToken(db, c, k, nil, tok, "/certs/issued-id"); err != nil {
		t.Fatalf("IssueCertWithToken: %v", err)
	}

	// Cert and key both written.
	if _, err := GetCert(db, "issued-id"); err != nil {
		t.Errorf("cert row missing: %v", err)
	}
	if _, err := GetCertKey(db, "issued-id"); err != nil {
		t.Errorf("key row missing: %v", err)
	}
	// Token marked used.
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.UsedAt == nil || row.ResultURL == nil || *row.ResultURL != "/certs/issued-id" {
		t.Errorf("token not marked: %+v", row)
	}
}

func TestIssueCertWithToken_RollsBackOnFKViolation(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}
	// Bad parent_id triggers FK violation inside insertCertTx.
	c := sampleCert("orphan")
	c.ParentID = ptrStr("does-not-exist")
	k := sampleKey("orphan")

	if err := IssueCertWithToken(db, c, k, nil, tok, "/x"); err == nil {
		t.Error("expected FK violation error, got nil")
	}
	// All three rows must be absent.
	if _, err := GetCert(db, "orphan"); !errors.Is(err, ErrCertNotFound) {
		t.Error("cert row should not have been written")
	}
	if _, err := GetCertKey(db, "orphan"); !errors.Is(err, ErrCertNotFound) {
		t.Error("key row should not have been written")
	}
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.UsedAt != nil {
		t.Error("token should not have been marked used after rollback")
	}
}

func TestIssueCertWithToken_WithInitialCRL(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}

	c := sampleCert("ca-id")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	k := sampleKey("ca-id")

	now := time.Now()
	crl := &CRL{
		IssuerCertID: "ca-id",
		CRLNumber:    1,
		ThisUpdate:   now,
		NextUpdate:   now.Add(7 * 24 * time.Hour),
		DER:          []byte{0xCA, 0xFE},
	}

	if err := IssueCertWithToken(db, c, k, crl, tok, "/certs/ca-id"); err != nil {
		t.Fatalf("IssueCertWithToken: %v", err)
	}

	// All four states must be visible after commit.
	if _, err := GetCert(db, "ca-id"); err != nil {
		t.Errorf("cert row missing: %v", err)
	}
	if _, err := GetCertKey(db, "ca-id"); err != nil {
		t.Errorf("key row missing: %v", err)
	}
	got, err := GetLatestCRL(db, "ca-id")
	if err != nil {
		t.Errorf("crl row missing: %v", err)
	} else if got.CRLNumber != 1 {
		t.Errorf("crl number: got %d, want 1", got.CRLNumber)
	}
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.UsedAt == nil {
		t.Error("token should have been marked used")
	}
}

func TestIssueCertWithToken_InitialCRLRollsBackOnFailure(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}

	// Mismatched issuer_cert_id will fail the FK on crls.issuer_cert_id
	// when the cert hasn't been inserted under that id.
	c := sampleCert("real-ca")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	crl := &CRL{
		IssuerCertID: "wrong-ca",
		CRLNumber:    1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		DER:          []byte{0x00},
	}
	if err := IssueCertWithToken(db, c, sampleKey("real-ca"), crl, tok, "/x"); err == nil {
		t.Fatal("expected FK violation, got nil")
	}
	// Cert, key, and token must all be in their pre-call state.
	if _, err := GetCert(db, "real-ca"); !errors.Is(err, ErrCertNotFound) {
		t.Error("cert row should not have been written")
	}
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.UsedAt != nil {
		t.Error("token should not have been marked used after rollback")
	}
}

func TestIssueCertWithToken_RejectsEmptyToken(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	c := sampleCert("x")
	c.Type = "root_ca"
	c.ParentID = nil
	if err := IssueCertWithToken(db, c, sampleKey("x"), nil, "", "/x"); err == nil {
		t.Error("expected error on empty form token")
	}
}

func TestCleanupExpired(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	// Make the just-created token "expired" by setting expires_at into the
	// past directly. CreateIdemToken won't do that itself.
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`UPDATE idempotency_tokens SET expires_at = datetime('now', '-1 hour') WHERE token = ?`,
		tok,
	); err != nil {
		t.Fatal(err)
	}

	n, err := CleanupExpiredIdemTokens(db)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deleted: got %d, want 1", n)
	}
	if _, err := LookupIdemToken(db, tok); !errors.Is(err, ErrIdemTokenNotFound) {
		t.Errorf("after cleanup: got %v, want ErrIdemTokenNotFound", err)
	}
}
