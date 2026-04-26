package store

import (
	"database/sql"
	"testing"
)

func TestMigrate_AppliesV1Schema(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Migration 0001 should be recorded.
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if version != 1 {
		t.Errorf("schema_migrations version: got %d, want 1", version)
	}

	// All v1 tables should exist.
	want := []string{
		"settings",
		"certificates",
		"cert_keys",
		"crls",
		"deploy_targets",
		"idempotency_tokens",
	}
	for _, table := range want {
		var name string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing: %v", table, err)
		}
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	db := openTestDB(t)

	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	var first int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&first); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var second int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&second); err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Errorf("schema_migrations row count changed across runs: %d → %d", first, second)
	}
}

func TestMigrate_EnforcesForeignKeyAndCheckConstraints(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	// FK on cert_keys.cert_id should reject orphan rows.
	_, err := db.Exec(`
		INSERT INTO cert_keys (cert_id, wrapped_dek, dek_nonce, cipher_nonce, ciphertext)
		VALUES ('does-not-exist', x'00', x'00', x'00', x'00')
	`)
	if err == nil {
		t.Error("expected FK violation inserting orphan cert_keys row, got nil")
	}

	// CHECK constraint on certificates.type should reject unknown types.
	_, err = db.Exec(`
		INSERT INTO certificates (
			id, type, serial_number, subject_cn, is_ca, key_algo,
			not_before, not_after, der_cert, fingerprint_sha256
		) VALUES (
			'id1', 'gibberish', '01', 'cn', 0, 'rsa',
			'2026-01-01', '2027-01-01', x'00', 'fp'
		)
	`)
	if err == nil {
		t.Error("expected CHECK violation on certificates.type='gibberish', got nil")
	}
}

// openTestDB returns a fresh on-disk SQLite DB in a temp dir, with the same
// pragmas Open uses in production. We don't use ":memory:" because shared
// in-memory DBs and connection pools can interact awkwardly.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
