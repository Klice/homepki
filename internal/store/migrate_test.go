package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrate_AppliesV1Schema(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db), "Migrate")

	// Migration 0001 should be recorded.
	var version int
	require.NoError(t, db.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version),
		"read schema_migrations")
	assert.Equal(t, 1, version, "schema_migrations version")

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
		assert.NoError(t, err, "table %q missing", table)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	db := openTestDB(t)

	require.NoError(t, Migrate(db), "first Migrate")
	var first int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&first))

	require.NoError(t, Migrate(db), "second Migrate")
	var second int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&second))

	assert.Equal(t, first, second, "schema_migrations row count changed across runs")
}

func TestMigrate_EnforcesForeignKeyAndCheckConstraints(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	// FK on cert_keys.cert_id should reject orphan rows.
	_, err := db.Exec(`
		INSERT INTO cert_keys (cert_id, wrapped_dek, dek_nonce, cipher_nonce, ciphertext)
		VALUES ('does-not-exist', x'00', x'00', x'00', x'00')
	`)
	assert.Error(t, err, "expected FK violation inserting orphan cert_keys row")

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
	assert.Error(t, err, "expected CHECK violation on certificates.type='gibberish'")
}

// openTestDB returns a fresh on-disk SQLite DB in a temp dir, with the same
// pragmas Open uses in production. We don't use ":memory:" because shared
// in-memory DBs and connection pools can interact awkwardly.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(t.TempDir())
	require.NoError(t, err, "Open")
	t.Cleanup(func() { _ = db.Close() })
	return db
}
