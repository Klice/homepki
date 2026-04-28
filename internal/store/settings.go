package store

import (
	"database/sql"
	"errors"
)

// Well-known keys in the `settings` table. See STORAGE.md §5.2.
const (
	SettingPassphraseVerifier = "passphrase_verifier"
	SettingKDFSalt            = "kdf_salt"
	SettingKDFParams          = "kdf_params"
	SettingCRLBaseURL         = "crl_base_url"
)

// ErrSettingNotFound is returned by GetSetting when the key has no row.
var ErrSettingNotFound = errors.New("setting not found")

// dbtx is the read+write surface implemented by both *sql.DB and *sql.Tx.
// Callers may pass either, so helpers compose naturally inside a
// transaction (e.g. first-run setup writes salt+params+verifier atomically;
// revoke writes the cert update + new CRL row in one tx).
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// GetSetting returns the value stored under key. Returns ErrSettingNotFound
// if the key does not exist.
func GetSetting(db dbtx, key string) ([]byte, error) {
	var v []byte
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSettingNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// SetSetting upserts a value for key. The updated_at column is refreshed
// on every write.
func SetSetting(db dbtx, key string, value []byte) error {
	_, err := db.Exec(
		`INSERT INTO settings (key, value, updated_at)
		 VALUES (?, ?, datetime('now'))
		 ON CONFLICT(key) DO UPDATE
		   SET value      = excluded.value,
		       updated_at = excluded.updated_at`,
		key, value,
	)
	return err
}

// IsSetUp reports whether first-run setup has completed — i.e. whether the
// passphrase verifier is present. Used to gate the /setup vs /unlock flow
// per LIFECYCLE.md §1.1.
func IsSetUp(db dbtx) (bool, error) {
	_, err := GetSetting(db, SettingPassphraseVerifier)
	if errors.Is(err, ErrSettingNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
