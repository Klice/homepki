package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Klice/homepki/internal/store/storedb"
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

// sqlcDBTX is the read+write surface sqlc-generated queries expect.
// *sql.DB and *sql.Tx both satisfy it, so helpers in this package
// compose naturally inside transactions.
type sqlcDBTX = storedb.DBTX

// GetSetting returns the value stored under key. Returns ErrSettingNotFound
// if the key does not exist.
func GetSetting(db sqlcDBTX, key string) ([]byte, error) {
	v, err := storedb.New(db).GetSetting(context.Background(), key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSettingNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// SetSetting upserts a value for key.
func SetSetting(db sqlcDBTX, key string, value []byte) error {
	return storedb.New(db).UpsertSetting(context.Background(), storedb.UpsertSettingParams{
		Key:   key,
		Value: value,
	})
}

// SetSettingIfMissing inserts a value for key only when no row exists yet.
// Returns true if a row was written, false if one was already present.
// Used for "snapshot" settings that must never overwrite (e.g.
// crl_base_url per STORAGE.md §5.2 — captured at first issuance and
// then frozen so drift can be detected).
func SetSettingIfMissing(db sqlcDBTX, key string, value []byte) (bool, error) {
	n, err := storedb.New(db).InsertSettingIfMissing(context.Background(), storedb.InsertSettingIfMissingParams{
		Key:   key,
		Value: value,
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// IsSetUp reports whether first-run setup has completed — i.e. whether the
// passphrase verifier is present. Used to gate the /setup vs /unlock flow
// per LIFECYCLE.md §1.1.
func IsSetUp(db sqlcDBTX) (bool, error) {
	_, err := GetSetting(db, SettingPassphraseVerifier)
	if errors.Is(err, ErrSettingNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
