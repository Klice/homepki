package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store/storedb"
)

// RewrapFunc is the per-row callback the rotation transaction calls to
// produce the new wrapped_dek + dek_nonce for a given cert_id. The closure
// owns the KEK_old / KEK_new context (we don't pass keys through the store
// layer).
//
// Returning an error rolls back the entire rotation — the operator's old
// passphrase still works (LIFECYCLE.md §1.6).
type RewrapFunc func(certID string, oldWrappedDEK, oldDEKNonce []byte) (newWrappedDEK, newDEKNonce []byte, err error)

// RotatePassphraseInputs bundles every settings-row update produced by the
// rotation. The store doesn't compute these — the caller (handler) owns the
// crypto and hands them in pre-marshalled.
type RotatePassphraseInputs struct {
	NewSalt       []byte // raw bytes
	NewParamsJSON []byte // JSON-encoded crypto.KDFParams
	NewVerifier   []byte // HMAC-SHA256(KEK_new, VerifierLabel)
}

// RotatePassphrase performs the rewrap-all-DEKs transaction described in
// LIFECYCLE.md §1.6 / STORAGE.md §7. In one DEFERRED tx:
//
//   1. Stream every cert_keys row, call rewrap to produce the new
//      (wrapped_dek, dek_nonce), update the row.
//   2. Write kdf_salt, kdf_params, passphrase_verifier into settings.
//   3. Mark the form token used.
//
// The transaction rolls back if any rewrap returns an error, leaving the
// store in its pre-rotation state. The caller is responsible for swapping
// the in-memory KEK only after this returns nil.
func RotatePassphrase(db *sql.DB, in RotatePassphraseInputs, rewrap RewrapFunc, formToken, resultURL string) error {
	if formToken == "" {
		return errors.New("RotatePassphrase: form token required")
	}
	if rewrap == nil {
		return errors.New("RotatePassphrase: rewrap callback required")
	}
	if len(in.NewSalt) == 0 || len(in.NewParamsJSON) == 0 || len(in.NewVerifier) == 0 {
		return errors.New("RotatePassphrase: salt, params, and verifier required")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("RotatePassphrase: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	q := storedb.New(tx)
	rows, err := q.ListCertKeyWraps(context.Background())
	if err != nil {
		return fmt.Errorf("RotatePassphrase: list cert_keys: %w", err)
	}
	for _, r := range rows {
		newWrapped, newNonce, err := rewrap(r.CertID, r.WrappedDek, r.DekNonce)
		if err != nil {
			return fmt.Errorf("RotatePassphrase: rewrap %s: %w", r.CertID, err)
		}
		n, err := q.UpdateCertKeyWrap(context.Background(), storedb.UpdateCertKeyWrapParams{
			WrappedDek: newWrapped,
			DekNonce:   newNonce,
			CertID:     r.CertID,
		})
		if err != nil {
			return fmt.Errorf("RotatePassphrase: update wrap %s: %w", r.CertID, err)
		}
		if n != 1 {
			return fmt.Errorf("RotatePassphrase: update wrap %s: rows affected = %d", r.CertID, n)
		}
	}

	for _, kv := range []struct {
		key   string
		value []byte
	}{
		{SettingKDFSalt, in.NewSalt},
		{SettingKDFParams, in.NewParamsJSON},
		{SettingPassphraseVerifier, in.NewVerifier},
	} {
		if err := SetSetting(tx, kv.key, kv.value); err != nil {
			return fmt.Errorf("RotatePassphrase: write %s: %w", kv.key, err)
		}
	}

	if err := MarkIdemTokenUsed(tx, formToken, resultURL); err != nil {
		return fmt.Errorf("RotatePassphrase: mark token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("RotatePassphrase: commit: %w", err)
	}
	return nil
}

// RewrapWithKEKs returns a RewrapFunc that unwraps each DEK with kekOld and
// re-wraps it with kekNew, both with AAD bound to the cert id per
// LIFECYCLE.md §2.2. Convenience helper for the common case; tests can
// supply their own RewrapFunc to inject failures.
func RewrapWithKEKs(kekOld, kekNew []byte) RewrapFunc {
	return func(certID string, oldWrapped, oldNonce []byte) ([]byte, []byte, error) {
		dek, err := crypto.Open(kekOld, oldNonce, oldWrapped, dekAAD(certID))
		if err != nil {
			return nil, nil, fmt.Errorf("unwrap dek: %w", err)
		}
		defer crypto.Zero(dek)
		newNonce, newWrapped, err := crypto.Seal(kekNew, dek, dekAAD(certID))
		if err != nil {
			return nil, nil, fmt.Errorf("wrap dek: %w", err)
		}
		return newWrapped, newNonce, nil
	}
}

// dekAAD reproduces the per-cert AAD label from internal/crypto so the
// rewrap helper here matches the Seal/Open binding used by SealPrivateKey
// (LIFECYCLE.md §2.2). Kept as a small private constant rather than
// exporting from crypto: the only caller is this rotation path.
func dekAAD(certID string) []byte {
	return []byte("homepki/dek/v1|" + certID)
}
