package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// AAD labels for the two AEAD layers, per LIFECYCLE.md §2.2. Versioned so a
// future cipher migration can rotate without colliding with existing
// ciphertexts.
const (
	dekAADLabel = "homepki/dek/v1|"
	keyAADLabel = "homepki/key/v1|"
)

// SealedPrivateKey holds the four blobs produced by SealPrivateKey, each
// matching one column of the cert_keys table.
type SealedPrivateKey struct {
	WrappedDEK  []byte
	DEKNonce    []byte
	CipherNonce []byte
	Ciphertext  []byte
}

// SealPrivateKey performs the two-layer wrap from LIFECYCLE.md §2:
// generate a fresh 32-byte DEK, wrap it under kek (AAD = dek-label||certID),
// then encrypt plaintext under the DEK (AAD = key-label||certID). The DEK
// is zeroed before the function returns. Caller persists all four blobs.
func SealPrivateKey(kek []byte, certID string, plaintext []byte) (*SealedPrivateKey, error) {
	if len(kek) != KeyLen {
		return nil, fmt.Errorf("kek must be %d bytes", KeyLen)
	}
	if certID == "" {
		return nil, errors.New("certID required")
	}
	dek := make([]byte, KeyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("dek gen: %w", err)
	}
	defer Zero(dek)

	dekNonce, wrappedDEK, err := Seal(kek, dek, []byte(dekAADLabel+certID))
	if err != nil {
		return nil, fmt.Errorf("wrap dek: %w", err)
	}
	cipherNonce, ciphertext, err := Seal(dek, plaintext, []byte(keyAADLabel+certID))
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}
	return &SealedPrivateKey{
		WrappedDEK:  wrappedDEK,
		DEKNonce:    dekNonce,
		CipherNonce: cipherNonce,
		Ciphertext:  ciphertext,
	}, nil
}

// OpenPrivateKey reverses SealPrivateKey. The DEK is unwrapped under kek
// (with the same AAD binding to certID), then used to decrypt the
// ciphertext. The returned plaintext is the caller's; it should be parsed
// (e.g. via x509.ParsePKCS8PrivateKey) and zeroed promptly.
func OpenPrivateKey(kek []byte, certID string, sealed *SealedPrivateKey) ([]byte, error) {
	if len(kek) != KeyLen {
		return nil, fmt.Errorf("kek must be %d bytes", KeyLen)
	}
	if certID == "" {
		return nil, errors.New("certID required")
	}
	if sealed == nil {
		return nil, errors.New("sealed material required")
	}
	dek, err := Open(kek, sealed.DEKNonce, sealed.WrappedDEK, []byte(dekAADLabel+certID))
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}
	defer Zero(dek)
	return Open(dek, sealed.CipherNonce, sealed.Ciphertext, []byte(keyAADLabel+certID))
}
