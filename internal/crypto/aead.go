package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// KeyLen is the required key length for the AEAD primitives (AES-256-GCM).
const KeyLen = 32

// NonceLen is the GCM nonce length in bytes.
const NonceLen = 12

// Seal encrypts plaintext under key using AES-256-GCM with a freshly
// generated random nonce. The nonce is returned alongside the ciphertext;
// both must be persisted to recover the plaintext later via Open.
//
// The aad (additional authenticated data) is bound to the ciphertext but
// not encrypted; supplying a different aad to Open will fail authentication.
// homepki uses the cert id as part of the aad to prevent ciphertext
// substitution between rows (see LIFECYCLE.md §2.2).
func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeyLen {
		return nil, nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Open decrypts ciphertext under key using AES-256-GCM and verifies the aad.
// Returns the plaintext or an error if authentication fails (wrong key,
// wrong nonce, wrong aad, or tampered ciphertext).
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, errors.New("key must be 32 bytes")
	}
	if len(nonce) != NonceLen {
		return nil, errors.New("nonce must be 12 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
