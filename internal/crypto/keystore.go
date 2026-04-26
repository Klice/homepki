package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// VerifierLabel is the constant string MAC'd under the KEK to produce a
// "verifier" stored alongside the salt and KDF params. On unlock, the
// candidate KEK is run through the same construction and the result is
// compared with the stored verifier in constant time. A match means the
// supplied passphrase derives the same KEK that was set at first run,
// without ever exposing key material.
const VerifierLabel = "homepki/verify/v1"

// Verifier returns HMAC-SHA256(kek, VerifierLabel). Stored in `settings`
// after first-run setup; recomputed on every unlock attempt.
func Verifier(kek []byte) []byte {
	mac := hmac.New(sha256.New, kek)
	mac.Write([]byte(VerifierLabel))
	return mac.Sum(nil)
}

// VerifierEqual compares two verifiers in constant time.
func VerifierEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// ErrLocked is returned from Keystore methods when the keystore is locked
// and the requested operation needs the KEK.
var ErrLocked = errors.New("keystore is locked")

// Keystore holds the in-memory KEK and exposes a small lock/unlock state
// machine. Methods are safe for concurrent use. The KEK byte slice is
// zeroed on Lock and on replacement via Install, so it is never resident
// any longer than necessary.
//
// Per LIFECYCLE.md §1, this is a process-global concept. v1 only ever
// constructs one Keystore.
type Keystore struct {
	mu  sync.RWMutex
	kek []byte // nil when locked
}

// NewKeystore returns an empty (locked) keystore.
func NewKeystore() *Keystore {
	return &Keystore{}
}

// Install replaces the in-memory KEK. The argument must be exactly 32
// bytes. After this call the keystore owns the slice — callers must not
// retain or zero it. Any previously-installed KEK is zeroed before being
// replaced.
func (k *Keystore) Install(kek []byte) error {
	if len(kek) != KeyLen {
		return errors.New("Install: kek must be 32 bytes")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kek != nil {
		zero(k.kek)
	}
	k.kek = kek
	return nil
}

// Lock zeros the in-memory KEK. No-op if the keystore is already locked.
func (k *Keystore) Lock() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kek != nil {
		zero(k.kek)
		k.kek = nil
	}
}

// IsUnlocked reports whether a KEK is currently held.
func (k *Keystore) IsUnlocked() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.kek != nil
}

// With invokes fn while holding a read lock on the keystore. fn receives
// a reference to the KEK byte slice; that reference must NOT escape fn.
// Returns ErrLocked if the keystore is locked, otherwise the result of fn.
//
// This is the only way a caller can use the KEK — there is no exported
// Get method by design, to keep the KEK from being copied around.
func (k *Keystore) With(fn func(kek []byte) error) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.kek == nil {
		return ErrLocked
	}
	return fn(k.kek)
}

// SessionSecretLabel is the HKDF info string for the session-cookie HMAC
// secret. Versioned so future changes to the cookie format can rotate it
// without colliding with stored sessions.
const SessionSecretLabel = "homepki/session-cookie/v1"

// SessionSecretLen is the length of the derived session HMAC secret.
const SessionSecretLen = 32

// DeriveSessionSecret returns a 32-byte HMAC key derived from the KEK via
// HKDF-SHA256. The derivation is deterministic per KEK, so the same KEK
// always yields the same secret — an unlock with the correct passphrase
// after a process restart re-derives the same session secret and existing
// session cookies remain valid. A passphrase rotation changes the KEK and
// therefore invalidates all sessions (per STORAGE.md §6).
//
// The caller owns the returned slice and is responsible for zeroing it
// when no longer needed. Returns ErrLocked if the keystore is locked.
func (k *Keystore) DeriveSessionSecret() ([]byte, error) {
	var out []byte
	err := k.With(func(kek []byte) error {
		h := hkdf.New(sha256.New, kek, nil, []byte(SessionSecretLabel))
		out = make([]byte, SessionSecretLen)
		_, err := io.ReadFull(h, out)
		return err
	})
	return out, err
}

// zero overwrites b with zeros. The compiler currently does not optimize
// this away because b is touched after the loop (the slice header is
// nilled by the caller).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
