package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// SaltLen is the length of the KDF salt in bytes.
const SaltLen = 16

// Argon2idV13 is the only Argon2id version we accept. Older 0x10
// (v1.0) had a known cryptanalytic weakness; no v1.4 has shipped.
// Persisted alongside the other KDF params so a future version of
// homepki can detect a row written by an even-newer version it
// doesn't support, instead of silently mis-deriving the KEK.
const Argon2idV13 uint32 = 0x13

// KDFParams capture the Argon2id parameters used to derive a KEK from a
// passphrase. They are persisted alongside the salt so that defaults can
// change without breaking existing installs — every install always uses the
// params it was created with.
//
// See LIFECYCLE.md §1.1 for the v1 defaults.
type KDFParams struct {
	Time    uint32 `json:"time"`              // iterations
	Memory  uint32 `json:"memory"`            // KiB
	Threads uint8  `json:"threads"`           // parallelism
	KeyLen  uint32 `json:"key_len"`           // output length in bytes
	Version uint32 `json:"version,omitempty"` // Argon2id algorithm version; absent on legacy rows means Argon2idV13
}

// DefaultKDFParams returns the v1 Argon2id defaults: time=3, memory=64 MiB,
// threads=2, key_len=32, version=0x13.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 2,
		KeyLen:  32,
		Version: Argon2idV13,
	}
}

// NewSalt returns a cryptographically random salt of length SaltLen.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKEK runs Argon2id over passphrase with the given salt and parameters
// and returns a KeyLen-byte key. The caller owns the returned slice and is
// responsible for zeroing it when no longer needed.
func DeriveKEK(passphrase, salt []byte, p KDFParams) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt is empty")
	}
	if p.KeyLen == 0 {
		return nil, errors.New("KeyLen must be > 0")
	}
	if p.Time == 0 {
		return nil, errors.New("Time must be > 0")
	}
	if p.Memory == 0 {
		return nil, errors.New("Memory must be > 0")
	}
	if p.Threads == 0 {
		return nil, errors.New("Threads must be > 0")
	}
	// Version=0 covers rows persisted before the field existed; we
	// always produced Argon2id v1.3 so this is safe.
	if p.Version != 0 && p.Version != Argon2idV13 {
		return nil, fmt.Errorf("unsupported Argon2id version 0x%x; only 0x%x is supported", p.Version, Argon2idV13)
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}
