package pki

import (
	"crypto/rand"
	"math/big"
)

// NewSerial returns a cryptographically-random 159-bit positive integer
// suitable for use as an x509 serial number. RFC 5280 §4.1.2.2 caps the
// serial at 20 bytes; 159 bits keeps the high bit of byte 0 cleared so
// the encoded INTEGER stays positive without needing a leading zero pad.
func NewSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, max)
}
