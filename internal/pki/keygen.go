package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"
)

// GenerateKey produces a fresh private key per spec, returned as
// crypto.Signer so callers handle all algorithms uniformly. Validates
// key parameters per LIFECYCLE.md §2.4 — RSA <2048 and unsupported
// curves are rejected.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	switch spec.Algo {
	case RSA:
		bits, err := strconv.Atoi(spec.Params)
		if err != nil {
			return nil, fmt.Errorf("rsa: invalid bit size %q", spec.Params)
		}
		switch bits {
		case 2048, 3072, 4096:
			// allowed
		default:
			return nil, fmt.Errorf("rsa: unsupported bit size %d (allowed: 2048, 3072, 4096)", bits)
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case ECDSA:
		var curve elliptic.Curve
		switch spec.Params {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("ecdsa: unsupported curve %q (allowed: P-256, P-384)", spec.Params)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key algo %q", spec.Algo)
	}
}
