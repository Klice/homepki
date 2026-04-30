package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// PEM block types we accept on the import path. PKCS#1 RSA / EC PRIVATE KEY
// blocks are explicitly rejected so the operator gets a clear "convert with
// openssl pkcs8 -topk8" hint instead of an opaque parse error.
const (
	pemBlockCertificate    = "CERTIFICATE"
	pemBlockPrivateKey     = "PRIVATE KEY"
	pemBlockRSAPrivateKey  = "RSA PRIVATE KEY"
	pemBlockECPrivateKey   = "EC PRIVATE KEY"
)

// ParseSingleCertPEM expects exactly one CERTIFICATE PEM block and returns
// the parsed *x509.Certificate. Empty input, multiple blocks, blocks of the
// wrong type, and bad DER all return errors with messages worded for the
// operator (this is a UI-facing path).
func ParseSingleCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("certificate PEM is empty")
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in certificate field")
	}
	if block.Type != pemBlockCertificate {
		return nil, fmt.Errorf("expected a %q PEM block, got %q", pemBlockCertificate, block.Type)
	}
	// Tolerate trailing whitespace; reject a second cert block (an
	// imported root has exactly one cert).
	if next, _ := pem.Decode(rest); next != nil {
		return nil, errors.New("expected exactly one certificate, found more than one PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate DER: %w", err)
	}
	return cert, nil
}

// ParsePrivateKeyPEM expects exactly one PRIVATE KEY (PKCS#8) block and
// returns the parsed key as a crypto.Signer ready for the existing wrap
// path in internal/web/persist.go. Legacy PKCS#1 / EC PRIVATE KEY blocks
// are rejected with a hint pointing at the openssl one-liner that
// converts them.
func ParsePrivateKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("private-key PEM is empty")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in private-key field")
	}
	switch block.Type {
	case pemBlockPrivateKey:
		// PKCS#8 — what we want.
	case pemBlockRSAPrivateKey, pemBlockECPrivateKey:
		return nil, fmt.Errorf("got %q; convert to PKCS#8 first: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem", block.Type)
	default:
		return nil, fmt.Errorf("expected a %q PEM block, got %q", pemBlockPrivateKey, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T is not a crypto.Signer", parsed)
	}
	return signer, nil
}

// MatchKeyToCert reports whether the cert's public key matches the
// supplied private key. Uses the per-type Equal methods that *rsa.PublicKey
// / *ecdsa.PublicKey / ed25519.PublicKey all expose, so the comparison is
// the canonical one (constant-time where it matters, type-checked).
//
// Returns nil on match, a clear "key does not match certificate" error on
// mismatch, and a typed error if the cert/key combination uses an
// unsupported algorithm.
func MatchKeyToCert(cert *x509.Certificate, key crypto.Signer) error {
	if cert == nil {
		return errors.New("MatchKeyToCert: cert required")
	}
	if key == nil {
		return errors.New("MatchKeyToCert: key required")
	}
	pub := key.Public()
	switch certPub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		got, ok := pub.(*rsa.PublicKey)
		if !ok || !certPub.Equal(got) {
			return errors.New("key does not match certificate (RSA mismatch)")
		}
	case *ecdsa.PublicKey:
		got, ok := pub.(*ecdsa.PublicKey)
		if !ok || !certPub.Equal(got) {
			return errors.New("key does not match certificate (ECDSA mismatch)")
		}
	case ed25519.PublicKey:
		got, ok := pub.(ed25519.PublicKey)
		if !ok || !certPub.Equal(got) {
			return errors.New("key does not match certificate (Ed25519 mismatch)")
		}
	default:
		return fmt.Errorf("unsupported certificate public-key type %T", cert.PublicKey)
	}
	return nil
}

// KeySpecOf inspects the cert's public key and returns the corresponding
// KeyAlgo + parameter string (matches the values stored in the
// certificates.key_algo / key_algo_params columns). Used by the import
// handler — homepki didn't generate the key, so we describe what's
// inside it for storage.
func KeySpecOf(cert *x509.Certificate) (KeyAlgo, string, error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return RSA, fmt.Sprintf("%d", pub.N.BitLen()), nil
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return ECDSA, "P-256", nil
		case elliptic.P384():
			return ECDSA, "P-384", nil
		case elliptic.P521():
			return ECDSA, "P-521", nil
		}
		return ECDSA, pub.Params().Name, nil
	case ed25519.PublicKey:
		return Ed25519, "", nil
	default:
		return "", "", fmt.Errorf("unsupported public-key type %T", cert.PublicKey)
	}
}

// ValidateRootCert is the gatekeeper for /certs/import/root: the certificate
// must be a self-signed CA. Returns an error worded for operator display.
//
// Self-signed is enforced both by Subject == Issuer (cheap canonical check)
// and by signature verification under the cert's own public key (catches
// forged Subject DNs that don't actually self-sign).
//
// Expiry is checked but not fatal: an expired root carrying its private key
// might still be useful (the operator may want to issue a final
// out-of-band CRL, then rotate). The function returns a typed
// ErrCertExpired in that case, which the handler logs as a warning but
// allows through. All other validation errors are hard rejections.
var ErrCertExpired = errors.New("certificate is expired")

func ValidateRootCert(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("ValidateRootCert: cert required")
	}
	if !cert.BasicConstraintsValid {
		return errors.New("certificate has no BasicConstraints extension; not a CA")
	}
	if !cert.IsCA {
		return errors.New("certificate is not a CA (BasicConstraints CA=false)")
	}
	// Self-signed: subject and issuer DNs must be identical *and* the
	// signature must verify under the cert's own public key. We check
	// both because a forged Subject DN can match Issuer without the
	// signature actually validating.
	if cert.Subject.String() != cert.Issuer.String() {
		return errors.New("certificate is not self-signed (Subject != Issuer); only self-signed roots can be imported")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate self-signature does not verify: %w", err)
	}
	if time.Now().After(cert.NotAfter) {
		return ErrCertExpired
	}
	return nil
}
