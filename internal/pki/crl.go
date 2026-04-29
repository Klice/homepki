package pki

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// CRLEntry is a single revoked-certificate entry in a CRL.
type CRLEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	// ReasonCode is an RFC 5280 reason. 0 ("unspecified") is omitted from
	// the encoded CRL per RFC 5280 §5.3.1.
	ReasonCode int
}

// CRLRequest is the input to CreateCRL.
type CRLRequest struct {
	Issuer     *Signer  // the CA whose CRL we're signing
	Number     *big.Int // strictly monotonic per-issuer CRL number
	ThisUpdate time.Time
	NextUpdate time.Time
	Entries    []CRLEntry
}

// CreateCRL produces a signed CRL DER per LIFECYCLE.md §6.4. An empty
// Entries slice is valid and produces an empty CRL (used for the initial
// CRL written on CA issuance per §6.2).
func CreateCRL(req CRLRequest) ([]byte, error) {
	if req.Issuer == nil {
		return nil, errors.New("Issuer required")
	}
	if req.Issuer.Cert == nil {
		return nil, errors.New("Issuer.Cert required")
	}
	if req.Issuer.Key == nil {
		return nil, errors.New("Issuer.Key required")
	}
	if req.Number == nil || req.Number.Sign() < 0 {
		return nil, errors.New("positive Number required")
	}
	if !req.NextUpdate.After(req.ThisUpdate) {
		return nil, fmt.Errorf("NextUpdate %v must be after ThisUpdate %v", req.NextUpdate, req.ThisUpdate)
	}

	entries := make([]x509.RevocationListEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		entry := x509.RevocationListEntry{
			SerialNumber:   e.SerialNumber,
			RevocationTime: e.RevocationTime,
		}
		// RFC 5280 §5.3.1: omit the reasonCode extension when value is
		// "unspecified". stdlib emits the extension whenever ReasonCode
		// is non-zero, so non-zero == include.
		if e.ReasonCode != 0 {
			entry.ReasonCode = e.ReasonCode
		}
		entries = append(entries, entry)
	}

	template := &x509.RevocationList{
		Number:                    req.Number,
		ThisUpdate:                req.ThisUpdate,
		NextUpdate:                req.NextUpdate,
		RevokedCertificateEntries: entries,
	}
	return x509.CreateRevocationList(rand.Reader, template, req.Issuer.Cert, req.Issuer.Key)
}
