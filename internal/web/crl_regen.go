package web

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"time"

	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

// ErrIssuerCannotSignCRL is returned by regenerateCRL when the issuer
// cert doesn't carry the cRLSign KeyUsage bit (RFC 5280 §4.2.1.3).
// Surfaces explicitly so callers can distinguish "this CA structurally
// cannot publish a CRL" from a transient signing failure. Most relevant
// to imported roots minted without cRLSign — homepki accepts the import
// (per persist.go) but won't write CRL rows for it.
var ErrIssuerCannotSignCRL = errors.New("issuer cert lacks cRLSign key usage")

// regenerateCRL builds a fresh CRL for issuerID by listing every revoked
// child cert and signing the result with the issuer's key. The new CRL row
// is inserted with a strictly-monotonic crl_number per LIFECYCLE.md §6.4.
//
// The signing requires the keystore to be unlocked (it decrypts the
// issuer's private key). Returns the freshly-inserted CRL row.
func (s *Server) regenerateCRL(issuerID string) (*store.CRL, error) {
	signer, _, err := s.loadSigner(issuerID)
	if err != nil {
		return nil, fmt.Errorf("regen CRL: load signer: %w", err)
	}
	if signer.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, ErrIssuerCannotSignCRL
	}

	children, err := store.ListRevokedChildren(s.db, issuerID)
	if err != nil {
		return nil, fmt.Errorf("regen CRL: list revoked: %w", err)
	}
	entries := make([]pki.CRLEntry, 0, len(children))
	for _, c := range children {
		serial, ok := new(big.Int).SetString(c.SerialNumber, 16)
		if !ok {
			return nil, fmt.Errorf("regen CRL: bad serial %q for child of %s", c.SerialNumber, issuerID)
		}
		entries = append(entries, pki.CRLEntry{
			SerialNumber:   serial,
			RevocationTime: c.RevokedAt,
			ReasonCode:     c.ReasonCode,
		})
	}

	nextNumber, err := store.NextCRLNumber(s.db, issuerID)
	if err != nil {
		return nil, fmt.Errorf("regen CRL: next number: %w", err)
	}
	now := time.Now()
	thisUpdate := now.Add(-crlClockSkewMargin)
	nextUpdate := now.Add(crlNextUpdateWindow)
	der, err := pki.CreateCRL(pki.CRLRequest{
		Issuer:     signer,
		Number:     big.NewInt(nextNumber),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		Entries:    entries,
	})
	if err != nil {
		return nil, fmt.Errorf("regen CRL: sign: %w", err)
	}
	row := &store.CRL{
		IssuerCertID: issuerID,
		CRLNumber:    nextNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		DER:          der,
	}
	if err := store.InsertCRL(s.db, row); err != nil {
		return nil, fmt.Errorf("regen CRL: insert: %w", err)
	}
	return row, nil
}

// revokeAndRegen marks cert revoked (or no-ops if it already was) and
// regenerates the issuer's CRL. Returns true on actual transition, false
// if the cert was already revoked (per API.md §6.6 ensure-state semantics:
// the caller still 303s to /certs/{id} either way).
func (s *Server) revokeAndRegen(cert *store.Cert, reason int) (bool, error) {
	n, err := store.MarkRevoked(s.db, cert.ID, reason, time.Now())
	if err != nil {
		return false, err
	}
	if n == 0 {
		// Already revoked — no transition, no need to regenerate.
		return false, nil
	}
	if cert.ParentID == nil {
		// Revoking a root: it has no parent CRL to update. Per
		// LIFECYCLE.md §5.4 the operator manages root revocation
		// out-of-band (trust store removal); homepki just marks it.
		return true, nil
	}
	if _, err := s.regenerateCRL(*cert.ParentID); err != nil {
		// Same shape as the root case: the issuer structurally
		// can't publish a CRL (typically an imported root minted
		// without cRLSign). Mark revoked, log, and treat the
		// transition as successful — the operator already accepted
		// the trade-off at import time.
		if errors.Is(err, ErrIssuerCannotSignCRL) {
			slog.Warn("revoke: issuer cannot sign CRL — revocation recorded but no CRL update",
				"cert", cert.ID, "issuer", *cert.ParentID)
			return true, nil
		}
		return true, err
	}
	return true, nil
}

// validReasonCode returns true if reason is one of the codes homepki
// supports per LIFECYCLE.md §5.2. CA-only codes (cACompromise=2,
// aACompromise=10) are accepted only when isCA is true.
func validReasonCode(reason int, isCA bool) bool {
	switch reason {
	case 0, 1, 3, 4, 5, 9: // unspecified, keyCompromise, affiliation, superseded, cessation, privilegeWithdrawn
		return true
	case 2, 10: // cACompromise, aACompromise
		return isCA
	}
	return false
}

// parseReason parses a string reason code and validates it against the
// supported set. Returns -1 + error on invalid input.
func parseReason(s string, isCA bool) (int, error) {
	if s == "" {
		return -1, fmt.Errorf("reason code required")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1, fmt.Errorf("reason code must be a number, got %q", s)
	}
	if !validReasonCode(n, isCA) {
		return -1, fmt.Errorf("reason code %d not supported", n)
	}
	return n, nil
}

// suppress unused warning for sql.DB when the file is included in tests
// that don't exercise it directly.
var _ = (*sql.DB)(nil)
