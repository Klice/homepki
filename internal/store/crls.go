package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Klice/homepki/internal/store/storedb"
)

// CRL mirrors a row in the crls table.
type CRL struct {
	IssuerCertID string
	CRLNumber    int64
	ThisUpdate   time.Time
	NextUpdate   time.Time
	DER          []byte
	UpdatedAt    time.Time
}

// ErrCRLNotFound is returned by GetLatestCRL when the issuer has no
// CRL row yet (per LIFECYCLE.md §6.2 a CA's first CRL is written at
// issuance, so this should be a programmer-error path in normal use).
var ErrCRLNotFound = errors.New("crl not found")

// InsertCRL writes a new CRL row.
func InsertCRL(db sqlcDBTX, c *CRL) error {
	if c == nil {
		return errors.New("InsertCRL: nil")
	}
	if c.IssuerCertID == "" {
		return errors.New("InsertCRL: IssuerCertID required")
	}
	if c.CRLNumber <= 0 {
		return fmt.Errorf("InsertCRL: CRLNumber must be positive, got %d", c.CRLNumber)
	}
	if len(c.DER) == 0 {
		return errors.New("InsertCRL: DER required")
	}
	err := storedb.New(db).InsertCRL(context.Background(), storedb.InsertCRLParams{
		IssuerCertID: c.IssuerCertID,
		CrlNumber:    c.CRLNumber,
		ThisUpdate:   c.ThisUpdate.UTC(),
		NextUpdate:   c.NextUpdate.UTC(),
		Der:          c.DER,
		UpdatedAt:    time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("InsertCRL: %w", err)
	}
	return nil
}

// GetLatestCRL returns the row with the highest crl_number for issuerID.
// Returns ErrCRLNotFound if no rows exist.
func GetLatestCRL(db sqlcDBTX, issuerID string) (*CRL, error) {
	if issuerID == "" {
		return nil, ErrCRLNotFound
	}
	row, err := storedb.New(db).GetLatestCRL(context.Background(), issuerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCRLNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetLatestCRL: %w", err)
	}
	return &CRL{
		IssuerCertID: row.IssuerCertID,
		CRLNumber:    row.CrlNumber,
		ThisUpdate:   row.ThisUpdate,
		NextUpdate:   row.NextUpdate,
		DER:          row.Der,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// NextCRLNumber returns one more than the highest crl_number for issuerID,
// or 1 if no CRLs exist yet. Strict monotonicity per LIFECYCLE.md §6.4.
func NextCRLNumber(db sqlcDBTX, issuerID string) (int64, error) {
	max, err := storedb.New(db).NextCRLNumber(context.Background(), issuerID)
	if err != nil {
		return 0, fmt.Errorf("NextCRLNumber: %w", err)
	}
	// MAX() returns NULL → interface{} nil → sqlc emits interface{}; we get
	// 0 from the type-assertion fallback path. Either way, "no rows" → 1.
	switch v := max.(type) {
	case int64:
		return v + 1, nil
	case nil:
		return 1, nil
	default:
		return 0, fmt.Errorf("NextCRLNumber: unexpected MAX type %T", v)
	}
}

// ListRevokedChildren returns the (serial, revocation_time, reason_code)
// triples for every cert that names issuerID as parent and has status
// 'revoked'. Per LIFECYCLE.md §5.5, expired certs are filtered out.
func ListRevokedChildren(db sqlcDBTX, issuerID string) ([]RevokedChild, error) {
	id := issuerID
	rows, err := storedb.New(db).ListRevokedChildren(context.Background(), &id)
	if err != nil {
		return nil, fmt.Errorf("ListRevokedChildren: %w", err)
	}
	out := make([]RevokedChild, 0, len(rows))
	for _, r := range rows {
		c := RevokedChild{
			SerialNumber: r.SerialNumber,
			ReasonCode:   int(r.ReasonCode),
		}
		if r.RevokedAt != nil {
			c.RevokedAt = *r.RevokedAt
		}
		out = append(out, c)
	}
	return out, nil
}

// RevokedChild is a row in the result of ListRevokedChildren — just the
// fields a CRL needs.
type RevokedChild struct {
	SerialNumber string // hex
	RevokedAt    time.Time
	ReasonCode   int
}

// MarkRevoked sets a cert to revoked atomically. Returns the number of rows
// affected — 0 means the cert was already revoked (or didn't exist), 1
// means we just transitioned it. Used by the revoke handler to detect
// "already revoked" for ensure-state semantics per API.md §6.6.
func MarkRevoked(db sqlcDBTX, certID string, reason int, when time.Time) (int, error) {
	revokedAt := when.UTC()
	r := int64(reason)
	n, err := storedb.New(db).MarkCertRevoked(context.Background(), storedb.MarkCertRevokedParams{
		RevokedAt:        &revokedAt,
		RevocationReason: &r,
		ID:               certID,
	})
	if err != nil {
		return 0, fmt.Errorf("MarkRevoked: %w", err)
	}
	return int(n), nil
}
