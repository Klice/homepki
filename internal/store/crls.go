package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
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
func InsertCRL(db dbtx, c *CRL) error {
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
	_, err := db.Exec(
		`INSERT INTO crls (issuer_cert_id, crl_number, this_update, next_update, der, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.IssuerCertID, c.CRLNumber, c.ThisUpdate.UTC(), c.NextUpdate.UTC(), c.DER, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("InsertCRL: %w", err)
	}
	return nil
}

// GetLatestCRL returns the row with the highest crl_number for issuerID.
// Returns ErrCRLNotFound if no rows exist.
func GetLatestCRL(db dbtx, issuerID string) (*CRL, error) {
	if issuerID == "" {
		return nil, ErrCRLNotFound
	}
	var c CRL
	err := db.QueryRow(
		`SELECT issuer_cert_id, crl_number, this_update, next_update, der, updated_at
		 FROM crls
		 WHERE issuer_cert_id = ?
		 ORDER BY crl_number DESC
		 LIMIT 1`,
		issuerID,
	).Scan(&c.IssuerCertID, &c.CRLNumber, &c.ThisUpdate, &c.NextUpdate, &c.DER, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCRLNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetLatestCRL: %w", err)
	}
	return &c, nil
}

// NextCRLNumber returns one more than the highest crl_number for issuerID,
// or 1 if no CRLs exist yet. Strict monotonicity per LIFECYCLE.md §6.4.
func NextCRLNumber(db dbtx, issuerID string) (int64, error) {
	var n sql.NullInt64
	err := db.QueryRow(
		`SELECT MAX(crl_number) FROM crls WHERE issuer_cert_id = ?`,
		issuerID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("NextCRLNumber: %w", err)
	}
	if !n.Valid {
		return 1, nil
	}
	return n.Int64 + 1, nil
}

// ListRevokedChildren returns the (serial, revocation_time, reason_code)
// triples for every cert that names issuerID as parent and has status
// 'revoked'. Per LIFECYCLE.md §5.5, expired certs are filtered out (no
// point listing them on a CRL clients won't accept anyway).
func ListRevokedChildren(db dbtx, issuerID string) ([]RevokedChild, error) {
	rows, err := db.Query(
		`SELECT serial_number, revoked_at, COALESCE(revocation_reason, 0)
		 FROM certificates
		 WHERE parent_id = ?
		   AND status = 'revoked'
		   AND not_after > datetime('now')
		 ORDER BY revoked_at`,
		issuerID,
	)
	if err != nil {
		return nil, fmt.Errorf("ListRevokedChildren: %w", err)
	}
	defer rows.Close()
	var out []RevokedChild
	for rows.Next() {
		var c RevokedChild
		var revokedAt sql.NullTime
		if err := rows.Scan(&c.SerialNumber, &revokedAt, &c.ReasonCode); err != nil {
			return nil, err
		}
		if revokedAt.Valid {
			c.RevokedAt = revokedAt.Time
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
func MarkRevoked(db dbtx, certID string, reason int, when time.Time) (int, error) {
	res, err := db.Exec(
		`UPDATE certificates
		   SET status = 'revoked', revoked_at = ?, revocation_reason = ?
		   WHERE id = ? AND status != 'revoked'`,
		when.UTC(), reason, certID,
	)
	if err != nil {
		return 0, fmt.Errorf("MarkRevoked: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
