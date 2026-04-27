package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// IdemTokenTTL is the lifetime of a form token. Matches API.md §2.7.1.
const IdemTokenTTL = 24 * time.Hour

// ErrIdemTokenNotFound is returned when a token is missing, expired, or
// otherwise unknown.
var ErrIdemTokenNotFound = errors.New("idempotency token not found or expired")

// IdemToken is a row in idempotency_tokens. UsedAt and ResultURL are nil
// until the token is consumed.
type IdemToken struct {
	Token     string
	CreatedAt time.Time
	UsedAt    *time.Time
	ResultURL *string
	ExpiresAt time.Time
}

// CreateIdemToken generates a fresh 32-byte hex token and persists it with
// a TTL of IdemTokenTTL. Returns the token to embed in a rendered form.
func CreateIdemToken(db dbtx) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("CreateIdemToken: rand: %w", err)
	}
	token := hex.EncodeToString(raw)
	now := time.Now().UTC()
	if _, err := db.Exec(
		`INSERT INTO idempotency_tokens (token, created_at, expires_at)
		 VALUES (?, ?, ?)`,
		token, now, now.Add(IdemTokenTTL),
	); err != nil {
		return "", fmt.Errorf("CreateIdemToken: %w", err)
	}
	return token, nil
}

// LookupIdemToken returns the row for token. Returns ErrIdemTokenNotFound
// if the token is missing, expired, or otherwise unknown. Side effect:
// rows whose expires_at has passed are filtered out by the WHERE clause —
// physical cleanup is the periodic sweep's job per STORAGE.md §5.7.
func LookupIdemToken(db dbtx, token string) (*IdemToken, error) {
	if token == "" {
		return nil, ErrIdemTokenNotFound
	}
	var t IdemToken
	var usedAt sql.NullTime
	var resultURL sql.NullString
	err := db.QueryRow(
		`SELECT token, created_at, used_at, result_url, expires_at
		 FROM idempotency_tokens
		 WHERE token = ? AND expires_at > datetime('now')`,
		token,
	).Scan(&t.Token, &t.CreatedAt, &usedAt, &resultURL, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdemTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("LookupIdemToken: %w", err)
	}
	if usedAt.Valid {
		v := usedAt.Time
		t.UsedAt = &v
	}
	if resultURL.Valid {
		v := resultURL.String
		t.ResultURL = &v
	}
	return &t, nil
}

// MarkIdemTokenUsed atomically sets used_at and result_url on a token that
// hasn't been used yet. Returns ErrIdemTokenNotFound if no such row exists.
// Used in conjunction with the operation it gates (e.g. cert issuance) in
// the same transaction so the "operation succeeded + token marked" state
// is all-or-nothing.
func MarkIdemTokenUsed(db dbtx, token, resultURL string) error {
	if token == "" {
		return ErrIdemTokenNotFound
	}
	res, err := db.Exec(
		`UPDATE idempotency_tokens
		   SET used_at = datetime('now'), result_url = ?
		   WHERE token = ? AND used_at IS NULL`,
		resultURL, token,
	)
	if err != nil {
		return fmt.Errorf("MarkIdemTokenUsed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrIdemTokenNotFound
	}
	return nil
}

// CleanupExpiredIdemTokens deletes every token whose TTL has passed.
// Idempotent. Intended for a periodic sweep per STORAGE.md §5.7.
func CleanupExpiredIdemTokens(db dbtx) (int, error) {
	res, err := db.Exec(`DELETE FROM idempotency_tokens WHERE expires_at <= datetime('now')`)
	if err != nil {
		return 0, fmt.Errorf("CleanupExpiredIdemTokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
