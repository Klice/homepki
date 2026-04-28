package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Klice/homepki/internal/store/storedb"
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
func CreateIdemToken(db sqlcDBTX) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("CreateIdemToken: rand: %w", err)
	}
	token := hex.EncodeToString(raw)
	now := time.Now().UTC()
	err := storedb.New(db).InsertIdemToken(context.Background(), storedb.InsertIdemTokenParams{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(IdemTokenTTL),
	})
	if err != nil {
		return "", fmt.Errorf("CreateIdemToken: %w", err)
	}
	return token, nil
}

// LookupIdemToken returns the row for token. Returns ErrIdemTokenNotFound
// if the token is missing, expired, or otherwise unknown.
func LookupIdemToken(db sqlcDBTX, token string) (*IdemToken, error) {
	if token == "" {
		return nil, ErrIdemTokenNotFound
	}
	row, err := storedb.New(db).GetIdemToken(context.Background(), token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdemTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("LookupIdemToken: %w", err)
	}
	return &IdemToken{
		Token:     row.Token,
		CreatedAt: row.CreatedAt,
		UsedAt:    row.UsedAt,
		ResultURL: row.ResultUrl,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// MarkIdemTokenUsed atomically sets used_at and result_url on a token that
// hasn't been used yet. Returns ErrIdemTokenNotFound if no such row exists.
func MarkIdemTokenUsed(db sqlcDBTX, token, resultURL string) error {
	if token == "" {
		return ErrIdemTokenNotFound
	}
	url := resultURL
	n, err := storedb.New(db).MarkIdemTokenUsed(context.Background(), storedb.MarkIdemTokenUsedParams{
		ResultUrl: &url,
		Token:     token,
	})
	if err != nil {
		return fmt.Errorf("MarkIdemTokenUsed: %w", err)
	}
	if n == 0 {
		return ErrIdemTokenNotFound
	}
	return nil
}

// CleanupExpiredIdemTokens deletes every token whose TTL has passed.
// Idempotent. Intended for a periodic sweep per STORAGE.md §5.7.
func CleanupExpiredIdemTokens(db sqlcDBTX) (int, error) {
	n, err := storedb.New(db).DeleteExpiredIdemTokens(context.Background())
	if err != nil {
		return 0, fmt.Errorf("CleanupExpiredIdemTokens: %w", err)
	}
	return int(n), nil
}
