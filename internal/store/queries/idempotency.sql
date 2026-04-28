-- Queries against the idempotency_tokens table. Backs internal/store/idempotency.go.

-- name: InsertIdemToken :exec
INSERT INTO idempotency_tokens (token, created_at, expires_at)
VALUES (?, ?, ?);

-- name: GetIdemToken :one
SELECT token, created_at, used_at, result_url, expires_at
FROM idempotency_tokens
WHERE token = ? AND expires_at > datetime('now');

-- name: MarkIdemTokenUsed :execrows
UPDATE idempotency_tokens
   SET used_at = datetime('now'), result_url = ?
   WHERE token = ? AND used_at IS NULL;

-- name: DeleteExpiredIdemTokens :execrows
DELETE FROM idempotency_tokens WHERE expires_at <= datetime('now');
