-- Queries against the settings table. Backs internal/store/settings.go.

-- name: GetSetting :one
SELECT value FROM settings WHERE key = ?;

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, updated_at)
VALUES (?, ?, datetime('now'))
ON CONFLICT(key) DO UPDATE
  SET value      = excluded.value,
      updated_at = excluded.updated_at;
