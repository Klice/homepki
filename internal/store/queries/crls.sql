-- Queries against the crls table. Backs internal/store/crls.go.

-- name: InsertCRL :exec
INSERT INTO crls (issuer_cert_id, crl_number, this_update, next_update, der, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLatestCRL :one
SELECT issuer_cert_id, crl_number, this_update, next_update, der, updated_at
FROM crls
WHERE issuer_cert_id = ?
ORDER BY crl_number DESC
LIMIT 1;

-- name: NextCRLNumber :one
SELECT MAX(crl_number) FROM crls WHERE issuer_cert_id = ?;

-- name: ListCRLsByIssuer :many
SELECT issuer_cert_id, crl_number, this_update, next_update, der, updated_at
FROM crls
WHERE issuer_cert_id = ?
ORDER BY crl_number DESC;

-- name: GetCRLByNumber :one
SELECT issuer_cert_id, crl_number, this_update, next_update, der, updated_at
FROM crls
WHERE issuer_cert_id = ? AND crl_number = ?;
