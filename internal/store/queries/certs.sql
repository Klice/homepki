-- Queries against the certificates and cert_keys tables. Backs internal/store/certs.go.

-- name: InsertCertificate :exec
INSERT INTO certificates (
    id, type, parent_id, serial_number,
    subject_cn, subject_o, subject_ou, subject_l, subject_st, subject_c,
    san_dns, san_ip, is_ca, path_len_constraint,
    key_algo, key_algo_params, key_usage, ext_key_usage,
    not_before, not_after, der_cert, fingerprint_sha256,
    status, replaces_id
) VALUES (?, ?, ?, ?,  ?, ?, ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?);

-- name: InsertCertKey :exec
INSERT INTO cert_keys (cert_id, kek_tier, wrapped_dek, dek_nonce, cipher_nonce, ciphertext)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetCertificate :one
SELECT id, type, parent_id, serial_number,
       subject_cn, subject_o, subject_ou, subject_l, subject_st, subject_c,
       san_dns, san_ip, is_ca, path_len_constraint,
       key_algo, key_algo_params, key_usage, ext_key_usage,
       not_before, not_after, der_cert, fingerprint_sha256,
       status, revoked_at, revocation_reason, replaces_id, replaced_by_id, created_at
FROM certificates
WHERE id = ?;

-- name: GetCertKeyByID :one
SELECT cert_id, kek_tier, wrapped_dek, dek_nonce, cipher_nonce, ciphertext
FROM cert_keys
WHERE cert_id = ?;

-- name: ListCAs :many
SELECT id FROM certificates
WHERE type IN ('root_ca', 'intermediate_ca')
ORDER BY created_at DESC, id DESC;

-- name: ListLeaves :many
SELECT id FROM certificates
WHERE type = 'leaf'
ORDER BY created_at DESC, id DESC;

-- name: ListRevokedChildren :many
SELECT serial_number, revoked_at, COALESCE(revocation_reason, 0) AS reason_code
FROM certificates
WHERE parent_id = ?
  AND status = 'revoked'
  AND not_after > datetime('now')
ORDER BY revoked_at;

-- name: MarkCertRevoked :execrows
UPDATE certificates
   SET status = 'revoked', revoked_at = ?, revocation_reason = ?
   WHERE id = ? AND status != 'revoked';

-- name: SupersedeCert :execrows
UPDATE certificates
   SET status = 'superseded', replaced_by_id = ?
   WHERE id = ? AND status = 'active';

-- name: ListCertKeyWraps :many
SELECT cert_id, wrapped_dek, dek_nonce
FROM cert_keys
ORDER BY cert_id;

-- name: UpdateCertKeyWrap :execrows
UPDATE cert_keys
   SET wrapped_dek = ?, dek_nonce = ?
   WHERE cert_id = ?;
