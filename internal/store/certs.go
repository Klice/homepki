package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Cert mirrors a row in the certificates table. NULLable columns use
// pointers so callers can distinguish "absent" from "zero value".
type Cert struct {
	ID                string
	Type              string
	ParentID          *string
	SerialNumber      string
	SubjectCN         string
	SubjectO          string
	SubjectOU         string
	SubjectL          string
	SubjectST         string
	SubjectC          string
	SANDNS            []string
	SANIPs            []string
	IsCA              bool
	PathLen           *int
	KeyAlgo           string
	KeyAlgoParams     string
	KeyUsage          []string
	ExtKeyUsage       []string
	NotBefore         time.Time
	NotAfter          time.Time
	DERCert           []byte
	FingerprintSHA256 string
	Status            string
	RevokedAt         *time.Time
	RevocationReason  *int
	ReplacesID        *string
	ReplacedByID      *string
	CreatedAt         time.Time
}

// CertKey mirrors a row in the cert_keys table. The blobs are AEAD output;
// produce them via crypto.SealPrivateKey.
type CertKey struct {
	CertID      string
	KEKTier     string
	WrappedDEK  []byte
	DEKNonce    []byte
	CipherNonce []byte
	Ciphertext  []byte
}

// ErrCertNotFound is returned by GetCert / GetCertKey when no row exists.
var ErrCertNotFound = errors.New("cert not found")

// InsertCert writes the cert and its key bundle in one transaction.
// Either both rows are written or neither is.
func InsertCert(db *sql.DB, c *Cert, k *CertKey) error {
	if c == nil || k == nil {
		return errors.New("InsertCert: cert and key required")
	}
	if c.ID == "" || k.CertID == "" {
		return errors.New("InsertCert: cert.ID and key.CertID required")
	}
	if c.ID != k.CertID {
		return fmt.Errorf("InsertCert: cert.ID %q != key.CertID %q", c.ID, k.CertID)
	}

	sanDNSJSON, _ := json.Marshal(strSliceOrEmpty(c.SANDNS))
	sanIPsJSON, _ := json.Marshal(strSliceOrEmpty(c.SANIPs))
	keyUsageJSON, _ := json.Marshal(strSliceOrEmpty(c.KeyUsage))
	extKeyUsageJSON, _ := json.Marshal(strSliceOrEmpty(c.ExtKeyUsage))

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("InsertCert: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
		INSERT INTO certificates (
			id, type, parent_id, serial_number,
			subject_cn, subject_o, subject_ou, subject_l, subject_st, subject_c,
			san_dns, san_ip, is_ca, path_len_constraint,
			key_algo, key_algo_params, key_usage, ext_key_usage,
			not_before, not_after, der_cert, fingerprint_sha256,
			status, replaces_id
		) VALUES (?, ?, ?, ?,  ?, ?, ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?)`,
		c.ID, c.Type, c.ParentID, c.SerialNumber,
		c.SubjectCN, nullString(c.SubjectO), nullString(c.SubjectOU), nullString(c.SubjectL), nullString(c.SubjectST), nullString(c.SubjectC),
		sanDNSJSON, sanIPsJSON, c.IsCA, c.PathLen,
		c.KeyAlgo, nullString(c.KeyAlgoParams), keyUsageJSON, extKeyUsageJSON,
		c.NotBefore.UTC(), c.NotAfter.UTC(), c.DERCert, c.FingerprintSHA256,
		nonEmptyOrDefault(c.Status, "active"), c.ReplacesID,
	); err != nil {
		return fmt.Errorf("InsertCert: insert certificates: %w", err)
	}

	if _, err := tx.Exec(`
		INSERT INTO cert_keys (cert_id, kek_tier, wrapped_dek, dek_nonce, cipher_nonce, ciphertext)
		VALUES (?, ?, ?, ?, ?, ?)`,
		k.CertID, nonEmptyOrDefault(k.KEKTier, "main"),
		k.WrappedDEK, k.DEKNonce, k.CipherNonce, k.Ciphertext,
	); err != nil {
		return fmt.Errorf("InsertCert: insert cert_keys: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("InsertCert: commit: %w", err)
	}
	return nil
}

// GetCert loads a cert row by id. Returns ErrCertNotFound if missing.
func GetCert(db *sql.DB, id string) (*Cert, error) {
	var c Cert
	var sanDNSJSON, sanIPsJSON, keyUsageJSON, extKeyUsageJSON []byte
	var subjectO, subjectOU, subjectL, subjectST, subjectC sql.NullString
	var keyAlgoParams sql.NullString
	var pathLen sql.NullInt64
	var revokedAt sql.NullTime
	var revocationReason sql.NullInt64
	var replacesID, replacedByID sql.NullString
	var parentID sql.NullString

	err := db.QueryRow(`
		SELECT id, type, parent_id, serial_number,
		       subject_cn, subject_o, subject_ou, subject_l, subject_st, subject_c,
		       san_dns, san_ip, is_ca, path_len_constraint,
		       key_algo, key_algo_params, key_usage, ext_key_usage,
		       not_before, not_after, der_cert, fingerprint_sha256,
		       status, revoked_at, revocation_reason, replaces_id, replaced_by_id, created_at
		FROM certificates WHERE id = ?`, id).Scan(
		&c.ID, &c.Type, &parentID, &c.SerialNumber,
		&c.SubjectCN, &subjectO, &subjectOU, &subjectL, &subjectST, &subjectC,
		&sanDNSJSON, &sanIPsJSON, &c.IsCA, &pathLen,
		&c.KeyAlgo, &keyAlgoParams, &keyUsageJSON, &extKeyUsageJSON,
		&c.NotBefore, &c.NotAfter, &c.DERCert, &c.FingerprintSHA256,
		&c.Status, &revokedAt, &revocationReason, &replacesID, &replacedByID, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetCert: %w", err)
	}

	if parentID.Valid {
		v := parentID.String
		c.ParentID = &v
	}
	c.SubjectO = subjectO.String
	c.SubjectOU = subjectOU.String
	c.SubjectL = subjectL.String
	c.SubjectST = subjectST.String
	c.SubjectC = subjectC.String
	c.KeyAlgoParams = keyAlgoParams.String
	if pathLen.Valid {
		v := int(pathLen.Int64)
		c.PathLen = &v
	}
	if revokedAt.Valid {
		v := revokedAt.Time
		c.RevokedAt = &v
	}
	if revocationReason.Valid {
		v := int(revocationReason.Int64)
		c.RevocationReason = &v
	}
	if replacesID.Valid {
		v := replacesID.String
		c.ReplacesID = &v
	}
	if replacedByID.Valid {
		v := replacedByID.String
		c.ReplacedByID = &v
	}

	if err := json.Unmarshal(sanDNSJSON, &c.SANDNS); err != nil {
		return nil, fmt.Errorf("GetCert: unmarshal san_dns: %w", err)
	}
	if err := json.Unmarshal(sanIPsJSON, &c.SANIPs); err != nil {
		return nil, fmt.Errorf("GetCert: unmarshal san_ip: %w", err)
	}
	if err := json.Unmarshal(keyUsageJSON, &c.KeyUsage); err != nil {
		return nil, fmt.Errorf("GetCert: unmarshal key_usage: %w", err)
	}
	if err := json.Unmarshal(extKeyUsageJSON, &c.ExtKeyUsage); err != nil {
		return nil, fmt.Errorf("GetCert: unmarshal ext_key_usage: %w", err)
	}
	return &c, nil
}

// GetCertKey loads the cert_keys row for id. Returns ErrCertNotFound if
// missing — the caller should treat "key gone" the same as "cert gone".
func GetCertKey(db *sql.DB, id string) (*CertKey, error) {
	var k CertKey
	err := db.QueryRow(`
		SELECT cert_id, kek_tier, wrapped_dek, dek_nonce, cipher_nonce, ciphertext
		FROM cert_keys WHERE cert_id = ?`, id).Scan(
		&k.CertID, &k.KEKTier, &k.WrappedDEK, &k.DEKNonce, &k.CipherNonce, &k.Ciphertext,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetCertKey: %w", err)
	}
	return &k, nil
}

// ---- helpers ----

func strSliceOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonEmptyOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
