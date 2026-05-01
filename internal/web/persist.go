package web

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"time"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

// crlNextUpdateWindow is how far ahead a freshly-generated CRL claims to be
// valid. LIFECYCLE.md §6.4: "now + 7d".
const crlNextUpdateWindow = 7 * 24 * time.Hour

// crlClockSkewMargin is how far the CRL's ThisUpdate is shifted into the
// past to absorb clock skew across the issuer and CRL consumers.
const crlClockSkewMargin = 60 * time.Second

// persistIssued bridges a freshly-issued cert from the pki package into the
// store, encrypting the private key under the keystore's KEK and atomically
// marking the form token as used. Returns the new cert's id.
//
// On any failure before commit (key marshal, encryption, insert, FK
// violation) the form token is NOT marked used, so the operator can retry
// the form. After success, replays of the same token return the same id.
func (s *Server) persistIssued(certType string, parentID *string, issued *pki.Issued, keySpec pki.KeySpec, formToken string) (string, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(issued.Key)
	if err != nil {
		return "", fmt.Errorf("persistIssued: marshal pkcs8: %w", err)
	}
	defer crypto.Zero(pkcs8)

	id := store.NewCertID()

	var sealed *crypto.SealedPrivateKey
	if err := s.keystore.With(func(kek []byte) error {
		var serr error
		sealed, serr = crypto.SealPrivateKey(kek, id, pkcs8)
		return serr
	}); err != nil {
		return "", fmt.Errorf("persistIssued: seal: %w", err)
	}

	cert := certFromIssued(id, certType, parentID, issued, keySpec)
	key := &store.CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}

	// CAs get an empty initial CRL (number=1) per LIFECYCLE.md §6.2 so
	// clients fetching /crl/{id}.crl right after issuance get a valid
	// CRL rather than a 404. The CRL is signed by the new CA's own key.
	var initialCRL *store.CRL
	if cert.IsCA {
		initialCRL, err = buildInitialCRL(id, issued)
		if err != nil {
			return "", fmt.Errorf("persistIssued: initial CRL: %w", err)
		}
	}

	resultURL := "/certs/" + id
	if err := store.IssueCertWithToken(s.db, cert, key, initialCRL, formToken, resultURL); err != nil {
		return "", err
	}
	s.snapshotCRLBaseURLOnFirstIssuance()
	return id, nil
}

func (s *Server) snapshotCRLBaseURLOnFirstIssuance() {
	if _, err := store.SetSettingIfMissing(s.db, store.SettingCRLBaseURL, []byte(s.cfg.CRLBaseURL)); err != nil {
		slog.Warn("snapshot CRL_BASE_URL: insert", "err", err)
	}
}

// buildInitialCRL produces the empty CRL written alongside a freshly-issued
// CA. Self-signed by the CA's own key (which is in issued.Key — we have it
// in plaintext because it was generated this request).
func buildInitialCRL(certID string, issued *pki.Issued) (*store.CRL, error) {
	now := time.Now()
	thisUpdate := now.Add(-crlClockSkewMargin)
	nextUpdate := now.Add(crlNextUpdateWindow)
	der, err := pki.CreateCRL(pki.CRLRequest{
		Issuer:     &pki.Signer{Cert: issued.Cert, Key: issued.Key},
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		// Empty entries — fresh CA has nothing revoked yet.
	})
	if err != nil {
		return nil, err
	}
	return &store.CRL{
		IssuerCertID: certID,
		CRLNumber:    1,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		DER:          der,
	}, nil
}

// persistRotation is the rotate-flow analogue of persistIssued. It seals
// the new key, builds the cert struct (with ReplacesID = oldID), produces
// an initial CRL when the new cert is itself a CA, and atomically:
//   - inserts the new cert + key (+ CRL)
//   - flips the old cert to superseded with replaced_by_id = new id
//   - marks the form token used
//
// Returns the new cert id. Per LIFECYCLE.md §4.2/§4.3.
func (s *Server) persistRotation(certType string, parentID *string, oldID string, issued *pki.Issued, keySpec pki.KeySpec, formToken string) (string, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(issued.Key)
	if err != nil {
		return "", fmt.Errorf("persistRotation: marshal pkcs8: %w", err)
	}
	defer crypto.Zero(pkcs8)

	id := store.NewCertID()

	var sealed *crypto.SealedPrivateKey
	if err := s.keystore.With(func(kek []byte) error {
		var serr error
		sealed, serr = crypto.SealPrivateKey(kek, id, pkcs8)
		return serr
	}); err != nil {
		return "", fmt.Errorf("persistRotation: seal: %w", err)
	}

	cert := certFromIssued(id, certType, parentID, issued, keySpec)
	cert.ReplacesID = &oldID
	key := &store.CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}

	var initialCRL *store.CRL
	if cert.IsCA {
		initialCRL, err = buildInitialCRL(id, issued)
		if err != nil {
			return "", fmt.Errorf("persistRotation: initial CRL: %w", err)
		}
	}

	resultURL := "/certs/" + id
	if err := store.IssueRotationWithToken(s.db, cert, key, initialCRL, oldID, formToken, resultURL); err != nil {
		return "", err
	}
	s.snapshotCRLBaseURLOnFirstIssuance()
	return id, nil
}

// loadSigner fetches a CA's parsed cert and decrypted private key, returning
// a pki.Signer suitable for signing children. The plaintext private key is
// zeroed before this function returns; the live signer holds a parsed key
// (decrypted form) — callers must not retain it longer than the request.
func (s *Server) loadSigner(parentID string) (*pki.Signer, *store.Cert, error) {
	parentCert, err := store.GetCert(s.db, parentID)
	if errors.Is(err, store.ErrCertNotFound) {
		return nil, nil, fmt.Errorf("parent not found")
	}
	if err != nil {
		return nil, nil, err
	}
	parentKey, err := store.GetCertKey(s.db, parentID)
	if err != nil {
		return nil, nil, fmt.Errorf("parent key missing: %w", err)
	}
	parsedCert, err := x509.ParseCertificate(parentCert.DERCert)
	if err != nil {
		return nil, nil, fmt.Errorf("parse parent cert: %w", err)
	}

	var signerKey stdcrypto.Signer
	if err := s.keystore.With(func(kek []byte) error {
		sealed := &crypto.SealedPrivateKey{
			WrappedDEK:  parentKey.WrappedDEK,
			DEKNonce:    parentKey.DEKNonce,
			CipherNonce: parentKey.CipherNonce,
			Ciphertext:  parentKey.Ciphertext,
		}
		pkcs8, derr := crypto.OpenPrivateKey(kek, parentID, sealed)
		if derr != nil {
			return fmt.Errorf("decrypt parent key: %w", derr)
		}
		defer crypto.Zero(pkcs8)
		priv, derr := x509.ParsePKCS8PrivateKey(pkcs8)
		if derr != nil {
			return fmt.Errorf("parse parent pkcs8: %w", derr)
		}
		s, ok := priv.(stdcrypto.Signer)
		if !ok {
			return fmt.Errorf("parent key %T does not implement crypto.Signer", priv)
		}
		signerKey = s
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return &pki.Signer{Cert: parsedCert, Key: signerKey}, parentCert, nil
}

// persistImportedRoot is the import-flow analogue of the CA branch of
// persistIssued: takes a pre-existing self-signed root cert (DER + parsed)
// and its private key, seals the key under the in-memory KEK, and inserts
// the cert + key + initial CRL atomically with the form token marked
// used. Returns the cert's id.
//
// Idempotent on the cert's SHA-256 fingerprint: re-uploading the same
// cert resolves to the same id without inserting a duplicate. The form
// token is still marked used pointing at the existing cert's URL so the
// stale-form path doesn't fire on a refresh-and-resubmit.
//
// keyAlgo / keyAlgoParams describe the cert's public key (the operator
// brings the keypair, we don't generate one). KeySpec is recreated here
// for storage parity with persistIssued.
func (s *Server) persistImportedRoot(certDER []byte, cert *x509.Certificate, key stdcrypto.Signer, keyAlgo, keyAlgoParams, formToken string) (string, error) {
	fp := sha256.Sum256(certDER)
	fpHex := hex.EncodeToString(fp[:])

	// Idempotency: same cert already in the DB → reuse the id, mark
	// the token used pointing at it, return.
	if existing, err := store.GetCertByFingerprint(s.db, fpHex); err == nil {
		resultURL := "/certs/" + existing.ID
		// Best-effort token-mark — already-used tokens are fine, the
		// caller will redirect to resultURL either way.
		_ = store.MarkIdemTokenUsed(s.db, formToken, resultURL)
		return existing.ID, nil
	} else if !errors.Is(err, store.ErrCertNotFound) {
		return "", fmt.Errorf("persistImportedRoot: lookup by fingerprint: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("persistImportedRoot: marshal pkcs8: %w", err)
	}
	defer crypto.Zero(pkcs8)

	id := store.NewCertID()

	var sealed *crypto.SealedPrivateKey
	if err := s.keystore.With(func(kek []byte) error {
		var serr error
		sealed, serr = crypto.SealPrivateKey(kek, id, pkcs8)
		return serr
	}); err != nil {
		return "", fmt.Errorf("persistImportedRoot: seal: %w", err)
	}

	storeCert := certFromImportedRoot(id, fpHex, certDER, cert, keyAlgo, keyAlgoParams)
	storeKey := &store.CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}

	// Initial CRL signed by the imported key — but only when the cert
	// declares cRLSign in its KeyUsage. RFC 5280 §4.2.1.3 requires it
	// for any CRL signer, and x509.CreateRevocationList enforces the
	// rule. Roots minted without cRLSign (common for older or
	// constrained PKIs) are still imported — their /crl/{id}.crl just
	// 404s, and revocation has to be managed out-of-band, the same way
	// root revocation already is per LIFECYCLE.md §5.4.
	var initialCRL *store.CRL
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		initialCRL, err = buildInitialCRLFromKey(id, cert, key)
		if err != nil {
			return "", fmt.Errorf("persistImportedRoot: initial CRL: %w", err)
		}
	}

	resultURL := "/certs/" + id
	if err := store.IssueCertWithToken(s.db, storeCert, storeKey, initialCRL, formToken, resultURL); err != nil {
		return "", err
	}
	s.snapshotCRLBaseURLOnFirstIssuance()
	return id, nil
}

// buildInitialCRLFromKey is buildInitialCRL but takes the parsed cert +
// signer directly, since import doesn't have a pki.Issued struct.
func buildInitialCRLFromKey(certID string, cert *x509.Certificate, key stdcrypto.Signer) (*store.CRL, error) {
	now := time.Now()
	thisUpdate := now.Add(-crlClockSkewMargin)
	nextUpdate := now.Add(crlNextUpdateWindow)
	der, err := pki.CreateCRL(pki.CRLRequest{
		Issuer:     &pki.Signer{Cert: cert, Key: key},
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	})
	if err != nil {
		return nil, err
	}
	return &store.CRL{
		IssuerCertID: certID,
		CRLNumber:    1,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		DER:          der,
	}, nil
}

// certFromImportedRoot maps a parsed self-signed cert into a store.Cert
// ready for insertion. Mirrors certFromIssued but works from primitives
// (no pki.Issued / pki.KeySpec wrapper) and stamps Source = "imported".
func certFromImportedRoot(id, fpHex string, certDER []byte, c *x509.Certificate, keyAlgo, keyAlgoParams string) *store.Cert {
	sanDNS := slices.Clone(c.DNSNames)
	sanIPs := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		sanIPs = append(sanIPs, ip.String())
	}

	var pathLen *int
	if c.MaxPathLenZero {
		v := 0
		pathLen = &v
	} else if c.MaxPathLen > 0 {
		v := c.MaxPathLen
		pathLen = &v
	}

	return &store.Cert{
		ID:                id,
		Type:              "root_ca",
		ParentID:          nil, // self-signed — no parent
		SerialNumber:      c.SerialNumber.Text(16),
		SubjectCN:         c.Subject.CommonName,
		SubjectO:          firstOrEmpty(c.Subject.Organization),
		SubjectOU:         firstOrEmpty(c.Subject.OrganizationalUnit),
		SubjectL:          firstOrEmpty(c.Subject.Locality),
		SubjectST:         firstOrEmpty(c.Subject.Province),
		SubjectC:          firstOrEmpty(c.Subject.Country),
		SANDNS:            sanDNS,
		SANIPs:            sanIPs,
		IsCA:              c.IsCA,
		PathLen:           pathLen,
		KeyAlgo:           keyAlgo,
		KeyAlgoParams:     keyAlgoParams,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		DERCert:           certDER,
		FingerprintSHA256: fpHex,
		Status:            "active",
		Source:            "imported",
	}
}

// certFromIssued maps the parsed pki.Issued struct (and the input keySpec)
// into a store.Cert ready for insertion.
func certFromIssued(id, certType string, parentID *string, issued *pki.Issued, keySpec pki.KeySpec) *store.Cert {
	c := issued.Cert
	fp := sha256.Sum256(issued.DER)

	sanDNS := slices.Clone(c.DNSNames)
	sanIPs := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		sanIPs = append(sanIPs, ip.String())
	}

	var pathLen *int
	if c.MaxPathLenZero {
		v := 0
		pathLen = &v
	} else if c.MaxPathLen > 0 {
		v := c.MaxPathLen
		pathLen = &v
	}

	return &store.Cert{
		ID:                id,
		Type:              certType,
		ParentID:          parentID,
		SerialNumber:      c.SerialNumber.Text(16),
		SubjectCN:         c.Subject.CommonName,
		SubjectO:          firstOrEmpty(c.Subject.Organization),
		SubjectOU:         firstOrEmpty(c.Subject.OrganizationalUnit),
		SubjectL:          firstOrEmpty(c.Subject.Locality),
		SubjectST:         firstOrEmpty(c.Subject.Province),
		SubjectC:          firstOrEmpty(c.Subject.Country),
		SANDNS:            sanDNS,
		SANIPs:            sanIPs,
		IsCA:              c.IsCA,
		PathLen:           pathLen,
		KeyAlgo:           string(keySpec.Algo),
		KeyAlgoParams:     keySpec.Params,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		DERCert:           issued.DER,
		FingerprintSHA256: hex.EncodeToString(fp[:]),
		Status:            "active",
	}
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
