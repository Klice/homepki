package web

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

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

	resultURL := "/certs/" + id
	if err := store.IssueCertWithToken(s.db, cert, key, formToken, resultURL); err != nil {
		return "", err
	}
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

// certFromIssued maps the parsed pki.Issued struct (and the input keySpec)
// into a store.Cert ready for insertion.
func certFromIssued(id, certType string, parentID *string, issued *pki.Issued, keySpec pki.KeySpec) *store.Cert {
	c := issued.Cert
	fp := sha256.Sum256(issued.DER)

	var sanDNS []string
	sanDNS = append(sanDNS, c.DNSNames...)
	var sanIPs []string
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
