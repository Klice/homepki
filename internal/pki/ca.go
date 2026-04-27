package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"
)

// IssueRoot creates a self-signed root CA. The root has no CRL DP — it's
// the trust anchor and is not itself revoked via a CRL it would host.
func IssueRoot(req RootRequest) (*Issued, error) {
	if err := validateSubject(req.Subject); err != nil {
		return nil, err
	}
	key, err := GenerateKey(req.Key)
	if err != nil {
		return nil, err
	}
	tmpl, err := caTemplate(req.Subject, req.Validity, req.Now, nil, "", "", false)
	if err != nil {
		return nil, err
	}
	return signAndParse(tmpl, tmpl, key.Public(), key, key)
}

// IssueIntermediate creates an intermediate CA signed by req.Parent.
// The CRL DP extension on the new cert points at the parent's CRL: the
// parent is the issuer that revokes children, and a client validating
// this intermediate fetches the parent's CRL.
func IssueIntermediate(req IntermediateRequest) (*Issued, error) {
	if req.Parent == nil {
		return nil, errors.New("intermediate: parent signer required")
	}
	if err := validateSubject(req.Subject); err != nil {
		return nil, err
	}
	key, err := GenerateKey(req.Key)
	if err != nil {
		return nil, err
	}
	tmpl, err := caTemplate(req.Subject, req.Validity, req.Now, req.PathLen, req.CRLBaseURL, req.ParentID, true)
	if err != nil {
		return nil, err
	}
	return signAndParse(tmpl, req.Parent.Cert, key.Public(), req.Parent.Key, key)
}

// caTemplate builds the x509 template shared by root and intermediate
// issuance. wantCRLDP toggles the CRL Distribution Point extension —
// true for intermediates (CRL DP -> parent CRL), false for roots.
func caTemplate(subj Subject, validity time.Duration, now time.Time, pathLen *int, crlBase, parentID string, wantCRLDP bool) (*x509.Certificate, error) {
	if validity <= 0 {
		return nil, errors.New("ca: validity must be positive")
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkixName(subj),
		NotBefore:             now.Add(-60 * time.Second),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if pathLen != nil {
		tmpl.MaxPathLen = *pathLen
		tmpl.MaxPathLenZero = (*pathLen == 0)
	}
	if wantCRLDP {
		if crlBase == "" || parentID == "" {
			return nil, errors.New("intermediate: CRLBaseURL and ParentID required to bake CRL DP")
		}
		tmpl.CRLDistributionPoints = []string{crlURL(crlBase, parentID)}
	}
	return tmpl, nil
}

// signAndParse signs template under signerKey, parses the resulting DER,
// and returns Issued bundling the parsed cert, raw DER, and the subject
// key (which the caller generated).
func signAndParse(template, parent *x509.Certificate, pub crypto.PublicKey, signerKey crypto.Signer, subjectKey crypto.Signer) (*Issued, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse cert: %w", err)
	}
	return &Issued{Cert: parsed, DER: der, Key: subjectKey}, nil
}

func pkixName(s Subject) pkix.Name {
	n := pkix.Name{CommonName: s.CN}
	if s.O != "" {
		n.Organization = []string{s.O}
	}
	if s.OU != "" {
		n.OrganizationalUnit = []string{s.OU}
	}
	if s.L != "" {
		n.Locality = []string{s.L}
	}
	if s.ST != "" {
		n.Province = []string{s.ST}
	}
	if s.C != "" {
		n.Country = []string{s.C}
	}
	return n
}

func validateSubject(s Subject) error {
	if s.CN == "" {
		return errors.New("subject CN required")
	}
	return nil
}

func crlURL(base, issuerID string) string {
	return strings.TrimRight(base, "/") + "/crl/" + issuerID + ".crl"
}
