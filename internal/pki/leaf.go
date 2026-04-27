package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// IssueLeaf creates a leaf certificate signed by req.Parent. EKU is
// serverAuth per LIFECYCLE.md / SPEC.md feature set. At least one of
// SANDNS / SANIPs is required.
func IssueLeaf(req LeafRequest) (*Issued, error) {
	if req.Parent == nil {
		return nil, errors.New("leaf: parent signer required")
	}
	if err := validateSubject(req.Subject); err != nil {
		return nil, err
	}
	if len(req.SANDNS) == 0 && len(req.SANIPs) == 0 {
		return nil, errors.New("leaf: at least one of SANDNS or SANIPs required")
	}
	if req.Validity <= 0 {
		return nil, errors.New("leaf: validity must be positive")
	}
	key, err := GenerateKey(req.Key)
	if err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, fmt.Errorf("leaf: serial: %w", err)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkixName(req.Subject),
		NotBefore:             now.Add(-60 * time.Second),
		NotAfter:              now.Add(req.Validity),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              req.SANDNS,
		IPAddresses:           req.SANIPs,
	}
	if req.CRLBaseURL != "" && req.ParentID != "" {
		tmpl.CRLDistributionPoints = []string{crlURL(req.CRLBaseURL, req.ParentID)}
	}
	return signAndParse(tmpl, req.Parent.Cert, key.Public(), req.Parent.Key, key)
}
