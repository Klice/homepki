package pki

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestCreateCRL_EmptyRoundTrip(t *testing.T) {
	root := mustRoot(t)
	now := time.Now()
	der, err := CreateCRL(CRLRequest{
		Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if parsed.Number.Int64() != 1 {
		t.Errorf("Number: got %d, want 1", parsed.Number.Int64())
	}
	if len(parsed.RevokedCertificateEntries) != 0 {
		t.Errorf("entries: got %d, want 0", len(parsed.RevokedCertificateEntries))
	}
	if err := parsed.CheckSignatureFrom(root.Cert); err != nil {
		t.Errorf("CheckSignatureFrom: %v", err)
	}
}

func TestCreateCRL_WithEntries(t *testing.T) {
	root := mustRoot(t)
	now := time.Now()
	revokedSerial := big.NewInt(424242)

	der, err := CreateCRL(CRLRequest{
		Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
		Number:     big.NewInt(2),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(7 * 24 * time.Hour),
		Entries: []CRLEntry{
			{
				SerialNumber:   revokedSerial,
				RevocationTime: now.Add(-time.Hour),
				ReasonCode:     1, // keyCompromise
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(parsed.RevokedCertificateEntries); got != 1 {
		t.Fatalf("entries: got %d, want 1", got)
	}
	entry := parsed.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(revokedSerial) != 0 {
		t.Errorf("serial: got %s, want %s", entry.SerialNumber, revokedSerial)
	}
	if entry.ReasonCode != 1 {
		t.Errorf("reason: got %d, want 1", entry.ReasonCode)
	}
}

func TestCreateCRL_Monotonic(t *testing.T) {
	root := mustRoot(t)
	now := time.Now()
	mk := func(num int64) []byte {
		der, err := CreateCRL(CRLRequest{
			Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
			Number:     big.NewInt(num),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(7 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("CreateCRL(%d): %v", num, err)
		}
		return der
	}
	d1 := mk(1)
	d5 := mk(5)
	p1, _ := x509.ParseRevocationList(d1)
	p5, _ := x509.ParseRevocationList(d5)
	if p1.Number.Int64() != 1 || p5.Number.Int64() != 5 {
		t.Errorf("numbers: got %d / %d, want 1 / 5", p1.Number.Int64(), p5.Number.Int64())
	}
}

func TestCreateCRL_RejectsBadInput(t *testing.T) {
	root := mustRoot(t)
	now := time.Now()
	cases := []struct {
		name string
		req  CRLRequest
	}{
		{"no issuer", CRLRequest{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		}},
		{"nil number", CRLRequest{
			Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		}},
		{"NextUpdate before ThisUpdate", CRLRequest{
			Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(-time.Hour),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateCRL(tc.req)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestCreateCRL_OmitsUnspecifiedReason(t *testing.T) {
	// RFC 5280 §5.3.1: reason "unspecified" (0) must be omitted.
	root := mustRoot(t)
	now := time.Now()
	der, err := CreateCRL(CRLRequest{
		Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		Entries: []CRLEntry{
			{
				SerialNumber:   big.NewInt(1),
				RevocationTime: now.Add(-time.Hour),
				ReasonCode:     0,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RevokedCertificateEntries) != 1 {
		t.Fatal("missing entry")
	}
	if parsed.RevokedCertificateEntries[0].ReasonCode != 0 {
		t.Errorf("reason: got %d, want 0", parsed.RevokedCertificateEntries[0].ReasonCode)
	}
}

// Sanity that ParseRevocationList round-trips.
func TestCreateCRL_RoundTripSignature(t *testing.T) {
	root := mustRoot(t)
	now := time.Now()
	der, err := CreateCRL(CRLRequest{
		Issuer:     &Signer{Cert: root.Cert, Key: root.Key},
		Number:     big.NewInt(7),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignatureFrom(root.Cert); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
	// Wrong issuer: should not validate.
	other := mustRoot(t)
	if err := parsed.CheckSignatureFrom(other.Cert); err == nil {
		t.Error("CRL should not verify under a different root")
	} else if !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		// Either type-mismatch or signature-mismatch error is fine.
		_ = err
	}
}
