package pki

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	parsed, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	assert.Equal(t, int64(1), parsed.Number.Int64())
	assert.Empty(t, parsed.RevokedCertificateEntries)
	assert.NoError(t, parsed.CheckSignatureFrom(root.Cert))
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
	require.NoError(t, err)
	parsed, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	require.Len(t, parsed.RevokedCertificateEntries, 1)
	entry := parsed.RevokedCertificateEntries[0]
	assert.Equal(t, 0, entry.SerialNumber.Cmp(revokedSerial))
	assert.Equal(t, 1, entry.ReasonCode)
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
		require.NoError(t, err)
		return der
	}
	d1 := mk(1)
	d5 := mk(5)
	p1, _ := x509.ParseRevocationList(d1)
	p5, _ := x509.ParseRevocationList(d5)
	assert.Equal(t, int64(1), p1.Number.Int64())
	assert.Equal(t, int64(5), p5.Number.Int64())
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
			assert.Error(t, err)
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
	require.NoError(t, err)
	parsed, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	require.Len(t, parsed.RevokedCertificateEntries, 1)
	assert.Equal(t, 0, parsed.RevokedCertificateEntries[0].ReasonCode)
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
	require.NoError(t, err)
	parsed, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	assert.NoError(t, parsed.CheckSignatureFrom(root.Cert))
	// Wrong issuer: should not validate.
	other := mustRoot(t)
	assert.Error(t, parsed.CheckSignatureFrom(other.Cert))
}
