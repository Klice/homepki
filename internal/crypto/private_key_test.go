package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealPrivateKey_RoundTrip(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	plaintext := []byte("PKCS#8 DER goes here")
	certID := "11111111-1111-1111-1111-111111111111"

	sealed, err := SealPrivateKey(kek, certID, plaintext)
	require.NoError(t, err, "Seal")
	assert.Equal(t, NonceLen, len(sealed.DEKNonce), "DEKNonce length")
	assert.Equal(t, NonceLen, len(sealed.CipherNonce), "CipherNonce length")
	assert.False(t, bytes.Equal(sealed.Ciphertext, plaintext), "ciphertext equals plaintext")

	got, err := OpenPrivateKey(kek, certID, sealed)
	require.NoError(t, err, "Open")
	assert.Equal(t, plaintext, got)
}

func TestSealPrivateKey_AADBoundToCertID(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	plaintext := []byte("secret key bytes")

	sealed, err := SealPrivateKey(kek, "cert-A", plaintext)
	require.NoError(t, err)
	// Attempting to open with a different cert ID must fail — that's the
	// whole point of binding the AAD: an attacker who can swap rows in the
	// DB can't trick us into using one cert's key under another cert's id.
	_, err = OpenPrivateKey(kek, "cert-B", sealed)
	assert.Error(t, err, "Open with wrong certID should fail")
}

func TestSealPrivateKey_DifferentKEKDifferentCiphertext(t *testing.T) {
	plaintext := []byte("secret")
	certID := "id"

	kek1 := make([]byte, KeyLen)
	rand.Read(kek1)
	kek2 := make([]byte, KeyLen)
	rand.Read(kek2)

	a, err := SealPrivateKey(kek1, certID, plaintext)
	require.NoError(t, err)
	b, err := SealPrivateKey(kek2, certID, plaintext)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a.WrappedDEK, b.WrappedDEK), "different KEKs produced identical wrapped DEKs")
	// Inner ciphertext also differs because each call generates a fresh DEK.
	assert.False(t, bytes.Equal(a.Ciphertext, b.Ciphertext), "different KEKs produced identical ciphertexts (DEK reuse?)")
}

func TestSealPrivateKey_RejectsBadInputs(t *testing.T) {
	plaintext := []byte("x")
	good := make([]byte, KeyLen)

	cases := []struct {
		name    string
		kek     []byte
		certID  string
		wantSub string
	}{
		{"short kek", make([]byte, 16), "id", "kek must be"},
		{"empty certID", good, "", "certID required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SealPrivateKey(tc.kek, tc.certID, plaintext)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantSub)
		})
	}
}

func TestOpenPrivateKey_RejectsTampering(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	sealed, err := SealPrivateKey(kek, "id", []byte("secret"))
	require.NoError(t, err)

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := *sealed
		bad.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
		bad.Ciphertext[0] ^= 0x01
		_, err := OpenPrivateKey(kek, "id", &bad)
		assert.Error(t, err)
	})
	t.Run("flipped wrapped dek byte", func(t *testing.T) {
		bad := *sealed
		bad.WrappedDEK = append([]byte(nil), sealed.WrappedDEK...)
		bad.WrappedDEK[0] ^= 0x01
		_, err := OpenPrivateKey(kek, "id", &bad)
		assert.Error(t, err)
	})
}
