package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freshKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeyLen)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte("homepki/key/v1|cert-id-42")

	nonce, ciphertext, err := Seal(key, plaintext, aad)
	require.NoError(t, err, "Seal")
	assert.Equal(t, NonceLen, len(nonce))
	assert.False(t, bytes.Equal(plaintext, ciphertext), "ciphertext equals plaintext — Seal did nothing")

	got, err := Open(key, nonce, ciphertext, aad)
	require.NoError(t, err, "Open")
	assert.Equal(t, plaintext, got)
}

func TestSeal_NonceIsUnique(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("hello")
	aad := []byte("aad")

	seen := map[string]bool{}
	for i := range 100 {
		nonce, _, err := Seal(key, plaintext, aad)
		require.NoError(t, err)
		k := string(nonce)
		require.Falsef(t, seen[k], "nonce reuse on iteration %d", i)
		seen[k] = true
	}
}

func TestOpen_RejectsTampering(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("secret")
	aad := []byte("aad")

	nonce, ct, err := Seal(key, plaintext, aad)
	require.NoError(t, err)

	t.Run("wrong key", func(t *testing.T) {
		other := freshKey(t)
		_, err := Open(other, nonce, ct, aad)
		assert.Error(t, err, "expected error with wrong key")
	})

	t.Run("wrong aad", func(t *testing.T) {
		_, err := Open(key, nonce, ct, []byte("different"))
		assert.Error(t, err, "expected error with wrong aad")
	})

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := append([]byte(nil), ct...)
		bad[0] ^= 0x01
		_, err := Open(key, nonce, bad, aad)
		assert.Error(t, err, "expected error with tampered ciphertext")
	})

	t.Run("wrong nonce", func(t *testing.T) {
		bad := append([]byte(nil), nonce...)
		bad[0] ^= 0x01
		_, err := Open(key, bad, ct, aad)
		assert.Error(t, err, "expected error with wrong nonce")
	})
}

func TestSeal_ValidatesKeyLen(t *testing.T) {
	for _, badLen := range []int{0, 16, 24, 31, 33, 64} {
		bad := make([]byte, badLen)
		_, _, err := Seal(bad, []byte("x"), nil)
		assert.Errorf(t, err, "Seal accepted %d-byte key", badLen)
	}
}

func TestOpen_ValidatesInputLengths(t *testing.T) {
	key := freshKey(t)
	nonce, ct, err := Seal(key, []byte("x"), nil)
	require.NoError(t, err)

	_, err = Open(make([]byte, 16), nonce, ct, nil)
	assert.Error(t, err, "Open accepted short key")
	_, err = Open(key, make([]byte, 8), ct, nil)
	assert.Error(t, err, "Open accepted short nonce")
}

func TestSeal_EmptyPlaintext(t *testing.T) {
	key := freshKey(t)
	nonce, ct, err := Seal(key, nil, []byte("aad"))
	require.NoError(t, err, "Seal")
	got, err := Open(key, nonce, ct, []byte("aad"))
	require.NoError(t, err, "Open")
	assert.Empty(t, got)
}
