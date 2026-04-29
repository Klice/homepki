package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastKDFParams returns Argon2id params low enough that tests don't grind for
// seconds. Memory is in KiB.
func fastKDFParams() KDFParams {
	return KDFParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32}
}

func TestDefaultKDFParams(t *testing.T) {
	p := DefaultKDFParams()
	assert.Equal(t, KDFParams{Time: 3, Memory: 64 * 1024, Threads: 2, KeyLen: 32}, p)
}

func TestNewSalt(t *testing.T) {
	a, err := NewSalt()
	require.NoError(t, err)
	assert.Equal(t, SaltLen, len(a))
	b, err := NewSalt()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, b), "two consecutive NewSalt() returned identical bytes — RNG is broken")
}

func TestDeriveKEK_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	pw := []byte("correct horse battery staple")
	p := fastKDFParams()

	a, err := DeriveKEK(pw, salt, p)
	require.NoError(t, err)
	b, err := DeriveKEK(pw, salt, p)
	require.NoError(t, err)
	assert.Equal(t, a, b, "DeriveKEK is not deterministic for identical inputs")
	assert.Equal(t, int(p.KeyLen), len(a))
}

func TestDeriveKEK_DifferentSaltDifferentKey(t *testing.T) {
	pw := []byte("correct horse battery staple")
	p := fastKDFParams()

	a, err := DeriveKEK(pw, []byte("0123456789abcdef"), p)
	require.NoError(t, err)
	b, err := DeriveKEK(pw, []byte("fedcba9876543210"), p)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, b), "different salts produced identical KEKs")
}

func TestDeriveKEK_DifferentPassphraseDifferentKey(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := fastKDFParams()

	a, err := DeriveKEK([]byte("first passphrase"), salt, p)
	require.NoError(t, err)
	b, err := DeriveKEK([]byte("second passphrase"), salt, p)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, b), "different passphrases produced identical KEKs")
}

func TestDeriveKEK_RejectsEmptyInputs(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := fastKDFParams()

	cases := []struct {
		name       string
		passphrase []byte
		salt       []byte
		params     KDFParams
		want       string
	}{
		{"empty passphrase", nil, salt, p, "passphrase"},
		{"empty salt", []byte("pw"), nil, p, "salt"},
		{"zero KeyLen", []byte("pw"), salt, KDFParams{Time: 1, Memory: 64, Threads: 1}, "KeyLen"},
		{"zero Time", []byte("pw"), salt, KDFParams{Memory: 64, Threads: 1, KeyLen: 32}, "Time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveKEK(tc.passphrase, tc.salt, tc.params)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.want)
		})
	}
}
