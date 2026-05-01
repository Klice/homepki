package crypto

import (
	"bytes"
	"encoding/json"
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
	assert.Equal(t, KDFParams{
		Time: 3, Memory: 64 * 1024, Threads: 2, KeyLen: 32,
		Version: Argon2idV13,
	}, p)
}

func TestKDFParams_JSONRoundTripIncludesVersion(t *testing.T) {
	p := DefaultKDFParams()
	b, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"version":19`,
		"persisted JSON must carry the Argon2id version so a future homepki version can refuse rows it can't safely re-derive")

	var got KDFParams
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, p, got)
}

func TestKDFParams_JSONLegacyRowsHaveNoVersion(t *testing.T) {
	// Pre-version-field rows decode to Version=0; DeriveKEK must
	// treat that as Argon2idV13 so existing installs keep working
	// after upgrade.
	legacy := []byte(`{"time":3,"memory":65536,"threads":2,"key_len":32}`)
	var p KDFParams
	require.NoError(t, json.Unmarshal(legacy, &p))
	assert.Equal(t, uint32(0), p.Version)
}

func TestDeriveKEK_AcceptsLegacyVersionZero(t *testing.T) {
	p := fastKDFParams() // Version is unset → 0
	_, err := DeriveKEK([]byte("pw"), []byte("0123456789abcdef"), p)
	require.NoError(t, err, "legacy rows without version field must still derive")
}

func TestDeriveKEK_AcceptsExplicitV13(t *testing.T) {
	p := fastKDFParams()
	p.Version = Argon2idV13
	_, err := DeriveKEK([]byte("pw"), []byte("0123456789abcdef"), p)
	require.NoError(t, err)
}

func TestDeriveKEK_RejectsUnknownVersion(t *testing.T) {
	p := fastKDFParams()
	p.Version = 0x14 // hypothetical future version
	_, err := DeriveKEK([]byte("pw"), []byte("0123456789abcdef"), p)
	require.Error(t, err)
	assert.ErrorContains(t, err, "Argon2id version")
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
