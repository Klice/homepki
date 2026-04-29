package store

import (
	"errors"
	"testing"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedCertWithRealKey inserts a cert + a real two-tier sealed private-key
// blob under kek. Returns the certID. Lets the rotation test verify that
// after rewrap the key still decrypts under the new KEK and the original
// PKCS#8 plaintext is recoverable.
func seedCertWithRealKey(t *testing.T, db sqlcDBTX, id string, kek []byte) {
	t.Helper()
	plaintext := []byte("PRETEND-PKCS8-" + id)
	sealed, err := crypto.SealPrivateKey(kek, id, plaintext)
	require.NoError(t, err, "SealPrivateKey")
	c := sampleCert(id)
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	c.SubjectCN = "rot-" + id
	k := &CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}
	require.NoError(t, insertCertTx(db, c, k), "insertCertTx")
}

func TestRotate_HappyPath_RewrapsAllAndUpdatesSettings(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	// Seed the install with a verifier so the rotation has something to
	// "replace" — though RotatePassphrase doesn't read the old verifier
	// itself, we want the test to look like a real install.
	oldKEK := make([]byte, crypto.KeyLen)
	for i := range oldKEK {
		oldKEK[i] = 0xAA
	}
	require.NoError(t, SetSetting(db, SettingPassphraseVerifier, crypto.Verifier(oldKEK)))

	// Seed three certs so the rewrap loop has work to do.
	seedCertWithRealKey(t, db, "a", oldKEK)
	seedCertWithRealKey(t, db, "b", oldKEK)
	seedCertWithRealKey(t, db, "c", oldKEK)

	// Stash the original ciphertext blobs so we can confirm they're
	// untouched (only the wrap layer rotates).
	origCT := map[string][]byte{}
	for _, id := range []string{"a", "b", "c"} {
		k, err := GetCertKey(db, id)
		require.NoError(t, err)
		origCT[id] = append([]byte(nil), k.Ciphertext...)
	}

	newKEK := make([]byte, crypto.KeyLen)
	for i := range newKEK {
		newKEK[i] = 0xBB
	}
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)
	in := RotatePassphraseInputs{
		NewSalt:       []byte("0123456789abcdef"),
		NewParamsJSON: []byte(`{"time":3,"memory":65536,"threads":2,"key_len":32}`),
		NewVerifier:   crypto.Verifier(newKEK),
	}
	require.NoError(t, RotatePassphrase(db, in, RewrapWithKEKs(oldKEK, newKEK), tok, "/settings"),
		"RotatePassphrase")

	// 1. settings now reflect the new salt / params / verifier.
	v, _ := GetSetting(db, SettingKDFSalt)
	assert.Equal(t, "0123456789abcdef", string(v), "kdf_salt")
	v, _ = GetSetting(db, SettingPassphraseVerifier)
	assert.True(t, crypto.VerifierEqual(v, crypto.Verifier(newKEK)),
		"verifier didn't match new KEK's verifier")

	// 2. Each rewrapped key opens under the NEW KEK and gives back the
	//    original PKCS#8 plaintext, and the ciphertext column is bit-for-bit
	//    unchanged (only the wrap layer rotated).
	for _, id := range []string{"a", "b", "c"} {
		k, err := GetCertKey(db, id)
		require.NoError(t, err)
		sealed := &crypto.SealedPrivateKey{
			WrappedDEK:  k.WrappedDEK,
			DEKNonce:    k.DEKNonce,
			CipherNonce: k.CipherNonce,
			Ciphertext:  k.Ciphertext,
		}
		got, err := crypto.OpenPrivateKey(newKEK, id, sealed)
		if !assert.NoError(t, err, "Open under new KEK for %s", id) {
			continue
		}
		want := "PRETEND-PKCS8-" + id
		assert.Equal(t, want, string(got), "plaintext for %s", id)
		assert.Equal(t, origCT[id], k.Ciphertext, "ciphertext for %s changed (should be untouched)", id)
		// And the OLD KEK no longer opens it.
		_, err = crypto.OpenPrivateKey(oldKEK, id, sealed)
		assert.Error(t, err, "old KEK should NOT open rewrapped key for %s", id)
	}

	// 3. The form token is now used and points at /settings.
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.NotNil(t, row.UsedAt, "token should have been marked used")
	require.NotNil(t, row.ResultURL)
	assert.Equal(t, "/settings", *row.ResultURL)
}

func TestRotate_RewrapErrorRollsBackEverything(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	oldKEK := make([]byte, crypto.KeyLen)
	for i := range oldKEK {
		oldKEK[i] = 1
	}
	seedCertWithRealKey(t, db, "a", oldKEK)
	seedCertWithRealKey(t, db, "b", oldKEK)

	origAW, _ := GetCertKey(db, "a")
	origBW, _ := GetCertKey(db, "b")

	tok, _ := CreateIdemToken(db)
	rewrapErr := errors.New("simulated wrap failure")
	rewrap := func(certID string, _, _ []byte) ([]byte, []byte, error) {
		if certID == "b" {
			return nil, nil, rewrapErr
		}
		// 'a' rewraps successfully — we want to confirm its update is
		// rolled back when 'b' fails.
		return []byte("dummy-wrapped"), []byte("dummy-nonce"), nil
	}
	in := RotatePassphraseInputs{
		NewSalt:       []byte("ffffffffffffffff"),
		NewParamsJSON: []byte(`{}`),
		NewVerifier:   []byte("verifier"),
	}
	require.Error(t, RotatePassphrase(db, in, rewrap, tok, "/settings"))

	// 'a' wrap should be unchanged.
	a, _ := GetCertKey(db, "a")
	assert.Equal(t, origAW.WrappedDEK, a.WrappedDEK, "'a' wrap was modified despite rollback")
	assert.Equal(t, origAW.DEKNonce, a.DEKNonce, "'a' nonce was modified despite rollback")
	// 'b' wrap should be unchanged.
	b, _ := GetCertKey(db, "b")
	assert.Equal(t, origBW.WrappedDEK, b.WrappedDEK, "'b' wrap was modified despite rollback")

	// Settings rows should NOT have been written.
	if v, err := GetSetting(db, SettingKDFSalt); err == nil {
		assert.NotEqual(t, "ffffffffffffffff", string(v), "kdf_salt was written despite rollback")
	}

	// Form token should NOT be marked used.
	row, _ := LookupIdemToken(db, tok)
	assert.Nil(t, row.UsedAt, "token was marked used despite rollback")
}

func TestRotate_RejectsMissingInputs(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	tok, _ := CreateIdemToken(db)
	cases := []struct {
		name string
		in   RotatePassphraseInputs
		tok  string
	}{
		{"empty token", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: []byte("{}"), NewVerifier: []byte("v")}, ""},
		{"empty salt", RotatePassphraseInputs{NewSalt: nil, NewParamsJSON: []byte("{}"), NewVerifier: []byte("v")}, tok},
		{"empty params", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: nil, NewVerifier: []byte("v")}, tok},
		{"empty verifier", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: []byte("{}"), NewVerifier: nil}, tok},
	}
	for _, tc := range cases {
		err := RotatePassphrase(db, tc.in, RewrapWithKEKs(nil, nil), tc.tok, "/settings")
		assert.Error(t, err, tc.name)
	}
}

func TestRotate_NoCertsIsValid(t *testing.T) {
	// A fresh install with no issued certs should rotate cleanly — the
	// rewrap loop is a no-op and the settings still update.
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	oldKEK := make([]byte, crypto.KeyLen)
	newKEK := make([]byte, crypto.KeyLen)
	for i := range newKEK {
		newKEK[i] = 9
	}
	tok, _ := CreateIdemToken(db)
	in := RotatePassphraseInputs{
		NewSalt:       []byte("aaaaaaaaaaaaaaaa"),
		NewParamsJSON: []byte(`{"time":3,"memory":1024,"threads":1,"key_len":32}`),
		NewVerifier:   crypto.Verifier(newKEK),
	}
	require.NoError(t, RotatePassphrase(db, in, RewrapWithKEKs(oldKEK, newKEK), tok, "/settings"),
		"RotatePassphrase")
	v, _ := GetSetting(db, SettingKDFSalt)
	assert.Equal(t, "aaaaaaaaaaaaaaaa", string(v), "kdf_salt")
}
