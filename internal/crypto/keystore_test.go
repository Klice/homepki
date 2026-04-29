package crypto

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeystore_StartsLocked(t *testing.T) {
	k := NewKeystore()
	assert.False(t, k.IsUnlocked(), "new keystore should be locked")
}

func TestKeystore_InstallUnlock(t *testing.T) {
	k := NewKeystore()
	require.NoError(t, k.Install(make([]byte, KeyLen)), "Install")
	assert.True(t, k.IsUnlocked(), "keystore should be unlocked after Install")
}

func TestKeystore_InstallRejectsWrongKeyLen(t *testing.T) {
	k := NewKeystore()
	for _, badLen := range []int{0, 16, 24, 31, 33, 64} {
		err := k.Install(make([]byte, badLen))
		assert.Errorf(t, err, "Install accepted %d-byte kek", badLen)
	}
}

func TestKeystore_LockZeroesUnderlyingSlice(t *testing.T) {
	k := NewKeystore()
	original := make([]byte, KeyLen)
	for i := range original {
		original[i] = 0xAB
	}
	require.NoError(t, k.Install(original))
	// `original` is now owned by the keystore; capture the same pointer for
	// post-Lock inspection.
	captured := original

	k.Lock()
	assert.False(t, k.IsUnlocked(), "IsUnlocked should be false after Lock")
	for i, b := range captured {
		assert.Equalf(t, byte(0), b, "Lock did not zero byte %d (got 0x%02X)", i, b)
	}
}

func TestKeystore_LockIsIdempotent(t *testing.T) {
	k := NewKeystore()
	k.Lock() // already locked; should not panic
	k.Lock()
	assert.False(t, k.IsUnlocked(), "still unlocked after double Lock")
}

func TestKeystore_InstallReplacesAndZeroesPrevious(t *testing.T) {
	k := NewKeystore()
	first := bytes.Repeat([]byte{0x11}, KeyLen)
	require.NoError(t, k.Install(first))
	captured := first

	second := bytes.Repeat([]byte{0x22}, KeyLen)
	require.NoError(t, k.Install(second))
	for i, b := range captured {
		assert.Equalf(t, byte(0), b, "previous kek byte %d not zeroed (got 0x%02X)", i, b)
	}
	err := k.With(func(kek []byte) error {
		assert.Equal(t, second, kek, "With saw stale kek")
		return nil
	})
	require.NoError(t, err, "With")
}

func TestKeystore_WithReturnsErrLockedWhenLocked(t *testing.T) {
	k := NewKeystore()
	called := false
	err := k.With(func(kek []byte) error {
		called = true
		return nil
	})
	assert.ErrorIs(t, err, ErrLocked)
	assert.False(t, called, "fn must not be invoked when keystore is locked")
}

func TestKeystore_WithPropagatesFnError(t *testing.T) {
	k := NewKeystore()
	require.NoError(t, k.Install(make([]byte, KeyLen)))
	want := errors.New("boom")
	got := k.With(func(kek []byte) error { return want })
	assert.ErrorIs(t, got, want)
}

func TestKeystore_ConcurrentAccess(t *testing.T) {
	k := NewKeystore()
	require.NoError(t, k.Install(make([]byte, KeyLen)))

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_ = k.With(func(kek []byte) error {
				assert.Equal(t, KeyLen, len(kek))
				return nil
			})
		})
	}
	for range 5 {
		wg.Go(func() {
			_ = k.IsUnlocked()
		})
	}
	wg.Wait()
}

func TestVerifier_DeterministicAndDistinct(t *testing.T) {
	a := bytes.Repeat([]byte{0xAA}, KeyLen)
	b := bytes.Repeat([]byte{0xBB}, KeyLen)

	va1 := Verifier(a)
	va2 := Verifier(a)
	vb := Verifier(b)

	assert.Equal(t, va1, va2, "Verifier is not deterministic")
	assert.False(t, bytes.Equal(va1, vb), "Verifier collides for distinct keys")
	assert.Equal(t, 32, len(va1), "verifier length should be 32 (HMAC-SHA256)")
}

func TestVerifierEqual(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 32)
	b := bytes.Repeat([]byte{0x01}, 32)
	c := bytes.Repeat([]byte{0x02}, 32)

	assert.True(t, VerifierEqual(a, b), "identical bytes should compare equal")
	assert.False(t, VerifierEqual(a, c), "differing bytes should not compare equal")
}

func TestDeriveSessionSecret_DeterministicPerKEK(t *testing.T) {
	k := NewKeystore()
	kek := bytes.Repeat([]byte{0x42}, KeyLen)
	require.NoError(t, k.Install(append([]byte(nil), kek...)))

	a, err := k.DeriveSessionSecret()
	require.NoError(t, err)
	b, err := k.DeriveSessionSecret()
	require.NoError(t, err)
	assert.Equal(t, a, b, "DeriveSessionSecret is not deterministic for the same KEK")
	assert.Equal(t, SessionSecretLen, len(a))
	// The session secret must not equal the KEK itself.
	assert.False(t, bytes.Equal(a, kek), "session secret equals the KEK — HKDF derivation is broken")
}

func TestDeriveSessionSecret_DifferentKEKDifferentSecret(t *testing.T) {
	k := NewKeystore()

	require.NoError(t, k.Install(bytes.Repeat([]byte{0xAA}, KeyLen)))
	a, err := k.DeriveSessionSecret()
	require.NoError(t, err)

	require.NoError(t, k.Install(bytes.Repeat([]byte{0xBB}, KeyLen)))
	b, err := k.DeriveSessionSecret()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(a, b), "different KEKs produced identical session secrets")
}

func TestDeriveSessionSecret_LockedReturnsErrLocked(t *testing.T) {
	k := NewKeystore()
	_, err := k.DeriveSessionSecret()
	assert.ErrorIs(t, err, ErrLocked)
}

func TestZero(t *testing.T) {
	b := bytes.Repeat([]byte{0xAA}, 16)
	Zero(b)
	for i, v := range b {
		assert.Equalf(t, byte(0), v, "byte %d not zeroed: 0x%02X", i, v)
	}
}

func TestDeriveAndVerify_RoundTrip(t *testing.T) {
	salt := []byte("0123456789abcdef")
	pw := []byte("correct horse battery staple")
	p := fastKDFParams()

	kek, err := DeriveKEK(pw, salt, p)
	require.NoError(t, err)
	verifier := Verifier(kek)
	Zero(kek)

	got, err := DeriveAndVerify(pw, salt, p, verifier)
	require.NoError(t, err, "DeriveAndVerify")
	assert.Equal(t, int(p.KeyLen), len(got))
}

func TestDeriveAndVerify_WrongPassphrase(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := fastKDFParams()

	kek, err := DeriveKEK([]byte("right"), salt, p)
	require.NoError(t, err)
	verifier := Verifier(kek)

	_, err = DeriveAndVerify([]byte("wrong"), salt, p, verifier)
	assert.ErrorIs(t, err, ErrPassphraseMismatch)
}

func TestDeriveAndVerify_PropagatesDeriveErrors(t *testing.T) {
	// Empty passphrase fails inside DeriveKEK before any verifier check.
	_, err := DeriveAndVerify(nil, []byte("salt"), fastKDFParams(), []byte("verifier"))
	assert.Error(t, err, "expected error from empty passphrase")
	assert.NotErrorIs(t, err, ErrPassphraseMismatch, "derive error should not be reported as ErrPassphraseMismatch")
}
