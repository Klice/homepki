package crypto

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestNewKeystore_StartsLocked(t *testing.T) {
	k := NewKeystore()
	if k.IsUnlocked() {
		t.Error("new keystore should be locked")
	}
}

func TestKeystore_InstallUnlock(t *testing.T) {
	k := NewKeystore()
	if err := k.Install(make([]byte, KeyLen)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !k.IsUnlocked() {
		t.Error("keystore should be unlocked after Install")
	}
}

func TestKeystore_InstallRejectsWrongKeyLen(t *testing.T) {
	k := NewKeystore()
	for _, badLen := range []int{0, 16, 24, 31, 33, 64} {
		if err := k.Install(make([]byte, badLen)); err == nil {
			t.Errorf("Install accepted %d-byte kek", badLen)
		}
	}
}

func TestKeystore_LockZeroesUnderlyingSlice(t *testing.T) {
	k := NewKeystore()
	original := make([]byte, KeyLen)
	for i := range original {
		original[i] = 0xAB
	}
	if err := k.Install(original); err != nil {
		t.Fatal(err)
	}
	// `original` is now owned by the keystore; capture the same pointer for
	// post-Lock inspection.
	captured := original

	k.Lock()
	if k.IsUnlocked() {
		t.Error("IsUnlocked should be false after Lock")
	}
	for i, b := range captured {
		if b != 0 {
			t.Errorf("Lock did not zero byte %d (got 0x%02X)", i, b)
		}
	}
}

func TestKeystore_LockIsIdempotent(t *testing.T) {
	k := NewKeystore()
	k.Lock() // already locked; should not panic
	k.Lock()
	if k.IsUnlocked() {
		t.Error("still unlocked after double Lock")
	}
}

func TestKeystore_InstallReplacesAndZeroesPrevious(t *testing.T) {
	k := NewKeystore()
	first := bytes.Repeat([]byte{0x11}, KeyLen)
	if err := k.Install(first); err != nil {
		t.Fatal(err)
	}
	captured := first

	second := bytes.Repeat([]byte{0x22}, KeyLen)
	if err := k.Install(second); err != nil {
		t.Fatal(err)
	}
	for i, b := range captured {
		if b != 0 {
			t.Errorf("previous kek byte %d not zeroed (got 0x%02X)", i, b)
		}
	}
	if err := k.With(func(kek []byte) error {
		if !bytes.Equal(kek, second) {
			t.Errorf("With saw stale kek: %x", kek)
		}
		return nil
	}); err != nil {
		t.Fatalf("With: %v", err)
	}
}

func TestKeystore_WithReturnsErrLockedWhenLocked(t *testing.T) {
	k := NewKeystore()
	called := false
	err := k.With(func(kek []byte) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrLocked) {
		t.Errorf("got %v, want ErrLocked", err)
	}
	if called {
		t.Error("fn must not be invoked when keystore is locked")
	}
}

func TestKeystore_WithPropagatesFnError(t *testing.T) {
	k := NewKeystore()
	if err := k.Install(make([]byte, KeyLen)); err != nil {
		t.Fatal(err)
	}
	want := errors.New("boom")
	got := k.With(func(kek []byte) error { return want })
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestKeystore_ConcurrentAccess(t *testing.T) {
	k := NewKeystore()
	if err := k.Install(make([]byte, KeyLen)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = k.With(func(kek []byte) error {
				if len(kek) != KeyLen {
					t.Errorf("With saw kek of length %d", len(kek))
				}
				return nil
			})
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = k.IsUnlocked()
		}()
	}
	wg.Wait()
}

func TestVerifier_DeterministicAndDistinct(t *testing.T) {
	a := bytes.Repeat([]byte{0xAA}, KeyLen)
	b := bytes.Repeat([]byte{0xBB}, KeyLen)

	va1 := Verifier(a)
	va2 := Verifier(a)
	vb := Verifier(b)

	if !bytes.Equal(va1, va2) {
		t.Error("Verifier is not deterministic")
	}
	if bytes.Equal(va1, vb) {
		t.Error("Verifier collides for distinct keys")
	}
	if len(va1) != 32 {
		t.Errorf("verifier length: got %d, want 32 (HMAC-SHA256)", len(va1))
	}
}

func TestVerifierEqual(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 32)
	b := bytes.Repeat([]byte{0x01}, 32)
	c := bytes.Repeat([]byte{0x02}, 32)

	if !VerifierEqual(a, b) {
		t.Error("identical bytes should compare equal")
	}
	if VerifierEqual(a, c) {
		t.Error("differing bytes should not compare equal")
	}
}
