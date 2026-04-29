package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func freshKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte("homepki/key/v1|cert-id-42")

	nonce, ciphertext, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) != NonceLen {
		t.Errorf("nonce length: got %d, want %d", len(nonce), NonceLen)
	}
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext equals plaintext — Seal did nothing")
	}

	got, err := Open(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch:\n  got %q\n want %q", got, plaintext)
	}
}

func TestSeal_NonceIsUnique(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("hello")
	aad := []byte("aad")

	seen := map[string]bool{}
	for i := range 100 {
		nonce, _, err := Seal(key, plaintext, aad)
		if err != nil {
			t.Fatal(err)
		}
		k := string(nonce)
		if seen[k] {
			t.Fatalf("nonce reuse on iteration %d", i)
		}
		seen[k] = true
	}
}

func TestOpen_RejectsTampering(t *testing.T) {
	key := freshKey(t)
	plaintext := []byte("secret")
	aad := []byte("aad")

	nonce, ct, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong key", func(t *testing.T) {
		other := freshKey(t)
		if _, err := Open(other, nonce, ct, aad); err == nil {
			t.Error("expected error with wrong key, got nil")
		}
	})

	t.Run("wrong aad", func(t *testing.T) {
		if _, err := Open(key, nonce, ct, []byte("different")); err == nil {
			t.Error("expected error with wrong aad, got nil")
		}
	})

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := append([]byte(nil), ct...)
		bad[0] ^= 0x01
		if _, err := Open(key, nonce, bad, aad); err == nil {
			t.Error("expected error with tampered ciphertext, got nil")
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		bad := append([]byte(nil), nonce...)
		bad[0] ^= 0x01
		if _, err := Open(key, bad, ct, aad); err == nil {
			t.Error("expected error with wrong nonce, got nil")
		}
	})
}

func TestSeal_ValidatesKeyLen(t *testing.T) {
	for _, badLen := range []int{0, 16, 24, 31, 33, 64} {
		bad := make([]byte, badLen)
		if _, _, err := Seal(bad, []byte("x"), nil); err == nil {
			t.Errorf("Seal accepted %d-byte key", badLen)
		}
	}
}

func TestOpen_ValidatesInputLengths(t *testing.T) {
	key := freshKey(t)
	nonce, ct, err := Seal(key, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(make([]byte, 16), nonce, ct, nil); err == nil {
		t.Error("Open accepted short key")
	}
	if _, err := Open(key, make([]byte, 8), ct, nil); err == nil {
		t.Error("Open accepted short nonce")
	}
}

func TestSeal_EmptyPlaintext(t *testing.T) {
	key := freshKey(t)
	nonce, ct, err := Seal(key, nil, []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(key, nonce, ct, []byte("aad"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}
