package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSealPrivateKey_RoundTrip(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	plaintext := []byte("PKCS#8 DER goes here")
	certID := "11111111-1111-1111-1111-111111111111"

	sealed, err := SealPrivateKey(kek, certID, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed.DEKNonce) != NonceLen || len(sealed.CipherNonce) != NonceLen {
		t.Errorf("nonce lengths: dek=%d cipher=%d", len(sealed.DEKNonce), len(sealed.CipherNonce))
	}
	if bytes.Equal(sealed.Ciphertext, plaintext) {
		t.Error("ciphertext equals plaintext")
	}

	got, err := OpenPrivateKey(kek, certID, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch:\n  got %x\n want %x", got, plaintext)
	}
}

func TestSealPrivateKey_AADBoundToCertID(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	plaintext := []byte("secret key bytes")

	sealed, err := SealPrivateKey(kek, "cert-A", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Attempting to open with a different cert ID must fail — that's the
	// whole point of binding the AAD: an attacker who can swap rows in the
	// DB can't trick us into using one cert's key under another cert's id.
	if _, err := OpenPrivateKey(kek, "cert-B", sealed); err == nil {
		t.Error("Open with wrong certID should fail, got nil")
	}
}

func TestSealPrivateKey_DifferentKEKDifferentCiphertext(t *testing.T) {
	plaintext := []byte("secret")
	certID := "id"

	kek1 := make([]byte, KeyLen)
	rand.Read(kek1)
	kek2 := make([]byte, KeyLen)
	rand.Read(kek2)

	a, err := SealPrivateKey(kek1, certID, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealPrivateKey(kek2, certID, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Error("different KEKs produced identical wrapped DEKs")
	}
	// Inner ciphertext also differs because each call generates a fresh DEK.
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Error("different KEKs produced identical ciphertexts (DEK reuse?)")
	}
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
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("got %v, want error containing %q", err, tc.wantSub)
			}
		})
	}
}

func TestOpenPrivateKey_RejectsTampering(t *testing.T) {
	kek := make([]byte, KeyLen)
	rand.Read(kek)
	sealed, err := SealPrivateKey(kek, "id", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := *sealed
		bad.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
		bad.Ciphertext[0] ^= 0x01
		if _, err := OpenPrivateKey(kek, "id", &bad); err == nil {
			t.Error("expected error, got nil")
		}
	})
	t.Run("flipped wrapped dek byte", func(t *testing.T) {
		bad := *sealed
		bad.WrappedDEK = append([]byte(nil), sealed.WrappedDEK...)
		bad.WrappedDEK[0] ^= 0x01
		if _, err := OpenPrivateKey(kek, "id", &bad); err == nil {
			t.Error("expected error, got nil")
		}
	})
}
