package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// fastKDFParams returns Argon2id params low enough that tests don't grind for
// seconds. Memory is in KiB.
func fastKDFParams() KDFParams {
	return KDFParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32}
}

func TestDefaultKDFParams(t *testing.T) {
	p := DefaultKDFParams()
	if p.Time != 3 || p.Memory != 64*1024 || p.Threads != 2 || p.KeyLen != 32 {
		t.Errorf("unexpected defaults: %+v", p)
	}
}

func TestNewSalt(t *testing.T) {
	a, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != SaltLen {
		t.Errorf("len: got %d, want %d", len(a), SaltLen)
	}
	b, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two consecutive NewSalt() returned identical bytes — RNG is broken")
	}
}

func TestDeriveKEK_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	pw := []byte("correct horse battery staple")
	p := fastKDFParams()

	a, err := DeriveKEK(pw, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEK(pw, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("DeriveKEK is not deterministic for identical inputs")
	}
	if len(a) != int(p.KeyLen) {
		t.Errorf("output length: got %d, want %d", len(a), p.KeyLen)
	}
}

func TestDeriveKEK_DifferentSaltDifferentKey(t *testing.T) {
	pw := []byte("correct horse battery staple")
	p := fastKDFParams()

	a, err := DeriveKEK(pw, []byte("0123456789abcdef"), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEK(pw, []byte("fedcba9876543210"), p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("different salts produced identical KEKs")
	}
}

func TestDeriveKEK_DifferentPassphraseDifferentKey(t *testing.T) {
	salt := []byte("0123456789abcdef")
	p := fastKDFParams()

	a, err := DeriveKEK([]byte("first passphrase"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEK([]byte("second passphrase"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("different passphrases produced identical KEKs")
	}
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
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
