package web

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freshSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSessionRoundTrip(t *testing.T) {
	secret := freshSecret(t)
	value, err := SignSession(secret)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if err := VerifySession(secret, value); err != nil {
		t.Errorf("VerifySession: %v", err)
	}
}

func TestVerifySession_RejectsWrongSecret(t *testing.T) {
	value, err := SignSession(freshSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	other := freshSecret(t)
	if err := VerifySession(other, value); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("got %v, want ErrSessionInvalid", err)
	}
}

func TestVerifySession_RejectsTamperedPayload(t *testing.T) {
	secret := freshSecret(t)
	value, err := SignSession(secret)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character in the middle of the base64 blob.
	bytes := []byte(value)
	bytes[len(bytes)/2] ^= 0x01
	if err := VerifySession(secret, string(bytes)); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("got %v, want ErrSessionInvalid", err)
	}
}

func TestVerifySession_RejectsExpired(t *testing.T) {
	secret := freshSecret(t)
	now := time.Now()
	value, err := signPayload(secret, sessionPayload{
		IssuedAt:  now.Add(-2 * time.Hour).Unix(),
		ExpiresAt: now.Add(-time.Minute).Unix(),
		Version:   sessionVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySession(secret, value); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("got %v, want ErrSessionInvalid", err)
	}
}

func TestVerifySession_RejectsBadVersion(t *testing.T) {
	secret := freshSecret(t)
	now := time.Now()
	value, err := signPayload(secret, sessionPayload{
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Version:   sessionVersion + 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySession(secret, value); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("got %v, want ErrSessionInvalid", err)
	}
}

func TestVerifySession_RejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not-base64-!!!",
		"AA",                  // valid base64 but too short
		strings.Repeat("A", 50), // valid base64, plausibly long but no valid payload+sig
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			if err := VerifySession(freshSecret(t), v); !errors.Is(err, ErrSessionInvalid) {
				t.Errorf("got %v, want ErrSessionInvalid", err)
			}
		})
	}
}

func TestNewSessionCookie_Attributes(t *testing.T) {
	c := NewSessionCookie("opaque-value", true)
	if c.Name != SessionCookieName {
		t.Errorf("name: got %q, want %q", c.Name, SessionCookieName)
	}
	if c.Value != "opaque-value" {
		t.Errorf("value: got %q", c.Value)
	}
	if c.Path != "/" {
		t.Errorf("path: got %q", c.Path)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly should be true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite: got %d, want Lax", c.SameSite)
	}
	if !c.Secure {
		t.Error("Secure should be true when secure=true")
	}
	if c.MaxAge != int(SessionTTL.Seconds()) {
		t.Errorf("MaxAge: got %d, want %d", c.MaxAge, int(SessionTTL.Seconds()))
	}
}

func TestNewSessionCookie_InsecureMode(t *testing.T) {
	c := NewSessionCookie("v", false)
	if c.Secure {
		t.Error("Secure should be false when secure=false")
	}
}

func TestClearSessionCookie(t *testing.T) {
	c := ClearSessionCookie()
	if c.Name != SessionCookieName {
		t.Errorf("name: got %q", c.Name)
	}
	if c.Value != "" {
		t.Errorf("value: got %q, want empty", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge: got %d, want -1", c.MaxAge)
	}
}
