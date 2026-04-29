package web

import (
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freshSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestSessionRoundTrip(t *testing.T) {
	secret := freshSecret(t)
	value, err := SignSession(secret)
	require.NoError(t, err, "SignSession")
	assert.NoError(t, VerifySession(secret, value), "VerifySession")
}

func TestVerifySession_RejectsWrongSecret(t *testing.T) {
	value, err := SignSession(freshSecret(t))
	require.NoError(t, err)
	other := freshSecret(t)
	assert.ErrorIs(t, VerifySession(other, value), ErrSessionInvalid)
}

func TestVerifySession_RejectsTamperedPayload(t *testing.T) {
	secret := freshSecret(t)
	value, err := SignSession(secret)
	require.NoError(t, err)
	// Flip a character in the middle of the base64 blob.
	bytes := []byte(value)
	bytes[len(bytes)/2] ^= 0x01
	assert.ErrorIs(t, VerifySession(secret, string(bytes)), ErrSessionInvalid)
}

func TestVerifySession_RejectsExpired(t *testing.T) {
	secret := freshSecret(t)
	now := time.Now()
	value, err := signPayload(secret, sessionPayload{
		IssuedAt:  now.Add(-2 * time.Hour).Unix(),
		ExpiresAt: now.Add(-time.Minute).Unix(),
		Version:   sessionVersion,
	})
	require.NoError(t, err)
	assert.ErrorIs(t, VerifySession(secret, value), ErrSessionInvalid)
}

func TestVerifySession_RejectsBadVersion(t *testing.T) {
	secret := freshSecret(t)
	now := time.Now()
	value, err := signPayload(secret, sessionPayload{
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Version:   sessionVersion + 99,
	})
	require.NoError(t, err)
	assert.ErrorIs(t, VerifySession(secret, value), ErrSessionInvalid)
}

func TestVerifySession_RejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not-base64-!!!",
		"AA",                    // valid base64 but too short
		strings.Repeat("A", 50), // valid base64, plausibly long but no valid payload+sig
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			assert.ErrorIs(t, VerifySession(freshSecret(t), v), ErrSessionInvalid)
		})
	}
}

func TestNewSessionCookie_Attributes(t *testing.T) {
	c := NewSessionCookie("opaque-value", true)
	assert.Equal(t, SessionCookieName, c.Name, "name")
	assert.Equal(t, "opaque-value", c.Value, "value")
	assert.Equal(t, "/", c.Path, "path")
	assert.True(t, c.HttpOnly, "HttpOnly should be true")
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "SameSite")
	assert.True(t, c.Secure, "Secure should be true when secure=true")
	assert.Equal(t, int(SessionTTL.Seconds()), c.MaxAge, "MaxAge")
}

func TestNewSessionCookie_InsecureMode(t *testing.T) {
	c := NewSessionCookie("v", false)
	assert.False(t, c.Secure, "Secure should be false when secure=false")
}

func TestClearSessionCookie(t *testing.T) {
	c := ClearSessionCookie()
	assert.Equal(t, SessionCookieName, c.Name, "name")
	assert.Equal(t, "", c.Value, "value")
	assert.Equal(t, -1, c.MaxAge, "MaxAge")
}
