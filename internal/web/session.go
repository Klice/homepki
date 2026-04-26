package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SessionCookieName is the name of the session cookie.
const SessionCookieName = "session"

// SessionTTL is how long a freshly-issued session cookie remains valid.
const SessionTTL = 24 * time.Hour

// sessionVersion is bumped whenever the cookie payload structure changes
// in an incompatible way; old cookies fail to verify after a bump.
const sessionVersion = 1

// sessionPayload is the JSON-serialised body of the session cookie.
// Unix timestamps; seconds since epoch.
type sessionPayload struct {
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	Version   int   `json:"v"`
}

// ErrSessionInvalid is returned by VerifySession when the cookie value is
// missing, malformed, has a bad HMAC, has an unsupported version, or has
// expired.
var ErrSessionInvalid = errors.New("session: invalid")

// SignSession returns the cookie value for a freshly-issued session signed
// under secret with the default TTL.
func SignSession(secret []byte) (string, error) {
	now := time.Now()
	return signPayload(secret, sessionPayload{
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(SessionTTL).Unix(),
		Version:   sessionVersion,
	})
}

// VerifySession returns nil if value parses, has a valid HMAC under secret,
// has a supported version, and has not expired. Otherwise returns
// ErrSessionInvalid (use errors.Is to detect; the wrapped cause should
// not be relied on).
func VerifySession(secret []byte, value string) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return ErrSessionInvalid
	}
	if len(raw) <= sha256.Size {
		return ErrSessionInvalid
	}
	payload := raw[:len(raw)-sha256.Size]
	sig := raw[len(raw)-sha256.Size:]
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return ErrSessionInvalid
	}
	var p sessionPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return ErrSessionInvalid
	}
	if p.Version != sessionVersion {
		return ErrSessionInvalid
	}
	if time.Now().Unix() > p.ExpiresAt {
		return ErrSessionInvalid
	}
	return nil
}

// NewSessionCookie returns the http.Cookie to set on a response after a
// successful unlock or first-run setup. secure should be true when the
// response is going out over HTTPS.
func NewSessionCookie(value string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   int(SessionTTL.Seconds()),
	}
}

// ClearSessionCookie returns a cookie that, when set on the response,
// removes the session cookie from the browser. Used by POST /lock.
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func signPayload(secret []byte, p sessionPayload) (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	blob := make([]byte, 0, len(payload)+len(sig))
	blob = append(blob, payload...)
	blob = append(blob, sig...)
	return base64.RawURLEncoding.EncodeToString(blob), nil
}
