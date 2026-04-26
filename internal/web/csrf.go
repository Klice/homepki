package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// API.md §2.2 — cookie name and form field name for the CSRF token.
const (
	csrfCookieName = "csrf"
	csrfFormField  = "csrf_token"
	csrfTokenLen   = 32 // bytes; rendered as 64 hex chars
)

// CSRF returns a middleware that:
//   - sets a CSRF cookie on safe-method requests if none is present;
//   - rejects state-changing requests whose csrf_token form field does not
//     match the cookie (HTTP 403);
//   - lets exempt paths through unchanged.
//
// Per API.md §2.2 the CRL endpoint and /healthz are exempt — neither is
// state-changing.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCSRFExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		token, err := ensureCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "csrf: failed to issue token", http.StatusInternalServerError)
			return
		}
		if isStateChanging(r.Method) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "csrf: bad form", http.StatusBadRequest)
				return
			}
			posted := r.PostForm.Get(csrfFormField)
			if subtle.ConstantTimeCompare([]byte(posted), []byte(token)) != 1 {
				http.Error(w, "csrf token mismatch", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isCSRFExempt(path string) bool {
	return path == "/healthz" || strings.HasPrefix(path, "/crl/")
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// ensureCSRFCookie returns the existing token from the request's csrf cookie,
// or generates a new one and adds it to the response.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	raw := make([]byte, csrfTokenLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPS(r),
		// No MaxAge → browser-session cookie. Per-session is fine for CSRF;
		// rotating gets a fresh value automatically each browser session.
	})
	return token, nil
}

// isHTTPS reports whether the request reached us over a TLS-secured channel,
// either terminated here (r.TLS != nil) or terminated upstream by a reverse
// proxy that set X-Forwarded-Proto=https.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
