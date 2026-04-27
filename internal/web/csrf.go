package web

import (
	"net/http"

	"github.com/gorilla/csrf"
)

// csrf-related identifiers used in templates and tests. Kept as package
// constants so the cookie/field names stay aligned across the middleware
// configuration in server.go and the handler/test code that reads them.
const (
	csrfCookieName = "csrf"
	csrfFormField  = "csrf_token"
)

// CSRFToken returns the CSRF token for the current request, suitable for
// embedding in form templates as a hidden input. Thin wrapper over
// gorilla/csrf so the rest of the codebase doesn't import the library
// directly.
func CSRFToken(r *http.Request) string {
	return csrf.Token(r)
}

// isHTTPS reports whether the request reached us over a TLS-secured
// channel, either terminated here (r.TLS != nil) or terminated upstream
// by a reverse proxy that set X-Forwarded-Proto=https. Used for setting
// the Secure flag on session cookies.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
