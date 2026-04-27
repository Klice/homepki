package web

import (
	"log/slog"
	"net/http"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// internalServerError logs op + err under ERROR and writes a plain-text 500.
// Use as the canonical "we hit something we can't handle" handler exit.
func internalServerError(w http.ResponseWriter, op string, err error) {
	slog.Error(op, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// hasValidSession returns true if the request carries a session cookie that
// verifies under the keystore-derived secret. Returns false if the keystore
// is locked, the cookie is missing, or it fails verification (any cause).
//
// Used by GET / to gate access; routes that need an authenticated operator
// redirect to /unlock when this returns false.
func hasValidSession(r *http.Request, ks *crypto.Keystore) bool {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	secret, err := ks.DeriveSessionSecret()
	if err != nil {
		// Keystore is locked — by definition any session is invalid because
		// we can't even derive the secret to verify it against.
		return false
	}
	defer crypto.Zero(secret)
	return VerifySession(secret, c.Value) == nil
}

// requireUnlocked enforces the auth gate shared by every page that needs
// the cert store. It 303-redirects to /setup when the app isn't configured,
// or to /unlock when it is configured but locked / missing a valid session.
// Returns true when the request should proceed.
func (s *Server) requireUnlocked(w http.ResponseWriter, r *http.Request) bool {
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "auth-gate: IsSetUp", err)
		return false
	}
	if !setUp {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return false
	}
	if !s.keystore.IsUnlocked() || !hasValidSession(r, s.keystore) {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return false
	}
	return true
}

// issueSessionCookie derives the secret and sets a fresh session cookie on w.
// Caller must have already installed the KEK in the keystore.
func issueSessionCookie(w http.ResponseWriter, r *http.Request, ks *crypto.Keystore) error {
	secret, err := ks.DeriveSessionSecret()
	if err != nil {
		return err
	}
	defer crypto.Zero(secret)
	value, err := SignSession(secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, NewSessionCookie(value, isHTTPS(r)))
	return nil
}
