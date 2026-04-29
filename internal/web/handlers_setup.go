package web

import (
	"encoding/json"
	"net/http"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// MinPassphraseLen is the minimum acceptable passphrase length per
// LIFECYCLE.md §1.1. Enforced server-side; the form also hints client-side
// via the input minlength attribute.
const MinPassphraseLen = 12

type setupViewData struct {
	CSRFToken string
	Error     string
	MinLen    int
}

// handleSetupGet renders the first-run setup form. If the app is already
// set up, it 303-redirects to /unlock per API.md §4.1.
func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "setup-get: IsSetUp", err)
		return
	}
	if setUp {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	s.render(w, "setup", setupViewData{
		CSRFToken: CSRFToken(r),
		MinLen:    MinPassphraseLen,
	})
}

// handleSetupPost performs first-run setup: validates the passphrase, derives
// a fresh KEK, atomically writes the salt + KDF params + verifier, installs
// the KEK in the keystore, and issues a session cookie.
func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "setup-post: IsSetUp", err)
		return
	}
	if setUp {
		// One-shot endpoint: replays after success land on /unlock.
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "setup-post: ParseForm", err)
		return
	}

	pp := r.PostForm.Get("passphrase")
	pp2 := r.PostForm.Get("passphrase2")
	if msg := validateNewPassphrase(pp, pp2); msg != "" {
		s.renderSetupError(w, r, msg)
		return
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		internalServerError(w, "setup-post: NewSalt", err)
		return
	}
	params := crypto.DefaultKDFParams()
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		internalServerError(w, "setup-post: marshal kdf params", err)
		return
	}

	kek, err := crypto.DeriveKEK([]byte(pp), salt, params)
	if err != nil {
		internalServerError(w, "setup-post: DeriveKEK", err)
		return
	}
	verifier := crypto.Verifier(kek)

	// Atomic write: salt + params + verifier in one transaction. Verifier
	// goes last so IsSetUp only flips after the whole bundle is durable.
	tx, err := s.db.Begin()
	if err != nil {
		crypto.Zero(kek)
		internalServerError(w, "setup-post: begin tx", err)
		return
	}
	for _, kv := range []struct {
		key   string
		value []byte
	}{
		{store.SettingKDFSalt, salt},
		{store.SettingKDFParams, paramsJSON},
		{store.SettingPassphraseVerifier, verifier},
	} {
		if err := store.SetSetting(tx, kv.key, kv.value); err != nil {
			_ = tx.Rollback()
			crypto.Zero(kek)
			internalServerError(w, "setup-post: SetSetting "+kv.key, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		crypto.Zero(kek)
		internalServerError(w, "setup-post: commit tx", err)
		return
	}

	if err := s.keystore.Install(kek); err != nil {
		// Setup persisted but KEK install failed. Operator can recover by
		// hitting /unlock with the passphrase they just chose.
		internalServerError(w, "setup-post: Install kek", err)
		return
	}
	if err := issueSessionCookie(w, r, s.keystore); err != nil {
		internalServerError(w, "setup-post: issue session", err)
		return
	}
	s.locker.Touch()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// validateNewPassphrase returns "" when the inputs are acceptable, or a
// user-facing error message otherwise.
func validateNewPassphrase(pp, pp2 string) string {
	switch {
	case len(pp) < MinPassphraseLen:
		return "Passphrase must be at least 12 characters."
	case pp != pp2:
		return "Passphrases do not match."
	}
	return ""
}

func (s *Server) renderSetupError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "setup", setupViewData{
		CSRFToken: CSRFToken(r),
		Error:     msg,
		MinLen:    MinPassphraseLen,
	})
}
