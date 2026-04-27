package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

type unlockViewData struct {
	CSRFToken string
	Error     string
}

// handleUnlockGet renders the unlock form. If the app is not set up,
// 303-redirects to /setup. If already unlocked with a valid session,
// 303-redirects to /.
func (s *Server) handleUnlockGet(w http.ResponseWriter, r *http.Request) {
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "unlock-get: IsSetUp", err)
		return
	}
	if !setUp {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.keystore.IsUnlocked() && hasValidSession(r, s.keystore) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "unlock", unlockViewData{
		CSRFToken: CSRFToken(r),
	})
}

// handleUnlockPost verifies the supplied passphrase against the stored
// verifier and, on match, installs the KEK and issues a session cookie.
//
// TODO(LIFECYCLE.md §1.2): in-process backoff after repeated failures.
func (s *Server) handleUnlockPost(w http.ResponseWriter, r *http.Request) {
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "unlock-post: IsSetUp", err)
		return
	}
	if !setUp {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	pp := r.PostForm.Get("passphrase")
	if pp == "" {
		s.renderUnlockError(w, r, "Passphrase required.")
		return
	}

	salt, err := store.GetSetting(s.db, store.SettingKDFSalt)
	if err != nil {
		internalServerError(w, "unlock-post: load salt", err)
		return
	}
	paramsJSON, err := store.GetSetting(s.db, store.SettingKDFParams)
	if err != nil {
		internalServerError(w, "unlock-post: load kdf params", err)
		return
	}
	verifier, err := store.GetSetting(s.db, store.SettingPassphraseVerifier)
	if err != nil {
		internalServerError(w, "unlock-post: load verifier", err)
		return
	}
	var params crypto.KDFParams
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		internalServerError(w, "unlock-post: parse kdf params", err)
		return
	}

	kek, err := crypto.DeriveAndVerify([]byte(pp), salt, params, verifier)
	if errors.Is(err, crypto.ErrPassphraseMismatch) {
		s.renderUnlockError(w, r, "Incorrect passphrase.")
		return
	}
	if err != nil {
		internalServerError(w, "unlock-post: derive+verify", err)
		return
	}

	if err := s.keystore.Install(kek); err != nil {
		internalServerError(w, "unlock-post: Install kek", err)
		return
	}
	if err := issueSessionCookie(w, r, s.keystore); err != nil {
		internalServerError(w, "unlock-post: issue session", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderUnlockError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "unlock", unlockViewData{
		CSRFToken: CSRFToken(r),
		Error:     msg,
	})
}
