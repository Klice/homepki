package web

import (
	"encoding/json"
	"net/http"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// settingsViewData is the payload for the /settings page. The page only
// hosts the passphrase-rotation form for now; future settings (auto-lock
// timer config, etc.) will land on the same page.
type settingsViewData struct {
	CSRFToken string
	FormToken string
	Error     string
	Notice    string
	MinLen    int
}

// handleSettingsGet renders the settings page. Requires unlocked state per
// API.md §3 (kek; the rotation form is the only thing here and it requires
// the current KEK to derive the new one).
func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "settings-get: CreateIdemToken", err)
		return
	}
	s.render(w, "settings", settingsViewData{
		CSRFToken: CSRFToken(r),
		FormToken: tok,
		MinLen:    MinPassphraseLen,
		Notice:    r.URL.Query().Get("notice"),
	})
}

// handleSettingsPassphrasePost rotates the passphrase per API.md §4.4 /
// LIFECYCLE.md §1.6. The whole rewrap-all-DEKs + write-settings path is
// transactional via store.RotatePassphrase; this handler only owns the
// crypto, the form-token gating, and the in-memory KEK swap on success.
func (s *Server) handleSettingsPassphrasePost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "settings-pp-post: ParseForm", err)
		return
	}

	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "settings-pp-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		// Per API.md §4.4: replays return 303 to /settings without
		// re-verifying current (which would fail because the passphrase
		// has already changed).
		http.Redirect(w, r, state.ResultURL, http.StatusSeeOther)
		return
	}

	current := r.PostForm.Get("current")
	newPP := r.PostForm.Get("new")
	newPP2 := r.PostForm.Get("new2")
	if current == "" {
		s.renderSettingsError(w, r, state.Token, "Current passphrase required.")
		return
	}
	if msg := validateNewPassphrase(newPP, newPP2); msg != "" {
		s.renderSettingsError(w, r, state.Token, msg)
		return
	}

	// Verify "current" against the in-memory KEK, not by deriving a fresh
	// KEK from the salt. The verifier is HMAC(KEK, label); we already hold
	// KEK in the keystore, so we can compare HMAC(current's-derived-KEK,
	// label) against HMAC(in-memory-KEK, label) without ever loading the
	// stored verifier blob.
	salt, err := store.GetSetting(s.db, store.SettingKDFSalt)
	if err != nil {
		internalServerError(w, "settings-pp-post: load salt", err)
		return
	}
	paramsJSON, err := store.GetSetting(s.db, store.SettingKDFParams)
	if err != nil {
		internalServerError(w, "settings-pp-post: load kdf params", err)
		return
	}
	var oldParams crypto.KDFParams
	if err := json.Unmarshal(paramsJSON, &oldParams); err != nil {
		internalServerError(w, "settings-pp-post: parse kdf params", err)
		return
	}

	candidate, err := crypto.DeriveKEK([]byte(current), salt, oldParams)
	if err != nil {
		internalServerError(w, "settings-pp-post: derive candidate", err)
		return
	}
	defer crypto.Zero(candidate)

	currentMatches := false
	_ = s.keystore.With(func(live []byte) error {
		currentMatches = crypto.VerifierEqual(crypto.Verifier(candidate), crypto.Verifier(live))
		return nil
	})
	if !currentMatches {
		s.renderSettingsError(w, r, state.Token, "Current passphrase is incorrect.")
		return
	}

	// Derive KEK_new under a fresh salt + the current default params.
	// Defaults may have moved on since install (LIFECYCLE.md §2.2 allows
	// it); rotation is the natural moment to adopt them.
	newSalt, err := crypto.NewSalt()
	if err != nil {
		internalServerError(w, "settings-pp-post: NewSalt", err)
		return
	}
	newParams := crypto.DefaultKDFParams()
	newParamsJSON, err := json.Marshal(newParams)
	if err != nil {
		internalServerError(w, "settings-pp-post: marshal kdf params", err)
		return
	}
	newKEK, err := crypto.DeriveKEK([]byte(newPP), newSalt, newParams)
	if err != nil {
		internalServerError(w, "settings-pp-post: DeriveKEK new", err)
		return
	}
	// newKEK is handed to the keystore on success; on failure we zero it
	// before returning.
	commit := false
	defer func() {
		if !commit {
			crypto.Zero(newKEK)
		}
	}()
	newVerifier := crypto.Verifier(newKEK)

	resultURL := "/settings?notice=passphrase-rotated"
	in := store.RotatePassphraseInputs{
		NewSalt:       newSalt,
		NewParamsJSON: newParamsJSON,
		NewVerifier:   newVerifier,
	}

	// The rewrap closure needs both old and new KEKs. Hand it the live
	// keystore KEK via With so we never copy it out.
	var rotateErr error
	if err := s.keystore.With(func(oldKEK []byte) error {
		rotateErr = store.RotatePassphrase(s.db, in, store.RewrapWithKEKs(oldKEK, newKEK), state.Token, resultURL)
		return nil
	}); err != nil {
		internalServerError(w, "settings-pp-post: keystore.With", err)
		return
	}
	if rotateErr != nil {
		// The transaction rolled back; the operator's old passphrase
		// still works. Surface the error inline.
		s.renderSettingsError(w, r, state.Token, "Failed to rotate: "+rotateErr.Error())
		return
	}

	// Swap the live KEK. Install zeroes the previous one for us.
	if err := s.keystore.Install(newKEK); err != nil {
		internalServerError(w, "settings-pp-post: Install new KEK", err)
		return
	}
	commit = true // newKEK is now owned by the keystore.

	// Re-issue the session cookie under the new HKDF-derived secret so the
	// operator who rotated isn't logged out (API.md §4.4: "the existing
	// session stays valid"). Other devices' cookies become invalid because
	// the secret changed.
	if err := issueSessionCookie(w, r, s.keystore); err != nil {
		internalServerError(w, "settings-pp-post: issue session", err)
		return
	}

	http.Redirect(w, r, resultURL, http.StatusSeeOther)
}

func (s *Server) renderSettingsError(w http.ResponseWriter, r *http.Request, formToken, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "settings", settingsViewData{
		CSRFToken: CSRFToken(r),
		FormToken: formToken,
		Error:     msg,
		MinLen:    MinPassphraseLen,
	})
}
