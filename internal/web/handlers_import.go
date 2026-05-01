package web

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

// importViewData drives templates/import_root.html. The handler echoes
// the operator's pasted PEM back into the form on validation errors so
// they don't lose the upload to a typo.
type importViewData struct {
	CSRFToken string
	FormToken string
	Error     string

	CertPEM string
	KeyPEM  string
}

// handleImportRootGet renders the import form. Requires kek (and so a
// valid session) because the matching POST seals a private key under
// the in-memory KEK; we keep both endpoints behind the same gate to
// avoid the GET form rendering for a locked operator who'd then get a
// 303 to /unlock on submit.
func (s *Server) handleImportRootGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "import-root-get: CreateIdemToken", err)
		return
	}
	s.render(w, "import_root", importViewData{
		CSRFToken: CSRFToken(r),
		FormToken: tok,
	})
}

// handleImportRootPost parses the pasted cert + key PEM, validates the
// cert is a self-signed CA whose public key matches the supplied
// private key, seals the key, and inserts a row with Source="imported"
// plus an empty initial CRL signed by the imported key.
//
// Idempotent on the cert's SHA-256 fingerprint: re-uploading the same
// root resolves to the same id without duplicating. Form-token replays
// also redirect to the same id without re-doing the work.
func (s *Server) handleImportRootPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "import-root-post: ParseForm", err)
		return
	}

	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "import-root-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		hxRedirect(w, r, state.ResultURL)
		return
	}

	certPEM := r.PostForm.Get("cert_pem")
	keyPEM := r.PostForm.Get("key_pem")

	cert, err := pki.ParseSingleCertPEM([]byte(certPEM))
	if err != nil {
		s.renderImportError(w, r, state.Token, certPEM, keyPEM, "Certificate: "+err.Error())
		return
	}
	key, err := pki.ParsePrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		s.renderImportError(w, r, state.Token, certPEM, keyPEM, "Private key: "+err.Error())
		return
	}
	if err := pki.ValidateRootCert(cert); err != nil {
		// Expired roots are a soft-warn case in the spec — record but
		// flag. We log a warning and continue; the dashboard's status
		// pill already surfaces "expired" so the operator notices.
		if !errors.Is(err, pki.ErrCertExpired) {
			s.renderImportError(w, r, state.Token, certPEM, keyPEM, err.Error())
			return
		}
		slog.Warn("import-root-post: importing expired root", "subject", cert.Subject.CommonName)
	}
	if err := pki.MatchKeyToCert(cert, key); err != nil {
		s.renderImportError(w, r, state.Token, certPEM, keyPEM, err.Error())
		return
	}
	keyAlgo, keyAlgoParams, err := pki.KeySpecOf(cert)
	if err != nil {
		s.renderImportError(w, r, state.Token, certPEM, keyPEM, err.Error())
		return
	}

	id, err := s.persistImportedRoot(cert.Raw, cert, key, string(keyAlgo), keyAlgoParams, state.Token)
	if err != nil {
		internalServerError(w, "import-root-post: persist", err)
		return
	}
	hxRedirect(w, r, "/certs/"+id, EventCertsChanged)
}

// renderImportError re-renders the form with a 400 + the operator's
// pasted PEM preserved.
func (s *Server) renderImportError(w http.ResponseWriter, r *http.Request, formToken, certPEM, keyPEM, msg string) {
	view := importViewData{
		CSRFToken: CSRFToken(r),
		FormToken: formToken,
		Error:     msg,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
	}
	w.WriteHeader(http.StatusBadRequest)
	if IsHXRequest(r) {
		s.renderFragment(w, "import_root", "form_fragment", view)
		return
	}
	s.render(w, "import_root", view)
}
