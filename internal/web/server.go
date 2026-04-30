package web

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/csrf"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
)

// Server wires the HTTP mux, configuration, database, keystore, and parsed
// templates into one handler. All endpoint logic lives in handlers_*.go
// files; this file is the wiring.
type Server struct {
	cfg       config.Config
	db        *sql.DB
	keystore  *crypto.Keystore
	templates map[string]*template.Template
	mux       *http.ServeMux
	handler   http.Handler // mux wrapped in middleware
	locker    *idleLocker  // auto-lock idle timer; no-op when disabled
	backoff   *unlockBackoff
}

// New constructs a Server with all routes registered and middleware applied.
// Returns an error if any embedded template fails to parse — bad templates
// are programmer errors and should fail loud at startup, not at first request.
func New(cfg config.Config, db *sql.DB, keystore *crypto.Keystore) (*Server, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	// gorilla/csrf needs a 32-byte secret to HMAC-sign tokens with. Random
	// per-process — the trade-off is that an in-flight browser session
	// loses its CSRF token across restart and needs a refresh, which is
	// acceptable for a single-operator tool.
	csrfSecret := make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		return nil, fmt.Errorf("csrf: generate secret: %w", err)
	}

	s := &Server{
		cfg:       cfg,
		db:        db,
		keystore:  keystore,
		templates: tmpls,
		mux:       http.NewServeMux(),
		locker:    newIdleLocker(keystore, autoLockTimeout(cfg)),
		backoff:   newUnlockBackoff(),
	}
	s.routes()
	// Cookie/field names match the existing API contract documented in
	// API.md §2.2. Secure(false) because the SPEC deployment model puts
	// homepki behind a reverse proxy that terminates TLS — the
	// proxy→app hop is plain HTTP, so a Secure cookie wouldn't make it
	// through.
	csrfMW := csrf.Protect(csrfSecret,
		csrf.CookieName(csrfCookieName),
		csrf.FieldName(csrfFormField),
		csrf.Path("/"),
		csrf.HttpOnly(true),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.Secure(false),
	)
	s.handler = plaintextHTTPDetect(csrfMW(s.mux))
	return s, nil
}

// plaintextHTTPDetect tells gorilla/csrf when a request actually arrived over
// plain HTTP. Without this, gorilla assumes HTTPS and rejects POSTs without
// a Referer header. We mark requests that have neither r.TLS nor an
// X-Forwarded-Proto=https hint as plaintext, matching isHTTPS.
func plaintextHTTPDetect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHTTPS(r) {
			r = csrf.PlaintextHTTPRequest(r)
		}
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Stop releases server-owned background resources (currently the idle
// auto-lock timer). Safe to call multiple times. Should be deferred from
// the process entry point so a graceful shutdown doesn't leak the timer.
func (s *Server) Stop() {
	s.locker.Stop()
}

// autoLockTimeout converts CM_AUTO_LOCK_MINUTES into the timeout fed to
// idleLocker. Per LIFECYCLE.md §1.4 auto-lock is forced off when
// CM_PASSPHRASE is set — otherwise the next request would just re-unlock
// the keystore from the env var.
func autoLockTimeout(cfg config.Config) time.Duration {
	if cfg.AutoLockMinutes <= 0 || cfg.Passphrase != "" {
		return 0
	}
	return time.Duration(cfg.AutoLockMinutes) * time.Minute
}

// routes is the single canonical list of HTTP routes. Handlers live in
// handlers_*.go files alongside.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /certs/{id}", s.handleCertDetail)
	s.mux.HandleFunc("GET /certs/new/root", s.handleIssueRootGet)
	s.mux.HandleFunc("POST /certs/new/root", s.handleIssueRootPost)
	s.mux.HandleFunc("GET /certs/new/intermediate", s.handleIssueIntermediateGet)
	s.mux.HandleFunc("POST /certs/new/intermediate", s.handleIssueIntermediatePost)
	s.mux.HandleFunc("GET /certs/new/leaf", s.handleIssueLeafGet)
	s.mux.HandleFunc("POST /certs/new/leaf", s.handleIssueLeafPost)
	s.mux.HandleFunc("GET /certs/import/root", s.handleImportRootGet)
	s.mux.HandleFunc("POST /certs/import/root", s.handleImportRootPost)
	s.mux.HandleFunc("POST /certs/{id}/revoke", s.handleRevoke)
	s.mux.HandleFunc("GET /certs/{id}/rotate", s.handleRotateGet)
	s.mux.HandleFunc("POST /certs/{id}/rotate", s.handleRotatePost)
	s.mux.HandleFunc("GET /certs/{id}/cert.pem", s.handleCertPEM)
	s.mux.HandleFunc("GET /certs/{id}/key.pem", s.handleKeyPEM)
	s.mux.HandleFunc("GET /certs/{id}/chain.pem", s.handleChainPEM)
	s.mux.HandleFunc("GET /certs/{id}/fullchain.pem", s.handleFullchainPEM)
	s.mux.HandleFunc("POST /certs/{id}/bundle.p12", s.handleBundleP12)
	s.mux.HandleFunc("GET /certs/{id}/deploy/new", s.handleDeployNewGet)
	s.mux.HandleFunc("POST /certs/{id}/deploy/new", s.handleDeployNewPost)
	s.mux.HandleFunc("GET /certs/{id}/deploy/{tid}/edit", s.handleDeployEditGet)
	s.mux.HandleFunc("POST /certs/{id}/deploy/{tid}/edit", s.handleDeployEditPost)
	s.mux.HandleFunc("POST /certs/{id}/deploy/{tid}/delete", s.handleDeployDelete)
	s.mux.HandleFunc("POST /certs/{id}/deploy/{tid}/run", s.handleDeployRunOne)
	s.mux.HandleFunc("POST /certs/{id}/deploy", s.handleDeployRunAll)
	s.mux.HandleFunc("GET /certs/{id}/crls", s.handleCRLHistory)
	s.mux.HandleFunc("GET /crl/{id}", s.handleCRL)
	s.mux.HandleFunc("GET /crl/{id}/{number}", s.handleCRLByNumber)
	s.mux.HandleFunc("GET /setup", s.handleSetupGet)
	s.mux.HandleFunc("POST /setup", s.handleSetupPost)
	s.mux.HandleFunc("GET /unlock", s.handleUnlockGet)
	s.mux.HandleFunc("POST /unlock", s.handleUnlockPost)
	s.mux.HandleFunc("POST /lock", s.handleLock)
	s.mux.HandleFunc("GET /settings", s.handleSettingsGet)
	s.mux.HandleFunc("POST /settings/passphrase", s.handleSettingsPassphrasePost)
}
