package web

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// pemBlockCertificate is the PEM type used for X.509 cert blocks.
const pemBlockCertificate = "CERTIFICATE"

// pemBlockPrivateKey is the PEM type used for PKCS#8 private key blocks.
const pemBlockPrivateKey = "PRIVATE KEY"

// handleCertPEM implements GET /certs/{id}/cert.pem per API.md §7.1.
func (s *Server) handleCertPEM(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	body := pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: cert.DERCert})
	setDownloadHeaders(w, downloadOpts{
		ContentType: "application/x-pem-file",
		Filename:    sanitizeFilename(cert.SubjectCN) + ".crt",
		Sensitive:   false,
	})
	_, _ = w.Write(body)
}

// handleKeyPEM implements GET /certs/{id}/key.pem per API.md §7.2.
// Decrypts the private key under the in-memory KEK and emits PKCS#8 PEM.
func (s *Server) handleKeyPEM(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	pkcs8, err := s.loadPKCS8(cert.ID)
	if err != nil {
		internalServerError(w, "key-pem: load pkcs8", err)
		return
	}
	defer crypto.Zero(pkcs8)
	body := pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: pkcs8})
	setDownloadHeaders(w, downloadOpts{
		ContentType: "application/x-pem-file",
		Filename:    sanitizeFilename(cert.SubjectCN) + ".key",
		Sensitive:   true,
	})
	_, _ = w.Write(body)
}

// handleChainPEM implements GET /certs/{id}/chain.pem per API.md §7.3.
// Concatenated PEM of every cert above this one in the chain, excluding the
// self-signed root. 404 when the cert is itself a root (no chain to serve).
func (s *Server) handleChainPEM(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	chain, err := store.GetChain(s.db, cert.ID)
	if err != nil {
		internalServerError(w, "chain-pem: GetChain", err)
		return
	}
	above := chainAboveExcludingRoot(chain)
	if len(chain) == 1 {
		// Self is the only thing in the chain — it's a self-signed root.
		http.NotFound(w, r)
		return
	}
	setDownloadHeaders(w, downloadOpts{
		ContentType: "application/x-pem-file",
		Filename:    sanitizeFilename(cert.SubjectCN) + "-chain.crt",
		Sensitive:   false,
	})
	for _, c := range above {
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: c.DERCert}))
	}
}

// handleFullchainPEM implements GET /certs/{id}/fullchain.pem per API.md §7.4.
// cert.pem followed by chain.pem. Leaf certs only.
func (s *Server) handleFullchainPEM(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	if cert.Type != "leaf" {
		http.NotFound(w, r)
		return
	}
	chain, err := store.GetChain(s.db, cert.ID)
	if err != nil {
		internalServerError(w, "fullchain-pem: GetChain", err)
		return
	}
	above := chainAboveExcludingRoot(chain)
	setDownloadHeaders(w, downloadOpts{
		ContentType: "application/x-pem-file",
		Filename:    sanitizeFilename(cert.SubjectCN) + "-fullchain.crt",
		Sensitive:   false,
	})
	_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: cert.DERCert}))
	for _, c := range above {
		_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: c.DERCert}))
	}
}

// handleBundleP12 implements POST /certs/{id}/bundle.p12 per API.md §7.5.
// PKCS#12 bundle with key + leaf + chain. Method is POST so the password
// stays out of URLs, referrers, and access logs.
func (s *Server) handleBundleP12(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "bundle-p12: ParseForm", err)
		return
	}
	password := r.PostForm.Get("password")
	if password == "" {
		http.Error(w, "password is required", http.StatusBadRequest)
		return
	}
	cert, ok := s.lookupCert(w, r)
	if !ok {
		return
	}
	if cert.Type != "leaf" {
		http.NotFound(w, r)
		return
	}
	leafX509, err := x509.ParseCertificate(cert.DERCert)
	if err != nil {
		internalServerError(w, "bundle-p12: parse leaf", err)
		return
	}
	chain, err := store.GetChain(s.db, cert.ID)
	if err != nil {
		internalServerError(w, "bundle-p12: GetChain", err)
		return
	}
	caCerts := make([]*x509.Certificate, 0, len(chain))
	for _, c := range chainAboveExcludingRoot(chain) {
		parsed, err := x509.ParseCertificate(c.DERCert)
		if err != nil {
			internalServerError(w, "bundle-p12: parse intermediate", err)
			return
		}
		caCerts = append(caCerts, parsed)
	}
	pkcs8, err := s.loadPKCS8(cert.ID)
	if err != nil {
		internalServerError(w, "bundle-p12: load pkcs8", err)
		return
	}
	defer crypto.Zero(pkcs8)
	priv, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		internalServerError(w, "bundle-p12: parse pkcs8", err)
		return
	}
	pfx, err := pkcs12.Modern.Encode(priv, leafX509, caCerts, password)
	if err != nil {
		internalServerError(w, "bundle-p12: encode", err)
		return
	}
	setDownloadHeaders(w, downloadOpts{
		ContentType: "application/x-pkcs12",
		Filename:    sanitizeFilename(cert.SubjectCN) + ".p12",
		Sensitive:   true,
	})
	_, _ = w.Write(pfx)
}

// lookupCert resolves the {id} path parameter to a cert row and writes a 404
// if missing. Returns the cert and ok=true on success; on miss it has already
// written the response and the caller should return.
func (s *Server) lookupCert(w http.ResponseWriter, r *http.Request) (*store.Cert, bool) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return nil, false
	}
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return nil, false
	}
	if err != nil {
		internalServerError(w, "download: GetCert", err)
		return nil, false
	}
	return cert, true
}

// loadPKCS8 returns the plaintext PKCS#8 bytes for certID. Caller owns the
// slice and is responsible for zeroing it as soon as it's been consumed.
func (s *Server) loadPKCS8(certID string) ([]byte, error) {
	row, err := store.GetCertKey(s.db, certID)
	if err != nil {
		return nil, fmt.Errorf("loadPKCS8: GetCertKey: %w", err)
	}
	var pkcs8 []byte
	err = s.keystore.With(func(kek []byte) error {
		var derr error
		pkcs8, derr = crypto.OpenPrivateKey(kek, certID, &crypto.SealedPrivateKey{
			WrappedDEK:  row.WrappedDEK,
			DEKNonce:    row.DEKNonce,
			CipherNonce: row.CipherNonce,
			Ciphertext:  row.Ciphertext,
		})
		return derr
	})
	if err != nil {
		return nil, fmt.Errorf("loadPKCS8: %w", err)
	}
	return pkcs8, nil
}

// chainAboveExcludingRoot returns chain[1:] minus a trailing self-signed
// root. Per API.md §7.3 chain.pem is "all certs above this one, excluding the
// self-signed root". Returns nil if there is nothing above, or if the only
// thing above is the self-signed root.
func chainAboveExcludingRoot(chain []*store.Cert) []*store.Cert {
	if len(chain) <= 1 {
		return nil
	}
	above := chain[1:]
	if last := above[len(above)-1]; last.ParentID == nil {
		above = above[:len(above)-1]
	}
	return above
}

// downloadOpts collects the per-endpoint differences setDownloadHeaders cares
// about: content type, attachment filename, and whether the body is sensitive
// (private key / p12 → strict no-cache; cert / chain → revalidate-on-use).
type downloadOpts struct {
	ContentType string
	Filename    string
	Sensitive   bool
}

// setDownloadHeaders writes Content-Type, Content-Disposition, and the cache
// headers from API.md §2.4.
func setDownloadHeaders(w http.ResponseWriter, o downloadOpts) {
	w.Header().Set("Content-Type", o.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+o.Filename+`"`)
	if o.Sensitive {
		w.Header().Set("Cache-Control", "no-store, no-cache")
		w.Header().Set("Pragma", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	}
}

// sanitizeFilename produces an attachment filename that travels safely through
// HTTP response headers and onto common filesystems. Non-ASCII letters,
// digits, dot, dash, and underscore are replaced with `_`. An empty result
// (e.g. CN was all whitespace) falls back to "cert".
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "cert"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "cert"
	}
	return out
}
