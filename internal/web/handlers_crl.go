package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// handleCRL implements GET /crl/{issuer-id}.crl per API.md §9.1. Public
// and unauthenticated. Behaviour:
//   - cached fresh → serve as-is, 200
//   - cached stale + unlocked → regenerate inline, serve fresh, 200
//   - cached stale + locked → serve stale + Warning: 110 header, 200
//   - no row → 404 (should not happen for a valid CA — initial CRL is
//     written at issuance per LIFECYCLE.md §6.2)
//
// Path parameter is /crl/{id} where {id} carries the ".crl" suffix; the
// handler trims it before looking the issuer up. Invalid suffix → 404.
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	if !strings.HasSuffix(raw, ".crl") {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimSuffix(raw, ".crl")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	// Sanity: reject non-CA ids quickly so /crl/{leaf-id}.crl is a 404.
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "crl: GetCert", err)
		return
	}
	if !cert.IsCA {
		http.NotFound(w, r)
		return
	}

	cached, err := store.GetLatestCRL(s.db, id)
	if errors.Is(err, store.ErrCRLNotFound) {
		http.Error(w, "crl not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalServerError(w, "crl: GetLatestCRL", err)
		return
	}

	now := time.Now()
	if cached.NextUpdate.After(now) {
		serveCRL(w, cached.DER, false)
		return
	}

	// Cached is stale. Try to regenerate, but only if we have the KEK; a
	// locked keystore can't sign. Per API.md §9.1 we serve stale-with-warning
	// in that case rather than 503.
	if !s.keystore.IsUnlocked() {
		serveCRL(w, cached.DER, true)
		return
	}
	fresh, err := s.regenerateCRL(id)
	if err != nil {
		// Fall back to stale rather than failing the public endpoint.
		slog.Warn("crl regen failed, serving stale", "issuer", id, "err", err)
		serveCRL(w, cached.DER, true)
		return
	}
	serveCRL(w, fresh.DER, false)
}

// serveCRL writes the DER body with the right content type and cache
// headers. When stale=true, adds the RFC 7234 Warning header per API.md §9.1.
func serveCRL(w http.ResponseWriter, der []byte, stale bool) {
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	if stale {
		w.Header().Set("Warning", `110 - "CRL past nextUpdate; homepki is locked"`)
	}
	_, _ = w.Write(der)
}
