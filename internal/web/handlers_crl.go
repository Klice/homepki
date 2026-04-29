package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
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

// crlHistoryViewData feeds templates/crl_history.html.
type crlHistoryViewData struct {
	CSRFToken string
	View      *CertView
	CRLs      []*crlHistoryRow
}

// crlHistoryRow is the per-row display payload for the history table.
type crlHistoryRow struct {
	Number      int64
	ThisUpdate  string // YYYY-MM-DD HH:MM UTC
	NextUpdate  string
	DownloadURL string
	IsLatest    bool
}

// handleCRLHistory implements GET /certs/{id}/crls per API.md §5.3.
// CAs only; lists every historical CRL row newest first with a download
// link to that specific CRL DER.
func (s *Server) handleCRLHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	id := r.PathValue("id")
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "crl-history: GetCert", err)
		return
	}
	if !cert.IsCA {
		http.NotFound(w, r)
		return
	}

	rows, err := store.ListCRLs(s.db, id)
	if err != nil {
		internalServerError(w, "crl-history: ListCRLs", err)
		return
	}

	now := time.Now()
	chain, err := store.GetChain(s.db, id)
	if err != nil {
		internalServerError(w, "crl-history: GetChain", err)
		return
	}
	view := newCertView(cert, buildCNLookup(chain), now)

	display := make([]*crlHistoryRow, 0, len(rows))
	for i, c := range rows {
		display = append(display, &crlHistoryRow{
			Number:      c.CRLNumber,
			ThisUpdate:  c.ThisUpdate.UTC().Format("2006-01-02 15:04 UTC"),
			NextUpdate:  c.NextUpdate.UTC().Format("2006-01-02 15:04 UTC"),
			DownloadURL: "/crl/" + id + "/" + strconv.FormatInt(c.CRLNumber, 10) + ".crl",
			IsLatest:    i == 0,
		})
	}

	s.render(w, "crl_history", crlHistoryViewData{
		CSRFToken: CSRFToken(r),
		View:      view,
		CRLs:      display,
	})
}

// handleCRLByNumber implements GET /crl/{id}/{number}.crl — public,
// unauthenticated, returns the DER of a specific historical CRL. Same
// content-type as /crl/{id}.crl. Cache headers are stricter: a specific
// numbered CRL is immutable, so we can cache it forever.
func (s *Server) handleCRLByNumber(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	raw := r.PathValue("number")
	if !strings.HasSuffix(raw, ".crl") {
		http.NotFound(w, r)
		return
	}
	numStr := strings.TrimSuffix(raw, ".crl")
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil || n <= 0 {
		http.NotFound(w, r)
		return
	}

	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "crl-by-number: GetCert", err)
		return
	}
	if !cert.IsCA {
		http.NotFound(w, r)
		return
	}

	c, err := store.GetCRLByNumber(s.db, id, n)
	if errors.Is(err, store.ErrCRLNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "crl-by-number: GetCRLByNumber", err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	// A specific numbered CRL is immutable — once issued it never
	// changes. Long cache lifetime is safe.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(c.DER)
}
