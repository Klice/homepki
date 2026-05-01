package web

import (
	"errors"
	"net/http"

	"github.com/Klice/homepki/internal/store"
)

// handleRevoke implements POST /certs/{id}/revoke per API.md §6.6. The
// endpoint is idempotent (ensure-state): replays on an already-revoked
// cert return 303 to /certs/{id} without modifying anything or treating
// it as an error.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "revoke: ParseForm", err)
		return
	}

	id := r.PathValue("id")
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "revoke: GetCert", err)
		return
	}

	detailURL := "/certs/" + id

	// Ensure-state: already revoked → 303 to detail, no error.
	if cert.Status == "revoked" {
		hxRedirect(w, r, detailURL)
		return
	}

	reason, err := parseReason(r.PostForm.Get("reason"), cert.IsCA)
	if err != nil {
		// Field-level error: re-render the detail page with the message.
		// For now, a plain 400 — the detail page doesn't yet have an
		// inline error slot for revoke; that's a UI follow-up.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	transitioned, err := s.revokeAndRegen(cert, reason)
	if err != nil {
		// MarkRevoked may have already committed (but CRL regen failed) —
		// the cert is now revoked even though the CRL couldn't be
		// updated. Surface the error to the operator; the next CRL
		// fetch will retry the regen via the lazy path.
		internalServerError(w, "revoke: revokeAndRegen", err)
		return
	}
	_ = transitioned // currently same outcome either way; reserved for future logging
	hxRedirect(w, r, detailURL, EventCertsChanged)
}
