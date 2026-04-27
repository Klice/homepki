package web

import (
	"net/http"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// indexViewData is the data for the main view: two flat tables of CAs and
// leaves enriched with computed display fields.
type indexViewData struct {
	CSRFToken   string
	Authorities []*CertView
	Leaves      []*CertView
}

// handleIndex renders the main view at GET /. Redirects to /setup or
// /unlock as appropriate.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.requireUnlocked(w, r) {
		return
	}

	cas, err := store.ListCAs(s.db)
	if err != nil {
		internalServerError(w, "index: ListCAs", err)
		return
	}
	leaves, err := store.ListLeaves(s.db)
	if err != nil {
		internalServerError(w, "index: ListLeaves", err)
		return
	}

	cnByID := buildCNLookup(cas)
	now := time.Now()
	s.render(w, "index", indexViewData{
		CSRFToken:   CSRFToken(r),
		Authorities: newCertViews(cas, cnByID, now),
		Leaves:      newCertViews(leaves, cnByID, now),
	})
}

// buildCNLookup turns a slice of certs into an ID → CN map, used by the
// CertView enrichment to resolve issuer names.
func buildCNLookup(certs []*store.Cert) map[string]string {
	out := make(map[string]string, len(certs))
	for _, c := range certs {
		out[c.ID] = c.SubjectCN
	}
	return out
}
