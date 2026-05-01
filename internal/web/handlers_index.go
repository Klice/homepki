package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// indexViewData is the data for the main view: two flat tables of CAs and
// leaves enriched with computed display fields, plus the active filter
// state so the form can re-render its current values.
type indexViewData struct {
	CSRFToken   string
	Authorities []*CertView
	Leaves      []*CertView

	// Filter state, echoed back into the form. Q is the raw query string;
	// Status is one of "" (any) | "active" | "expiring" | "expired" |
	// "revoked" | "superseded". Active is true when at least one filter
	// is non-empty — the template uses it to surface a "clear filters"
	// affordance.
	Q             string
	Status        string
	Active        bool
	StatusOptions []string

	// Total counts before filtering, so a 0/N result still tells the
	// operator their PKI isn't actually empty.
	TotalAuthorities int
	TotalLeaves      int
}

// statusFilterOptions is the closed set per API.md §5.1. Order matters —
// it's the order rendered in the dropdown.
var statusFilterOptions = []string{"active", "expiring", "expired", "revoked", "superseded"}

// handleIndex renders the main view at GET /. Redirects to /setup or
// /unlock as appropriate. Honours `?q=` (substring match across CN,
// SANs, serial, fingerprint) and `?status=` (one of statusFilterOptions)
// per API.md §5.1.
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
	authorities := newCertViews(cas, cnByID, now)
	leafViews := newCertViews(leaves, cnByID, now)

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := normaliseStatusFilter(r.URL.Query().Get("status"))

	data := indexViewData{
		CSRFToken:        CSRFToken(r),
		Authorities:      filterCerts(authorities, q, status),
		Leaves:           filterCerts(leafViews, q, status),
		Q:                q,
		Status:           status,
		Active:           q != "" || status != "",
		StatusOptions:    statusFilterOptions,
		TotalAuthorities: len(authorities),
		TotalLeaves:      len(leafViews),
	}

	if IsHXRequest(r) {
		s.renderFragment(w, "index", "index_fragment", data)
		return
	}
	s.render(w, "index", data)
}

// normaliseStatusFilter accepts the closed set from API.md §5.1 and
// rejects anything else by treating it as "no filter". Lowercase compare
// so a stray ?status=Active still works.
func normaliseStatusFilter(raw string) string {
	got := strings.ToLower(strings.TrimSpace(raw))
	for _, ok := range statusFilterOptions {
		if got == ok {
			return ok
		}
	}
	return ""
}

// filterCerts returns the subset of certs that match every active filter.
// Empty q / status means "any". q is matched case-insensitively against
// CN, every SAN (DNS + IP), serial, and the SHA-256 fingerprint.
func filterCerts(certs []*CertView, q, status string) []*CertView {
	if q == "" && status == "" {
		return certs
	}
	out := make([]*CertView, 0, len(certs))
	needle := strings.ToLower(q)
	for _, c := range certs {
		if status != "" && c.EffectiveStatus != status {
			continue
		}
		if needle != "" && !certMatchesQuery(c, needle) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// certMatchesQuery reports whether the cert's identifying fields contain
// the (already lowercased) query as a substring.
func certMatchesQuery(c *CertView, needle string) bool {
	if strings.Contains(strings.ToLower(c.SubjectCN), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(c.SerialNumber), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(c.FingerprintSHA256), needle) {
		return true
	}
	for _, s := range c.SANDNS {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	for _, s := range c.SANIPs {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	return false
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
