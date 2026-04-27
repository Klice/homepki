package web

import (
	"net/http"

	"github.com/Klice/homepki/internal/store"
)

// indexViewData is the data for the placeholder main view. The cert
// browsing UI lands in a future phase.
type indexViewData struct {
	CSRFToken string
}

// handleIndex is the main view dispatcher. It funnels traffic to /setup
// when the app is unconfigured, to /unlock when locked or sessionless,
// and otherwise renders the placeholder index page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 1.22 ServeMux registers "GET /" as a catch-all; explicit 404 for
	// anything that isn't exactly "/".
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	setUp, err := store.IsSetUp(s.db)
	if err != nil {
		internalServerError(w, "index: IsSetUp", err)
		return
	}
	if !setUp {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if !s.keystore.IsUnlocked() || !hasValidSession(r, s.keystore) {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	s.render(w, "index", indexViewData{
		CSRFToken: CSRFToken(r),
	})
}
