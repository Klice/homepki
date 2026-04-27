package web

import "net/http"

// handleLock zeros the in-memory KEK and clears the session cookie.
// Per API.md §2.7.2 this is idempotent — locking when already locked
// is a no-op success that still 303s to /unlock.
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.keystore.Lock()
	http.SetCookie(w, ClearSessionCookie())
	http.Redirect(w, r, "/unlock", http.StatusSeeOther)
}
