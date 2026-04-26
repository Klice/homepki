package web

import "net/http"

// handleHealthz reports liveness. Per API.md §9.2, 200 if the DB is reachable,
// 503 otherwise. Lock state is intentionally ignored.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.db.PingContext(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("db unavailable\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}
