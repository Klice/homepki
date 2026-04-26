package web

import (
	"database/sql"
	"net/http"

	"github.com/Klice/homepki/internal/config"
)

// Server wires the HTTP mux, configuration, and database into one handler.
type Server struct {
	cfg config.Config
	db  *sql.DB
	mux *http.ServeMux
}

// New constructs a Server with all routes registered.
func New(cfg config.Config, db *sql.DB) *Server {
	s := &Server{cfg: cfg, db: db, mux: http.NewServeMux()}
	s.routes()
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}

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
