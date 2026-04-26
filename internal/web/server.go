package web

import (
	"database/sql"
	"net/http"

	"github.com/Klice/homepki/internal/config"
)

// Server wires the HTTP mux, configuration, and database into one handler.
// All endpoint logic lives in handlers_*.go files; this file is the wiring.
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

// routes is the single canonical list of HTTP routes. Handlers live in
// handlers_*.go files alongside.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}
