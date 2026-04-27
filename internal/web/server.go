package web

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/Klice/homepki/internal/config"
)

// Server wires the HTTP mux, configuration, database, and parsed templates
// into one handler. All endpoint logic lives in handlers_*.go files;
// this file is the wiring.
type Server struct {
	cfg       config.Config
	db        *sql.DB
	templates map[string]*template.Template
	mux       *http.ServeMux
	handler   http.Handler // mux wrapped in middleware
}

// New constructs a Server with all routes registered and middleware applied.
// Returns an error if any embedded template fails to parse — bad templates
// are programmer errors and should fail loud at startup, not at first request.
func New(cfg config.Config, db *sql.DB) (*Server, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		db:        db,
		templates: tmpls,
		mux:       http.NewServeMux(),
	}
	s.routes()
	s.handler = CSRF(s.mux)
	return s, nil
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// routes is the single canonical list of HTTP routes. Handlers live in
// handlers_*.go files alongside.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
}
