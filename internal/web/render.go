package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

const layoutPath = "templates/layout.html"

// loadTemplates parses every "templates/*.html" file other than layout.html
// alongside layout.html, producing one *template.Template per page keyed by
// the page's basename without extension. Returns an error if any template
// fails to parse.
//
// Page templates must define a "content" block; "title" and "header_actions"
// are optional and fall back to the layout's defaults.
func loadTemplates() (map[string]*template.Template, error) {
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("glob templates: %w", err)
	}
	out := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		if p == layoutPath {
			continue
		}
		name := strings.TrimSuffix(path.Base(p), ".html")
		t, err := template.ParseFS(templateFS, layoutPath, p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}

// render writes the named page template into w, executing the "layout" entry
// point so the page's content slots into the chrome. Logs and writes a 500
// if the template is unknown or execution fails.
//
// HTML pages are not cacheable per API.md §2.4.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.templates[name]
	if !ok {
		slog.Error("render: unknown template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		// Body may already be partially written; we can't change the status
		// at this point. Just log so the operator sees it.
		slog.Error("render: execute", "name", name, "err", err)
	}
}

// renderFragment writes a single named block from the page template
// without the surrounding layout. Used to serve htmx swaps at the same
// URL the page is otherwise rendered at — handlers branch on
// IsHXRequest and call this for the fragment branch (per API.md §10).
//
// Each fragment-aware page template defines a {{define "<name>"}}
// block that renders just the swappable region. Cache-Control is the
// same as the full-page render — fragments are still HTML, still not
// cacheable.
func (s *Server) renderFragment(w http.ResponseWriter, page, block string, data any) {
	t, ok := s.templates[page]
	if !ok {
		slog.Error("renderFragment: unknown template", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.ExecuteTemplate(w, block, data); err != nil {
		slog.Error("renderFragment: execute", "page", page, "block", block, "err", err)
	}
}
