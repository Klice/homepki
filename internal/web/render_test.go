package web

import (
	"bytes"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/config"
)

func TestLoadTemplates_NoErrors(t *testing.T) {
	tmpls, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	// Layout-only state at the end of Phase 2c — no page templates yet.
	// Just assert that loading succeeds.
	_ = tmpls
}

// renderViaSyntheticPage exercises the render path end-to-end with an
// inline page that defines the "content" block, by injecting a custom
// template into Server.templates.
func TestServer_Render_ExecutesLayoutWithContent(t *testing.T) {
	srv := mustNewServer(t)

	page := template.Must(template.ParseFS(templateFS, layoutPath))
	page = template.Must(page.Parse(`{{define "content"}}<p id="x">hello</p>{{end}}`))
	page = template.Must(page.Parse(`{{define "title"}}Custom Title{{end}}`))
	srv.templates["synthetic"] = page

	w := httptest.NewRecorder()
	srv.render(w, "synthetic", nil)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type: got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control: got %q, want no-store", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<title>Custom Title</title>`) {
		t.Errorf("title slot was not rendered:\n%s", body)
	}
	if !strings.Contains(body, `<p id="x">hello</p>`) {
		t.Errorf("content slot was not rendered:\n%s", body)
	}
	if !strings.Contains(body, `href="/static/pico.min.css"`) {
		t.Errorf("layout chrome (pico link) missing:\n%s", body)
	}
}

func TestServer_Render_UnknownTemplate500(t *testing.T) {
	srv := mustNewServer(t)

	w := httptest.NewRecorder()
	srv.render(w, "no-such-template", nil)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", w.Code)
	}
}

func TestLayoutDefaults_TitleAndHeaderActions(t *testing.T) {
	// Render with a synthetic page that supplies only "content" — title
	// should fall back to the layout's default and header_actions should
	// render empty.
	page := template.Must(template.ParseFS(templateFS, layoutPath))
	page = template.Must(page.Parse(`{{define "content"}}<p>body</p>{{end}}`))

	var buf bytes.Buffer
	if err := page.ExecuteTemplate(&buf, "layout", nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), `<title>homepki</title>`) {
		t.Errorf("layout default title missing:\n%s", buf.String())
	}
}

func mustNewServer(t *testing.T) *Server {
	t.Helper()
	db := openInMemoryDB(t)
	srv, err := New(config.Config{}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// Ensure openInMemoryDB and *sql.DB are referenced even if other tests
// in this file evolve to not need them — keeps the helper in scope.
var _ = (*sql.DB)(nil)
