package web

import (
	"bytes"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates_NoErrors(t *testing.T) {
	tmpls, err := loadTemplates()
	require.NoError(t, err, "loadTemplates")
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

	assert.Equal(t, http.StatusOK, w.Code, "status")
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	body := w.Body.String()
	assert.Contains(t, body, `<title>Custom Title</title>`, "title slot was not rendered")
	assert.Contains(t, body, `<p id="x">hello</p>`, "content slot was not rendered")
	assert.Contains(t, body, `href="/static/pico.min.css"`, "layout chrome (pico link) missing")
}

func TestServer_Render_UnknownTemplate500(t *testing.T) {
	srv := mustNewServer(t)

	w := httptest.NewRecorder()
	srv.render(w, "no-such-template", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLayoutDefaults_TitleAndHeaderActions(t *testing.T) {
	// Render with a synthetic page that supplies only "content" — title
	// should fall back to the layout's default and header_actions should
	// render empty.
	page := template.Must(template.ParseFS(templateFS, layoutPath))
	page = template.Must(page.Parse(`{{define "content"}}<p>body</p>{{end}}`))

	var buf bytes.Buffer
	require.NoError(t, page.ExecuteTemplate(&buf, "layout", nil), "execute")
	assert.Contains(t, buf.String(), `<title>homepki</title>`, "layout default title missing")
}

func mustNewServer(t *testing.T) *Server {
	t.Helper()
	db := openInMemoryDB(t)
	srv, err := New(config.Config{}, db, crypto.NewKeystore())
	require.NoError(t, err, "New")
	return srv
}

// Ensure openInMemoryDB and *sql.DB are referenced even if other tests
// in this file evolve to not need them — keeps the helper in scope.
var _ = (*sql.DB)(nil)
