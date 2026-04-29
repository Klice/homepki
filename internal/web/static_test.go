package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticHandler_ServesPicoCSS(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/pico.min.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status")
	ct := w.Header().Get("Content-Type")
	assert.True(t, strings.HasPrefix(ct, "text/css"), "Content-Type: got %q, want text/css", ct)
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), "@charset", "response body does not look like the vendored pico.css")
}

func TestStaticHandler_ServesHtmx(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status")
	ct := w.Header().Get("Content-Type")
	assert.True(t,
		strings.HasPrefix(ct, "text/javascript") || strings.HasPrefix(ct, "application/javascript"),
		"Content-Type: got %q, want a JS type", ct)
}

func TestStaticHandler_ServesHomepkiCSS(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/homepki.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "status")
}

func TestStaticHandler_404OnMissing(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/does-not-exist.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "status")
}
