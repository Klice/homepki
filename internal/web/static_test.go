package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticHandler_ServesPicoCSS(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/pico.min.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("Content-Type: got %q, want text/css", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control: got %q", cc)
	}
	if !strings.Contains(w.Body.String(), "@charset") {
		t.Error("response body does not look like the vendored pico.css")
	}
}

func TestStaticHandler_ServesHtmx(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") &&
		!strings.HasPrefix(ct, "application/javascript") {
		t.Errorf("Content-Type: got %q, want a JS type", ct)
	}
}

func TestStaticHandler_ServesHomepkiCSS(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/homepki.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
}

func TestStaticHandler_404OnMissing(t *testing.T) {
	h := http.StripPrefix("/static/", staticHandler())

	req := httptest.NewRequest(http.MethodGet, "/static/does-not-exist.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}
