package web

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Klice/homepki/internal/config"
)

func TestHandleHealthz_OK(t *testing.T) {
	db := openInMemoryDB(t)
	srv, err := New(config.Config{}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "ok" {
		t.Errorf("body: got %q, want %q", got, "ok")
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: got %q", ct)
	}
}

func TestHandleHealthz_DBUnreachable(t *testing.T) {
	db := openInMemoryDB(t)
	// Close the DB to simulate a failed Ping. Ping after Close returns
	// sql.ErrConnDone, which is exactly the "db unavailable" path.
	_ = db.Close()

	srv, err := New(config.Config{}, db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if got := w.Body.String(); !strings.Contains(got, "db unavailable") {
		t.Errorf("body: got %q, want body containing 'db unavailable'", got)
	}
}

func openInMemoryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
