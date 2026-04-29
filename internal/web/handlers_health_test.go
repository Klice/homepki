package web

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
)

func TestHandleHealthz_OK(t *testing.T) {
	db := openInMemoryDB(t)
	srv, err := New(config.Config{}, db, crypto.NewKeystore())
	require.NoError(t, err, "New")

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", strings.TrimSpace(w.Body.String()))
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
}

func TestHandleHealthz_DBUnreachable(t *testing.T) {
	db := openInMemoryDB(t)
	// Close the DB to simulate a failed Ping. Ping after Close returns
	// sql.ErrConnDone, which is exactly the "db unavailable" path.
	_ = db.Close()

	srv, err := New(config.Config{}, db, crypto.NewKeystore())
	require.NoError(t, err, "New")

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "db unavailable")
}

func openInMemoryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err, "open in-memory sqlite")
	require.NoError(t, db.Ping(), "ping")
	t.Cleanup(func() { _ = db.Close() })
	return db
}
