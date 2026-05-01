package web

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

func TestCRLBaseURL_SnapshotWrittenOnFirstIssuance(t *testing.T) {
	srv, db := testServer(t) // CRLBaseURL = https://test.lan
	fastSetup(t, srv, db)

	_, err := store.GetSetting(db, store.SettingCRLBaseURL)
	require.ErrorIs(t, err, store.ErrSettingNotFound,
		"snapshot must NOT be written until the first cert is issued")

	c := newClient(t, srv)
	installSession(t, srv, c)
	rootID := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Snapshot Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})
	require.NotEmpty(t, rootID)

	got, err := store.GetSetting(db, store.SettingCRLBaseURL)
	require.NoError(t, err, "snapshot must be written by first issuance")
	assert.Equal(t, "https://test.lan", string(got))
}

func TestCRLBaseURL_SnapshotFrozenAfterFirstIssuance(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// First issuance: snapshot captures the original env.
	mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"First Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	// Simulate the operator changing CRL_BASE_URL between issuances —
	// the snapshot must NOT be overwritten, otherwise drift detection
	// silently loses the original value.
	srv.cfg.CRLBaseURL = "https://moved.lan"
	mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Second Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	got, err := store.GetSetting(db, store.SettingCRLBaseURL)
	require.NoError(t, err)
	assert.Equal(t, "https://test.lan", string(got),
		"snapshot must remain the original URL even after env changed")
}

func TestCRLBaseURL_StartupDriftCheck_LogsWarnWhenEnvChanged(t *testing.T) {
	// Boot a server, issue a cert (writes the snapshot), then construct
	// a fresh server against the same DB but with a different env URL.
	// New() runs the drift check; capture slog output to verify the warn.
	first, db := testServer(t)
	fastSetup(t, first, db)
	c := newClient(t, first)
	installSession(t, first, c)
	mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Drift Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cfg := config.Config{CRLBaseURL: "https://moved.lan"}
	_, err := New(cfg, db, crypto.NewKeystore())
	require.NoError(t, err)

	logs := buf.String()
	assert.Contains(t, logs, "CRL_BASE_URL changed since first issuance")
	assert.Contains(t, logs, "https://test.lan", "warning must include the snapshot value")
	assert.Contains(t, logs, "https://moved.lan", "warning must include the live env value")
}

func TestCRLBaseURL_StartupDriftCheck_QuietWhenMatching(t *testing.T) {
	first, db := testServer(t)
	fastSetup(t, first, db)
	c := newClient(t, first)
	installSession(t, first, c)
	mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Match Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, err := New(config.Config{CRLBaseURL: "https://test.lan"}, db, crypto.NewKeystore())
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "CRL_BASE_URL changed",
		"matching env vs snapshot must not emit a drift warning")
}

func TestCRLBaseURL_StartupDriftCheck_QuietWhenNothingIssued(t *testing.T) {
	// A fresh DB with no certs and no snapshot must boot silently —
	// drift only matters once there's something to drift from.
	db := freshDB(t)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, err := New(config.Config{CRLBaseURL: "https://test.lan"}, db, crypto.NewKeystore())
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "CRL_BASE_URL")
}

func freshDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, store.Migrate(db))
	return db
}
