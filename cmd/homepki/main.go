package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
	"github.com/Klice/homepki/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		setupLogging("text") // pre-config fallback so the message is human-readable
		return err
	}
	setupLogging(cfg.LogFormat)
	slog.Info("starting", "addr", cfg.ListenAddr, "data_dir", cfg.DataDir)

	db, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := store.Migrate(db); err != nil {
		return err
	}

	keystore := crypto.NewKeystore()

	// Optional unattended unlock from env (LIFECYCLE.md §1.5). Only attempted
	// when the app is already set up — first-run setup must still go through
	// the UI so the operator confirms the passphrase choice deliberately.
	if cfg.Passphrase != "" {
		if err := tryAutoUnlock(db, keystore, cfg.Passphrase); err != nil {
			return fmt.Errorf("auto-unlock from CM_PASSPHRASE: %w", err)
		}
	}

	handler, err := web.New(cfg, db, keystore)
	if err != nil {
		return err
	}
	defer handler.Stop()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Idempotency-token sweep per STORAGE.md §5.7. Lazy cleanup happens
	// inside every token lookup; this hourly sweep just caps growth in
	// case nobody loads forms for a while.
	go runIdemSweep(ctx, db)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}

// idemSweepInterval is how often we delete expired idempotency tokens
// per STORAGE.md §5.7. Hourly is plenty given lazy cleanup also runs on
// every lookup.
const idemSweepInterval = time.Hour

// runIdemSweep deletes expired idempotency tokens on a periodic ticker.
// Returns when ctx is cancelled (graceful shutdown).
func runIdemSweep(ctx context.Context, db *sql.DB) {
	t := time.NewTicker(idemSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := store.CleanupExpiredIdemTokens(db)
			if err != nil {
				slog.Warn("idem sweep failed", "err", err)
				continue
			}
			if n > 0 {
				slog.Info("idem sweep", "deleted", n)
			}
		}
	}
}

// tryAutoUnlock loads the salt + KDF params + verifier from settings and
// attempts to install a KEK derived from passphrase. Returns nil (and logs
// a warning) when the app isn't yet set up — that's not an error, the
// operator just hasn't done first-run setup yet.
func tryAutoUnlock(db *sql.DB, keystore *crypto.Keystore, passphrase string) error {
	setUp, err := store.IsSetUp(db)
	if err != nil {
		return err
	}
	if !setUp {
		slog.Warn("CM_PASSPHRASE set but app is not yet set up; skipping auto-unlock")
		return nil
	}
	salt, err := store.GetSetting(db, store.SettingKDFSalt)
	if err != nil {
		return err
	}
	paramsJSON, err := store.GetSetting(db, store.SettingKDFParams)
	if err != nil {
		return err
	}
	verifier, err := store.GetSetting(db, store.SettingPassphraseVerifier)
	if err != nil {
		return err
	}
	var params crypto.KDFParams
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return err
	}
	kek, err := crypto.DeriveAndVerify([]byte(passphrase), salt, params, verifier)
	if err != nil {
		return err
	}
	if err := keystore.Install(kek); err != nil {
		crypto.Zero(kek)
		return err
	}
	slog.Info("auto-unlocked from CM_PASSPHRASE")
	return nil
}

func setupLogging(format string) {
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		h = slog.NewTextHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(h))
}
