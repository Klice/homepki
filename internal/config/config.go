package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config holds all runtime configuration sourced from environment variables.
// See SPEC.md "Configuration (env)" for the canonical list.
type Config struct {
	ListenAddr      string
	DataDir         string
	CRLBaseURL      string
	Passphrase      string
	AutoLockMinutes int
	LogFormat       string
}

// FromEnv reads the process environment and returns a validated Config.
func FromEnv() (Config, error) {
	cfg := Config{
		ListenAddr: getenv("CM_LISTEN_ADDR", ":8080"),
		DataDir:    getenv("CM_DATA_DIR", "/data"),
		CRLBaseURL: os.Getenv("CRL_BASE_URL"),
		Passphrase: os.Getenv("CM_PASSPHRASE"),
		LogFormat:  getenv("CM_LOG_FORMAT", "json"),
	}
	if cfg.CRLBaseURL == "" {
		return cfg, errors.New("CRL_BASE_URL is required")
	}
	if v := os.Getenv("CM_AUTO_LOCK_MINUTES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return cfg, fmt.Errorf("CM_AUTO_LOCK_MINUTES: must be a non-negative integer, got %q", v)
		}
		cfg.AutoLockMinutes = n
	}
	switch cfg.LogFormat {
	case "json", "text":
	default:
		return cfg, fmt.Errorf("CM_LOG_FORMAT: must be 'json' or 'text', got %q", cfg.LogFormat)
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
