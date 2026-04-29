package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allKeys is every env var FromEnv reads. Listed here so each test case
// starts from a known-empty state and can opt-in to specific values.
var allKeys = []string{
	"CM_LISTEN_ADDR",
	"CM_DATA_DIR",
	"CRL_BASE_URL",
	"CM_PASSPHRASE",
	"CM_LOG_FORMAT",
	"CM_AUTO_LOCK_MINUTES",
}

func TestFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr string // substring match; "" means expect no error
	}{
		{
			name: "minimal valid — only CRL_BASE_URL set",
			env: map[string]string{
				"CRL_BASE_URL": "https://certs.lan",
			},
			want: Config{
				ListenAddr: ":8080",
				DataDir:    "/data",
				CRLBaseURL: "https://certs.lan",
				LogFormat:  "json",
			},
		},
		{
			name:    "missing CRL_BASE_URL is fatal",
			env:     map[string]string{},
			wantErr: "CRL_BASE_URL is required",
		},
		{
			name: "all overrides",
			env: map[string]string{
				"CM_LISTEN_ADDR":       "127.0.0.1:9000",
				"CM_DATA_DIR":          "/var/homepki",
				"CRL_BASE_URL":         "https://certs.lan",
				"CM_PASSPHRASE":        "secret-passphrase",
				"CM_LOG_FORMAT":        "text",
				"CM_AUTO_LOCK_MINUTES": "15",
			},
			want: Config{
				ListenAddr:      "127.0.0.1:9000",
				DataDir:         "/var/homepki",
				CRLBaseURL:      "https://certs.lan",
				Passphrase:      "secret-passphrase",
				LogFormat:       "text",
				AutoLockMinutes: 15,
			},
		},
		{
			name: "auto-lock minutes non-numeric is rejected",
			env: map[string]string{
				"CRL_BASE_URL":         "https://certs.lan",
				"CM_AUTO_LOCK_MINUTES": "abc",
			},
			wantErr: "CM_AUTO_LOCK_MINUTES",
		},
		{
			name: "auto-lock minutes negative is rejected",
			env: map[string]string{
				"CRL_BASE_URL":         "https://certs.lan",
				"CM_AUTO_LOCK_MINUTES": "-5",
			},
			wantErr: "CM_AUTO_LOCK_MINUTES",
		},
		{
			name: "auto-lock minutes zero is allowed (means disabled)",
			env: map[string]string{
				"CRL_BASE_URL":         "https://certs.lan",
				"CM_AUTO_LOCK_MINUTES": "0",
			},
			want: Config{
				ListenAddr:      ":8080",
				DataDir:         "/data",
				CRLBaseURL:      "https://certs.lan",
				LogFormat:       "json",
				AutoLockMinutes: 0,
			},
		},
		{
			name: "log format must be json or text",
			env: map[string]string{
				"CRL_BASE_URL":  "https://certs.lan",
				"CM_LOG_FORMAT": "xml",
			},
			wantErr: "CM_LOG_FORMAT",
		},
		{
			name: "empty value falls back to default",
			env: map[string]string{
				"CRL_BASE_URL":   "https://certs.lan",
				"CM_LISTEN_ADDR": "", // empty → default applies
			},
			want: Config{
				ListenAddr: ":8080",
				DataDir:    "/data",
				CRLBaseURL: "https://certs.lan",
				LogFormat:  "json",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range allKeys {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			got, err := FromEnv()

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
