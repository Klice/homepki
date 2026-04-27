package web

import (
	"testing"
	"time"

	"github.com/Klice/homepki/internal/store"
)

func mkCert(cn string, parentID *string, status string, notAfter time.Time) *store.Cert {
	return &store.Cert{
		ID:            "id-" + cn,
		Type:          "leaf",
		ParentID:      parentID,
		SubjectCN:     cn,
		KeyAlgo:       "ecdsa",
		KeyAlgoParams: "P-256",
		Status:        status,
		NotBefore:     notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:      notAfter,
	}
}

func TestEffectiveStatus(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		status string
		na     time.Time
		want   string
	}{
		{"active", "active", now.Add(365 * 24 * time.Hour), "active"},
		{"expiring", "active", now.Add(15 * 24 * time.Hour), "expiring"},
		{"expired", "active", now.Add(-1 * time.Hour), "expired"},
		{"revoked beats expiry", "revoked", now.Add(365 * 24 * time.Hour), "revoked"},
		{"superseded beats expiry", "superseded", now.Add(-365 * 24 * time.Hour), "superseded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mkCert("x", nil, tc.status, tc.na)
			if got := effectiveStatus(c, now); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPillClass(t *testing.T) {
	cases := map[string]string{
		"active":     "pill-ok",
		"expiring":   "pill-warn",
		"expired":    "pill-bad",
		"revoked":    "pill-muted",
		"superseded": "pill-muted",
		"weird":      "",
	}
	for status, want := range cases {
		if got := pillClass(status); got != want {
			t.Errorf("pillClass(%q): got %q, want %q", status, got, want)
		}
	}
}

func TestRelativeExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{"in 6 days", now.Add(6 * 24 * time.Hour), "in 6d"},
		{"in 27 days", now.Add(27 * 24 * time.Hour), "in 27d"},
		{"in 4mo", now.Add(120 * 24 * time.Hour), "in 4mo"},
		{"in 8y", now.Add(8 * 365 * 24 * time.Hour), "in 8y"},
		{"expired 4d ago", now.Add(-4 * 24 * time.Hour), "expired 4d ago"},
		{"under 1h", now.Add(30 * time.Minute), "in <1h"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relativeExpiry(tc.notAfter, now); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatKey(t *testing.T) {
	cases := []struct {
		algo, params, want string
	}{
		{"rsa", "4096", "RSA 4096"},
		{"ecdsa", "P-384", "ECDSA P-384"},
		{"ed25519", "", "Ed25519"},
		{"unknown", "x", "unknown"},
	}
	for _, tc := range cases {
		if got := formatKey(tc.algo, tc.params); got != tc.want {
			t.Errorf("formatKey(%q,%q): got %q, want %q", tc.algo, tc.params, got, tc.want)
		}
	}
}

func TestNewCertView_IssuerLookup(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	parentID := "parent-id"

	root := mkCert("Root", nil, "active", now.Add(365*24*time.Hour))
	root.ID = parentID
	leaf := mkCert("leaf.test", &parentID, "active", now.Add(60*24*time.Hour))
	leaf.SANDNS = []string{"leaf.test", "alt.leaf.test"}
	leaf.SANIPs = []string{"10.0.0.1"}

	cnByID := map[string]string{root.ID: "Issuing CA"}

	t.Run("root shows self", func(t *testing.T) {
		v := newCertView(root, cnByID, now)
		if v.IssuerCN != "— self —" {
			t.Errorf("root issuer: got %q", v.IssuerCN)
		}
	})
	t.Run("leaf shows parent CN from lookup", func(t *testing.T) {
		v := newCertView(leaf, cnByID, now)
		if v.IssuerCN != "Issuing CA" {
			t.Errorf("leaf issuer: got %q", v.IssuerCN)
		}
		want := "leaf.test, alt.leaf.test, 10.0.0.1"
		if v.SANsDisplay != want {
			t.Errorf("SANs: got %q, want %q", v.SANsDisplay, want)
		}
	})
	t.Run("missing parent falls back to id", func(t *testing.T) {
		ghost := mkCert("orphan", &parentID, "active", now.Add(60*24*time.Hour))
		v := newCertView(ghost, map[string]string{}, now)
		if v.IssuerCN != parentID {
			t.Errorf("orphan: got %q, want %q", v.IssuerCN, parentID)
		}
	})
}
