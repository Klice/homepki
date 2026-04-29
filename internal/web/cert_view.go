package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// expiringWindow is how far ahead of now_after we flag a cert as
// "expiring" rather than "active". 30 days matches the mockup's
// "Expiring ≤30d" filter and the spec's typical operator workflow.
const expiringWindow = 30 * 24 * time.Hour

// CertView wraps a *store.Cert with display-ready fields computed at
// request time. Templates render these directly so they stay logic-free.
type CertView struct {
	*store.Cert

	// EffectiveStatus is the displayable status after deriving "expired"
	// from now > NotAfter (LIFECYCLE.md §5.5).
	EffectiveStatus string // active | expiring | expired | revoked | superseded
	StatusPillClass string // pill-ok | pill-warn | pill-bad | pill-muted

	// NotBeforeDisplay / NotAfterDisplay: short ISO date.
	NotBeforeDisplay string // "2026-04-22"
	NotAfterDisplay  string // "2027-04-22"
	// RelativeExpiry: human-friendly "in 6d" / "expired 4d ago" / "in 8mo".
	RelativeExpiry string

	// IssuerCN is the parent's subject CN, or "— self —" for roots.
	IssuerCN string

	// KeyDisplay is e.g. "RSA 4096", "ECDSA P-256", "Ed25519".
	KeyDisplay string

	// SANsDisplay is DNS + IP SANs joined with ", " for inline rendering.
	SANsDisplay string

	// TypeDisplay is the short type label for compact tables: "root",
	// "intermediate", "leaf". Use .Type for the underlying constant.
	TypeDisplay string

	// FingerprintShort is the first 6 hex chars of the SHA-256 fingerprint
	// formatted with colons (e.g. "8a:2c:11"). Used in the row-meta line
	// where the full fingerprint would dominate the column.
	FingerprintShort string
}

// newCertView produces a CertView. cnByID is a lookup map of cert ID →
// subject CN, used to render the issuer column. now is parameterized for
// deterministic test output.
func newCertView(c *store.Cert, cnByID map[string]string, now time.Time) *CertView {
	cv := &CertView{Cert: c}
	cv.EffectiveStatus = effectiveStatus(c, now)
	cv.StatusPillClass = pillClass(cv.EffectiveStatus)
	cv.NotBeforeDisplay = c.NotBefore.UTC().Format("2006-01-02")
	cv.NotAfterDisplay = c.NotAfter.UTC().Format("2006-01-02")
	cv.RelativeExpiry = relativeExpiry(c.NotAfter, now)
	cv.IssuerCN = "— self —"
	if c.ParentID != nil {
		if cn, ok := cnByID[*c.ParentID]; ok {
			cv.IssuerCN = cn
		} else {
			cv.IssuerCN = *c.ParentID // fallback if we can't resolve
		}
	}
	cv.KeyDisplay = formatKey(c.KeyAlgo, c.KeyAlgoParams)

	parts := make([]string, 0, len(c.SANDNS)+len(c.SANIPs))
	parts = append(parts, c.SANDNS...)
	parts = append(parts, c.SANIPs...)
	cv.SANsDisplay = strings.Join(parts, ", ")
	cv.TypeDisplay = shortType(c.Type)
	cv.FingerprintShort = shortFingerprint(c.FingerprintSHA256)
	return cv
}

func shortType(t string) string {
	switch t {
	case "root_ca":
		return "root"
	case "intermediate_ca":
		return "intermediate"
	case "leaf":
		return "leaf"
	}
	return t
}

// shortFingerprint formats the first 6 hex chars (3 bytes) as colon-separated
// pairs — enough disambiguation for an at-a-glance table row, full value
// available on the cert detail page.
func shortFingerprint(hex string) string {
	if len(hex) < 6 {
		return hex
	}
	return hex[0:2] + ":" + hex[2:4] + ":" + hex[4:6]
}

// newCertViews enriches a slice of certs against the same lookup map.
func newCertViews(certs []*store.Cert, cnByID map[string]string, now time.Time) []*CertView {
	out := make([]*CertView, len(certs))
	for i, c := range certs {
		out[i] = newCertView(c, cnByID, now)
	}
	return out
}

func effectiveStatus(c *store.Cert, now time.Time) string {
	if c.Status == "revoked" || c.Status == "superseded" {
		return c.Status
	}
	if now.After(c.NotAfter) {
		return "expired"
	}
	if c.NotAfter.Sub(now) < expiringWindow {
		return "expiring"
	}
	return "active"
}

func pillClass(status string) string {
	switch status {
	case "active":
		return "pill-ok"
	case "expiring":
		return "pill-warn"
	case "expired":
		return "pill-bad"
	case "revoked", "superseded":
		return "pill-muted"
	}
	return ""
}

func relativeExpiry(notAfter, now time.Time) string {
	if now.After(notAfter) {
		return "expired " + humanizeDuration(now.Sub(notAfter)) + " ago"
	}
	return "in " + humanizeDuration(notAfter.Sub(now))
}

// humanizeDuration produces compact relative-time strings in the same
// style as the mockup ("6d", "27d", "4mo", "8y").
func humanizeDuration(d time.Duration) string {
	hours := int(d / time.Hour)
	if hours < 24 {
		if hours < 1 {
			return "<1h"
		}
		return fmt.Sprintf("%dh", hours)
	}
	days := hours / 24
	if days < 60 {
		return fmt.Sprintf("%dd", days)
	}
	if days < 365 {
		return fmt.Sprintf("%dmo", days/30)
	}
	return fmt.Sprintf("%dy", days/365)
}

func formatKey(algo, params string) string {
	switch algo {
	case "rsa":
		return "RSA " + params
	case "ecdsa":
		return "ECDSA " + params
	case "ed25519":
		return "Ed25519"
	}
	return algo
}
