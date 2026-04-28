package web

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// certDetailViewData is the data for the cert detail page at /certs/{id}.
type certDetailViewData struct {
	CSRFToken      string
	View           *CertView
	IssuerCN       string // parent's CN, or "— self —" for roots
	IssuerID       string // parent's ID for linking, "" for roots
	Chain          []*CertView
	FingerprintFmt string // SHA-256 colon-separated for display
	DeployTargets  []*DeployTargetView
}

// handleCertDetail serves /certs/{id}. 404s if the cert doesn't exist.
func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "cert-detail: GetCert", err)
		return
	}

	chain, err := store.GetChain(s.db, id)
	if err != nil {
		internalServerError(w, "cert-detail: GetChain", err)
		return
	}

	now := time.Now()
	cnByID := buildCNLookup(chain)
	chainViews := newCertViews(chain, cnByID, now)
	view := newCertView(cert, cnByID, now)

	var issuerCN, issuerID string
	if cert.ParentID != nil && len(chain) > 1 {
		issuerCN = chain[1].SubjectCN
		issuerID = chain[1].ID
	}

	var deployTargets []*DeployTargetView
	if cert.Type == "leaf" {
		targets, err := store.ListDeployTargets(s.db, cert.ID)
		if err != nil {
			internalServerError(w, "cert-detail: ListDeployTargets", err)
			return
		}
		deployTargets = newDeployTargetViews(targets, cert.SerialNumber)
	}

	s.render(w, "cert_detail", certDetailViewData{
		CSRFToken:      CSRFToken(r),
		View:           view,
		IssuerCN:       issuerCN,
		IssuerID:       issuerID,
		Chain:          chainViews,
		FingerprintFmt: formatFingerprint(cert.FingerprintSHA256),
		DeployTargets:  deployTargets,
	})
}

// formatFingerprint renders a hex SHA-256 fingerprint with colon
// separators between every byte, matching how openssl prints them.
func formatFingerprint(hexStr string) string {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return hexStr
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = hexByte(x)
	}
	return strings.Join(parts, ":")
}

const hexChars = "0123456789abcdef"

func hexByte(x byte) string {
	return string([]byte{hexChars[x>>4], hexChars[x&0x0f]})
}
