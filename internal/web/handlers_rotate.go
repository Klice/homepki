package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

// handleRotateGet renders an issuance form pre-filled from an existing cert.
// Reuses the same templates as /certs/new/* — just with FormAction pointed
// at /certs/{id}/rotate and the parent picker locked to the cert's existing
// parent (rotation keeps the chain intact per LIFECYCLE.md §4.3).
func (s *Server) handleRotateGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	id := r.PathValue("id")
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "rotate-get: GetCert", err)
		return
	}
	if cert.Status != "active" {
		// API.md §6.5: only active certs can be rotated.
		http.Error(w, "cannot rotate "+cert.Status+" cert; rotate the latest version instead", http.StatusConflict)
		return
	}

	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "rotate-get: CreateIdemToken", err)
		return
	}

	view := buildRotateView(cert, tok, CSRFToken(r))

	// Parent dropdown: load the same set as the matching issue handler so
	// the locked-but-displayed value renders by name. Roots have no parent
	// so we skip the lookup.
	if cert.Type == "intermediate_ca" {
		choices, err := s.parentChoicesForIntermediate()
		if err != nil {
			internalServerError(w, "rotate-get: parent choices", err)
			return
		}
		view.ParentChoices = choices
	} else if cert.Type == "leaf" {
		choices, err := s.parentChoicesForLeaf()
		if err != nil {
			internalServerError(w, "rotate-get: parent choices", err)
			return
		}
		view.ParentChoices = choices
	}

	s.render(w, templateForType(cert.Type), view)
}

// handleRotatePost issues a successor and atomically supersedes the old cert.
// Per API.md §6.5: replays of the same form_token return 303 to the same
// successor; rotating a non-active cert returns 409.
func (s *Server) handleRotatePost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "rotate-post: ParseForm", err)
		return
	}

	// Form-token check FIRST so replays after a successful rotate don't
	// trip the "old cert is no longer active" 409 below — the natural
	// post-rotate state IS that the old cert is superseded, and the
	// replay's job is to redirect to the successor that already exists.
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "rotate-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		http.Redirect(w, r, state.ResultURL, http.StatusSeeOther)
		return
	}

	id := r.PathValue("id")
	oldCert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		internalServerError(w, "rotate-post: GetCert", err)
		return
	}
	if oldCert.Status != "active" {
		http.Error(w, "cannot rotate "+oldCert.Status+" cert", http.StatusConflict)
		return
	}

	form := readIssueForm(r)
	if msg := validateCommon(form); msg != "" {
		s.renderRotateError(w, r, oldCert, form, state.Token, msg)
		return
	}

	subj := pki.Subject{CN: form.SubjectCN, O: form.SubjectO, OU: form.SubjectOU, L: form.SubjectL, ST: form.SubjectST, C: form.SubjectC}
	keySpec := pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams}
	validity := time.Duration(form.ValidityDays) * 24 * time.Hour

	var issued *pki.Issued
	switch oldCert.Type {
	case "root_ca":
		issued, err = pki.IssueRoot(pki.RootRequest{
			Subject:  subj,
			Key:      keySpec,
			Validity: validity,
		})
	case "intermediate_ca":
		// Rotation keeps the parent. Reload signer fresh.
		signer, _, lerr := s.loadSigner(*oldCert.ParentID)
		if lerr != nil {
			s.renderRotateError(w, r, oldCert, form, state.Token, "Parent CA cannot be used: "+lerr.Error())
			return
		}
		issued, err = pki.IssueIntermediate(pki.IntermediateRequest{
			Subject:    subj,
			Key:        keySpec,
			Parent:     signer,
			ParentID:   *oldCert.ParentID,
			CRLBaseURL: s.cfg.CRLBaseURL,
			Validity:   validity,
		})
	case "leaf":
		dns := parseSANDNS(form.SANDNS)
		ips, ipErr := parseSANIPs(form.SANIPs)
		if ipErr != nil {
			s.renderRotateError(w, r, oldCert, form, state.Token, ipErr.Error())
			return
		}
		if len(dns) == 0 && len(ips) == 0 {
			s.renderRotateError(w, r, oldCert, form, state.Token, "At least one SAN (DNS or IP) is required.")
			return
		}
		signer, _, lerr := s.loadSigner(*oldCert.ParentID)
		if lerr != nil {
			s.renderRotateError(w, r, oldCert, form, state.Token, "Parent CA cannot be used: "+lerr.Error())
			return
		}
		issued, err = pki.IssueLeaf(pki.LeafRequest{
			Subject:    subj,
			Key:        keySpec,
			Parent:     signer,
			ParentID:   *oldCert.ParentID,
			CRLBaseURL: s.cfg.CRLBaseURL,
			SANDNS:     dns,
			SANIPs:     ips,
			Validity:   validity,
		})
	default:
		http.Error(w, "unknown cert type: "+oldCert.Type, http.StatusInternalServerError)
		return
	}
	if err != nil {
		s.renderRotateError(w, r, oldCert, form, state.Token, "Failed to issue: "+err.Error())
		return
	}

	newID, err := s.persistRotation(oldCert.Type, oldCert.ParentID, oldCert.ID, issued, keySpec, state.Token)
	if errors.Is(err, store.ErrSupersedeNotActive) {
		// Race: someone else rotated/revoked between our load and commit.
		http.Error(w, "cert is no longer active; refresh and rotate the latest version", http.StatusConflict)
		return
	}
	if err != nil {
		internalServerError(w, "rotate-post: persist", err)
		return
	}
	http.Redirect(w, r, "/certs/"+newID, http.StatusSeeOther)
}

// buildRotateView pre-fills an issueViewData from an existing cert, ready
// for the rotate form. Joins SAN slices with ", " for textarea display.
func buildRotateView(cert *store.Cert, formToken, csrfToken string) issueViewData {
	v := issueViewData{
		CSRFToken:     csrfToken,
		FormToken:     formToken,
		FormAction:    "/certs/" + cert.ID + "/rotate",
		PageTitle:     "rotate " + cert.SubjectCN,
		PageHeading:   "Rotate " + cert.SubjectCN,
		ParentLocked:  true,
		SubjectCN:     cert.SubjectCN,
		SubjectO:      cert.SubjectO,
		SubjectOU:     cert.SubjectOU,
		SubjectL:      cert.SubjectL,
		SubjectST:     cert.SubjectST,
		SubjectC:      cert.SubjectC,
		KeyAlgo:       cert.KeyAlgo,
		KeyAlgoParams: cert.KeyAlgoParams,
		ValidityDays:  defaultValidityFor(cert.Type),
		SANDNS:        strings.Join(cert.SANDNS, ", "),
		SANIPs:        strings.Join(cert.SANIPs, ", "),
	}
	if cert.ParentID != nil {
		v.ParentID = *cert.ParentID
	}
	return v
}

// renderRotateError mirrors renderIssueError but preserves the rotate-
// specific titles/action because the user submitted to the rotate URL.
func (s *Server) renderRotateError(w http.ResponseWriter, r *http.Request, cert *store.Cert, form issueViewData, formToken, msg string) {
	form.CSRFToken = CSRFToken(r)
	form.FormToken = formToken
	form.Error = msg
	form.PageTitle = "rotate " + cert.SubjectCN
	form.PageHeading = "Rotate " + cert.SubjectCN
	form.ParentLocked = true
	// Re-load the parent dropdown so the (locked) selector still renders.
	if cert.Type == "intermediate_ca" {
		if choices, err := s.parentChoicesForIntermediate(); err == nil {
			form.ParentChoices = choices
		}
	} else if cert.Type == "leaf" {
		if choices, err := s.parentChoicesForLeaf(); err == nil {
			form.ParentChoices = choices
		}
	}
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, templateForType(cert.Type), form)
}

func templateForType(certType string) string {
	switch certType {
	case "root_ca":
		return "issue_root"
	case "intermediate_ca":
		return "issue_intermediate"
	case "leaf":
		return "issue_leaf"
	}
	return ""
}

// defaultValidityFor returns the default validity in days for a cert type,
// used when pre-filling the rotate form. Per LIFECYCLE.md §4.3.
func defaultValidityFor(certType string) int {
	switch certType {
	case "root_ca":
		return defaultRootValidityDays
	case "intermediate_ca":
		return defaultIntValidityDays
	case "leaf":
		return defaultLeafValidityDays
	}
	return 365
}
