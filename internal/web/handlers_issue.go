package web

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/pki"
	"github.com/Klice/homepki/internal/store"
)

// Defaults per LIFECYCLE.md §4.3.
const (
	defaultRootValidityDays  = 10 * 365 // 10 years
	defaultIntValidityDays   = 5 * 365  // 5 years
	defaultLeafValidityDays  = 90       // 3 months
	defaultRootKeyAlgo       = string(pki.RSA)
	defaultRootKeyAlgoParams = "4096"
	defaultIntKeyAlgo        = string(pki.ECDSA)
	defaultIntKeyAlgoParams  = "P-384"
	defaultLeafKeyAlgo       = string(pki.ECDSA)
	defaultLeafKeyAlgoParams = "P-256"
)

// issueViewData is the data for all three issue forms; the template chooses
// which fields to render based on which struct fields are populated.
type issueViewData struct {
	CSRFToken string
	FormToken string
	Error     string

	// FormAction is the URL the form posts to. Issue handlers set this to
	// /certs/new/{type}; rotate handlers set it to /certs/{id}/rotate.
	FormAction string
	// PageTitle / PageHeading let the rotate flow re-use the same templates
	// with a different on-page label.
	PageTitle   string
	PageHeading string
	// ParentLocked, when true, disables the parent-CA picker (rotation
	// keeps the same parent as the cert being rotated).
	ParentLocked bool

	// Form values, echoed back to the user on validation error.
	SubjectCN     string
	SubjectO      string
	SubjectOU     string
	SubjectL      string
	SubjectST     string
	SubjectC      string
	KeyAlgo       string
	KeyAlgoParams string
	ValidityDays  int
	SANDNS        string
	SANIPs        string
	ParentID      string

	// For intermediate / leaf: the CAs the operator can pick as parent.
	ParentChoices []parentChoice
}

type parentChoice struct {
	ID   string
	CN   string
	Type string // "root_ca" or "intermediate_ca"
}

// ============== root ==============

func (s *Server) handleIssueRootGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "issue-root-get: CreateIdemToken", err)
		return
	}
	s.render(w, "issue_root", issueViewData{
		CSRFToken:     CSRFToken(r),
		FormToken:     tok,
		FormAction:    "/certs/new/root",
		PageTitle:     "issue root CA",
		PageHeading:   "Issue root CA",
		KeyAlgo:       defaultRootKeyAlgo,
		KeyAlgoParams: defaultRootKeyAlgoParams,
		ValidityDays:  defaultRootValidityDays,
	})
}

func (s *Server) handleIssueRootPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "issue-root-post: ParseForm", err)
		return
	}
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "issue-root-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		hxRedirect(w, r, state.ResultURL)
		return
	}

	form := readIssueForm(r)
	if msg := validateCommon(form); msg != "" {
		s.renderIssueError(w, r, "issue_root", form, state.Token, msg, nil)
		return
	}

	issued, err := pki.IssueRoot(pki.RootRequest{
		Subject:  pki.Subject{CN: form.SubjectCN, O: form.SubjectO, OU: form.SubjectOU, L: form.SubjectL, ST: form.SubjectST, C: form.SubjectC},
		Key:      pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams},
		Validity: time.Duration(form.ValidityDays) * 24 * time.Hour,
	})
	if err != nil {
		s.renderIssueError(w, r, "issue_root", form, state.Token, "Failed to issue: "+err.Error(), nil)
		return
	}

	id, err := s.persistIssued("root_ca", nil, issued, pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams}, state.Token)
	if err != nil {
		internalServerError(w, "issue-root-post: persist", err)
		return
	}
	hxRedirect(w, r, "/certs/"+id, EventCertsChanged)
}

// ============== intermediate ==============

func (s *Server) handleIssueIntermediateGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	choices, err := s.parentChoicesForIntermediate()
	if err != nil {
		internalServerError(w, "issue-int-get: parent choices", err)
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "issue-int-get: CreateIdemToken", err)
		return
	}
	s.render(w, "issue_intermediate", issueViewData{
		CSRFToken:     CSRFToken(r),
		FormToken:     tok,
		FormAction:    "/certs/new/intermediate",
		PageTitle:     "issue intermediate CA",
		PageHeading:   "Issue intermediate CA",
		KeyAlgo:       defaultIntKeyAlgo,
		KeyAlgoParams: defaultIntKeyAlgoParams,
		ValidityDays:  defaultIntValidityDays,
		ParentID:      r.URL.Query().Get("parent"),
		ParentChoices: choices,
	})
}

func (s *Server) handleIssueIntermediatePost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "issue-int-post: ParseForm", err)
		return
	}
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "issue-int-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		hxRedirect(w, r, state.ResultURL)
		return
	}

	form := readIssueForm(r)
	choices, err := s.parentChoicesForIntermediate()
	if err != nil {
		internalServerError(w, "issue-int-post: parent choices", err)
		return
	}
	if msg := validateCommon(form); msg != "" {
		s.renderIssueError(w, r, "issue_intermediate", form, state.Token, msg, choices)
		return
	}
	if form.ParentID == "" {
		s.renderIssueError(w, r, "issue_intermediate", form, state.Token, "Parent CA required.", choices)
		return
	}
	parentSigner, parentCert, err := s.loadSigner(form.ParentID)
	if err != nil {
		s.renderIssueError(w, r, "issue_intermediate", form, state.Token, "Parent CA cannot be used: "+err.Error(), choices)
		return
	}
	if !parentCert.IsCA {
		s.renderIssueError(w, r, "issue_intermediate", form, state.Token, "Selected parent is not a CA.", choices)
		return
	}

	issued, err := pki.IssueIntermediate(pki.IntermediateRequest{
		Subject:    pki.Subject{CN: form.SubjectCN, O: form.SubjectO, OU: form.SubjectOU, L: form.SubjectL, ST: form.SubjectST, C: form.SubjectC},
		Key:        pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams},
		Parent:     parentSigner,
		ParentID:   form.ParentID,
		CRLBaseURL: s.cfg.CRLBaseURL,
		Validity:   time.Duration(form.ValidityDays) * 24 * time.Hour,
	})
	if err != nil {
		s.renderIssueError(w, r, "issue_intermediate", form, state.Token, "Failed to issue: "+err.Error(), choices)
		return
	}
	parentIDCopy := form.ParentID
	id, err := s.persistIssued("intermediate_ca", &parentIDCopy, issued, pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams}, state.Token)
	if err != nil {
		internalServerError(w, "issue-int-post: persist", err)
		return
	}
	hxRedirect(w, r, "/certs/"+id, EventCertsChanged)
}

// ============== leaf ==============

func (s *Server) handleIssueLeafGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	choices, err := s.parentChoicesForLeaf()
	if err != nil {
		internalServerError(w, "issue-leaf-get: parent choices", err)
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "issue-leaf-get: CreateIdemToken", err)
		return
	}
	s.render(w, "issue_leaf", issueViewData{
		CSRFToken:     CSRFToken(r),
		FormToken:     tok,
		FormAction:    "/certs/new/leaf",
		PageTitle:     "issue leaf cert",
		PageHeading:   "Issue leaf certificate",
		KeyAlgo:       defaultLeafKeyAlgo,
		KeyAlgoParams: defaultLeafKeyAlgoParams,
		ValidityDays:  defaultLeafValidityDays,
		ParentID:      r.URL.Query().Get("parent"),
		ParentChoices: choices,
	})
}

func (s *Server) handleIssueLeafPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "issue-leaf-post: ParseForm", err)
		return
	}
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "issue-leaf-post: validateFormToken", err)
		return
	}
	if state == nil {
		staleFormResponse(w)
		return
	}
	if state.Replay {
		hxRedirect(w, r, state.ResultURL)
		return
	}

	form := readIssueForm(r)
	choices, err := s.parentChoicesForLeaf()
	if err != nil {
		internalServerError(w, "issue-leaf-post: parent choices", err)
		return
	}
	if msg := validateCommon(form); msg != "" {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, msg, choices)
		return
	}
	if form.ParentID == "" {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, "Parent CA required.", choices)
		return
	}
	dns := parseSANDNS(form.SANDNS)
	ips, err := parseSANIPs(form.SANIPs)
	if err != nil {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, err.Error(), choices)
		return
	}
	if len(dns) == 0 && len(ips) == 0 {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, "At least one SAN (DNS or IP) is required.", choices)
		return
	}
	parentSigner, _, err := s.loadSigner(form.ParentID)
	if err != nil {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, "Parent CA cannot be used: "+err.Error(), choices)
		return
	}

	issued, err := pki.IssueLeaf(pki.LeafRequest{
		Subject:    pki.Subject{CN: form.SubjectCN, O: form.SubjectO, OU: form.SubjectOU, L: form.SubjectL, ST: form.SubjectST, C: form.SubjectC},
		Key:        pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams},
		Parent:     parentSigner,
		ParentID:   form.ParentID,
		CRLBaseURL: s.cfg.CRLBaseURL,
		SANDNS:     dns,
		SANIPs:     ips,
		Validity:   time.Duration(form.ValidityDays) * 24 * time.Hour,
	})
	if err != nil {
		s.renderIssueError(w, r, "issue_leaf", form, state.Token, "Failed to issue: "+err.Error(), choices)
		return
	}
	parentIDCopy := form.ParentID
	id, err := s.persistIssued("leaf", &parentIDCopy, issued, pki.KeySpec{Algo: pki.KeyAlgo(form.KeyAlgo), Params: form.KeyAlgoParams}, state.Token)
	if err != nil {
		internalServerError(w, "issue-leaf-post: persist", err)
		return
	}
	hxRedirect(w, r, "/certs/"+id, EventCertsChanged)
}

// ============== shared helpers ==============

// readIssueForm pulls all form fields the issue handlers care about into one
// struct. FormAction is set to the request path so error re-renders post
// back to the same handler. Doesn't validate field contents.
func readIssueForm(r *http.Request) issueViewData {
	d := issueViewData{
		FormAction:    r.URL.Path,
		SubjectCN:     strings.TrimSpace(r.PostForm.Get("subject_cn")),
		SubjectO:      strings.TrimSpace(r.PostForm.Get("subject_o")),
		SubjectOU:     strings.TrimSpace(r.PostForm.Get("subject_ou")),
		SubjectL:      strings.TrimSpace(r.PostForm.Get("subject_l")),
		SubjectST:     strings.TrimSpace(r.PostForm.Get("subject_st")),
		SubjectC:      strings.TrimSpace(r.PostForm.Get("subject_c")),
		KeyAlgo:       r.PostForm.Get("key_algo"),
		KeyAlgoParams: r.PostForm.Get("key_algo_params"),
		SANDNS:        r.PostForm.Get("san_dns"),
		SANIPs:        r.PostForm.Get("san_ip"),
		ParentID:      r.PostForm.Get("parent_id"),
	}
	if v := r.PostForm.Get("validity_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d.ValidityDays = n
		}
	}
	return d
}

// validateCommon checks the fields common to all three issue forms. Returns
// "" when the form is acceptable, or a user-facing error message.
func validateCommon(d issueViewData) string {
	if d.SubjectCN == "" {
		return "Common name is required."
	}
	if d.KeyAlgo == "" {
		return "Key algorithm is required."
	}
	if d.ValidityDays <= 0 {
		return "Validity (days) must be a positive integer."
	}
	return ""
}

func parseSANDNS(input string) []string {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, s := range fields {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseSANIPs(input string) ([]net.IP, error) {
	dns := parseSANDNS(input)
	out := make([]net.IP, 0, len(dns))
	for _, s := range dns {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("not a valid IP address: %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

func (s *Server) parentChoicesForIntermediate() ([]parentChoice, error) {
	cas, err := store.ListCAs(s.db)
	if err != nil {
		return nil, err
	}
	out := make([]parentChoice, 0, len(cas))
	for _, c := range cas {
		// Only roots are reasonable parents for an intermediate. Intermediate-
		// of-an-intermediate is technically allowed but uncommon for v1.
		if c.Type != "root_ca" {
			continue
		}
		out = append(out, parentChoice{ID: c.ID, CN: c.SubjectCN, Type: c.Type})
	}
	return out, nil
}

func (s *Server) parentChoicesForLeaf() ([]parentChoice, error) {
	cas, err := store.ListCAs(s.db)
	if err != nil {
		return nil, err
	}
	out := make([]parentChoice, 0, len(cas))
	for _, c := range cas {
		// Both intermediates and roots are allowed (spec recommends
		// intermediate, but doesn't forbid root). Skip non-active CAs.
		if c.Status != "active" {
			continue
		}
		out = append(out, parentChoice{ID: c.ID, CN: c.SubjectCN, Type: c.Type})
	}
	return out, nil
}

// renderIssueError re-renders the named issue template with the form data
// preserved (so the operator doesn't have to re-fill everything) and an
// error message. Sets HTTP 400.
func (s *Server) renderIssueError(w http.ResponseWriter, r *http.Request, name string, form issueViewData, formToken, msg string, choices []parentChoice) {
	form.CSRFToken = CSRFToken(r)
	form.FormToken = formToken
	form.Error = msg
	form.ParentChoices = choices
	w.WriteHeader(http.StatusBadRequest)
	if IsHXRequest(r) {
		s.renderFragment(w, name, "form_fragment", form)
		return
	}
	s.render(w, name, form)
}
