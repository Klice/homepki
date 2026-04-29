package web

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/deploy"
	"github.com/Klice/homepki/internal/store"
)

// deployFormView is the shared payload for templates/deploy_form.html. The
// new and edit handlers feed it the same shape so the template stays simple;
// fields like ID and FormAction differ between the two flows.
type deployFormView struct {
	CSRFToken string
	FormToken string
	Error     string

	CertID      string
	CertCN      string
	FormAction  string
	PageTitle   string
	PageHeading string

	// TargetID is empty in the create flow.
	TargetID string

	Name         string
	CertPath     string
	KeyPath      string
	ChainPath    string
	Mode         string
	Owner        string
	Group        string
	PostCommand  string
	AutoOnRotate bool
}

// ============== new ==============

func (s *Server) handleDeployNewGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, ok := s.requireLeafCert(w, r)
	if !ok {
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "deploy-new-get: CreateIdemToken", err)
		return
	}
	s.render(w, "deploy_form", deployFormView{
		CSRFToken:   CSRFToken(r),
		FormToken:   tok,
		CertID:      cert.ID,
		CertCN:      cert.SubjectCN,
		FormAction:  "/certs/" + cert.ID + "/deploy/new",
		PageTitle:   "deploy target — " + cert.SubjectCN,
		PageHeading: "New deploy target",
		Mode:        "0640",
	})
}

func (s *Server) handleDeployNewPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "deploy-new-post: ParseForm", err)
		return
	}
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "deploy-new-post: validateFormToken", err)
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

	cert, ok := s.requireLeafCert(w, r)
	if !ok {
		return
	}

	form := readDeployForm(r, cert.ID)
	if msg := validateDeployForm(form); msg != "" {
		s.renderDeployError(w, r, form, state.Token, msg, "/certs/"+cert.ID+"/deploy/new", "New deploy target")
		return
	}

	t := buildTargetFromForm(form)
	t.ID = store.NewDeployTargetID()
	t.CertID = cert.ID

	resultURL := "/certs/" + cert.ID
	if err := store.CreateDeployTargetWithToken(s.db, t, state.Token, resultURL); err != nil {
		// Likely a UNIQUE(cert_id, name) violation. Render inline.
		s.renderDeployError(w, r, form, state.Token, "Failed to save: "+err.Error(),
			"/certs/"+cert.ID+"/deploy/new", "New deploy target")
		return
	}
	http.Redirect(w, r, resultURL, http.StatusSeeOther)
}

// ============== edit ==============

func (s *Server) handleDeployEditGet(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, target, ok := s.requireTarget(w, r)
	if !ok {
		return
	}
	tok, err := store.CreateIdemToken(s.db)
	if err != nil {
		internalServerError(w, "deploy-edit-get: CreateIdemToken", err)
		return
	}
	view := deployFormView{
		CSRFToken:   CSRFToken(r),
		FormToken:   tok,
		CertID:      cert.ID,
		CertCN:      cert.SubjectCN,
		TargetID:    target.ID,
		FormAction:  "/certs/" + cert.ID + "/deploy/" + target.ID + "/edit",
		PageTitle:   "edit deploy target — " + target.Name,
		PageHeading: "Edit deploy target: " + target.Name,
		Name:        target.Name,
		CertPath:    target.CertPath,
		KeyPath:     target.KeyPath,
		Mode:        target.Mode,
	}
	if target.ChainPath != nil {
		view.ChainPath = *target.ChainPath
	}
	if target.Owner != nil {
		view.Owner = *target.Owner
	}
	if target.Group != nil {
		view.Group = *target.Group
	}
	if target.PostCommand != nil {
		view.PostCommand = *target.PostCommand
	}
	view.AutoOnRotate = target.AutoOnRotate
	s.render(w, "deploy_form", view)
}

func (s *Server) handleDeployEditPost(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		internalServerError(w, "deploy-edit-post: ParseForm", err)
		return
	}
	state, err := s.validateFormToken(r.PostForm.Get(formTokenName))
	if err != nil {
		internalServerError(w, "deploy-edit-post: validateFormToken", err)
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

	cert, existing, ok := s.requireTarget(w, r)
	if !ok {
		return
	}

	form := readDeployForm(r, cert.ID)
	form.TargetID = existing.ID
	if msg := validateDeployForm(form); msg != "" {
		s.renderDeployError(w, r, form, state.Token, msg,
			"/certs/"+cert.ID+"/deploy/"+existing.ID+"/edit",
			"Edit deploy target: "+existing.Name)
		return
	}

	t := buildTargetFromForm(form)
	t.ID = existing.ID
	t.CertID = cert.ID

	resultURL := "/certs/" + cert.ID
	if err := store.UpdateDeployTargetWithToken(s.db, t, state.Token, resultURL); err != nil {
		s.renderDeployError(w, r, form, state.Token, "Failed to save: "+err.Error(),
			"/certs/"+cert.ID+"/deploy/"+existing.ID+"/edit",
			"Edit deploy target: "+existing.Name)
		return
	}
	http.Redirect(w, r, resultURL, http.StatusSeeOther)
}

// ============== delete ==============

// handleDeployDelete implements POST /certs/{id}/deploy/{tid}/delete.
// Idempotent per API.md §8.2 / §2.7.2.
func (s *Server) handleDeployDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	id := r.PathValue("id")
	tid := r.PathValue("tid")
	if id == "" || tid == "" {
		http.NotFound(w, r)
		return
	}
	if _, err := store.GetCert(s.db, id); errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		internalServerError(w, "deploy-delete: GetCert", err)
		return
	}
	if err := store.DeleteDeployTarget(s.db, tid, id); err != nil {
		internalServerError(w, "deploy-delete: DeleteDeployTarget", err)
		return
	}
	http.Redirect(w, r, "/certs/"+id, http.StatusSeeOther)
}

// ============== run ==============

// handleDeployRunOne implements POST /certs/{id}/deploy/{tid}/run.
func (s *Server) handleDeployRunOne(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnlocked(w, r) {
		return
	}
	cert, target, ok := s.requireTarget(w, r)
	if !ok {
		return
	}
	bytes, err := s.buildDeployBytes(cert)
	if err != nil {
		internalServerError(w, "deploy-run-one: build bytes", err)
		return
	}
	defer crypto.Zero(bytes.Key)
	s.runAndRecord(r.Context(), cert, []*store.DeployTarget{target}, bytes)
	http.Redirect(w, r, "/certs/"+cert.ID, http.StatusSeeOther)
}

// handleDeployRunAll implements POST /certs/{id}/deploy.
// Runs every target attached to the cert sequentially. Per-target failures
// don't abort the rest, and the response is always 303 → detail per API.md
// §8.3.
func (s *Server) handleDeployRunAll(w http.ResponseWriter, r *http.Request) {
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
		internalServerError(w, "deploy-run-all: GetCert", err)
		return
	}
	if cert.Type != "leaf" {
		http.NotFound(w, r)
		return
	}
	targets, err := store.ListDeployTargets(s.db, cert.ID)
	if err != nil {
		internalServerError(w, "deploy-run-all: ListDeployTargets", err)
		return
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/certs/"+cert.ID, http.StatusSeeOther)
		return
	}
	bytes, err := s.buildDeployBytes(cert)
	if err != nil {
		internalServerError(w, "deploy-run-all: build bytes", err)
		return
	}
	defer crypto.Zero(bytes.Key)
	s.runAndRecord(r.Context(), cert, targets, bytes)
	http.Redirect(w, r, "/certs/"+cert.ID, http.StatusSeeOther)
}

// ============== auto-on-rotate hook ==============

// runAutoOnRotateTargets is invoked by the rotate handler after the rotation
// transaction commits. Looks up every target with auto_on_rotate=1 and runs
// it against the new cert. Per-target failures do NOT roll back the rotation
// (LIFECYCLE.md §4.4) — they're recorded on the target row and surfaced via
// the cert detail page.
func (s *Server) runAutoOnRotateTargets(r *http.Request, newCert *store.Cert) {
	if newCert.Type != "leaf" {
		return // only leaves have deploy targets
	}
	targets, err := store.ListDeployTargets(s.db, newCert.ID)
	if err != nil {
		slog.Warn("auto-on-rotate: ListDeployTargets failed", "cert", newCert.ID, "err", err)
		return
	}
	auto := make([]*store.DeployTarget, 0, len(targets))
	for _, t := range targets {
		if t.AutoOnRotate {
			auto = append(auto, t)
		}
	}
	if len(auto) == 0 {
		return
	}
	bytes, err := s.buildDeployBytes(newCert)
	if err != nil {
		slog.Warn("auto-on-rotate: build bytes failed", "cert", newCert.ID, "err", err)
		return
	}
	defer crypto.Zero(bytes.Key)
	s.runAndRecord(r.Context(), newCert, auto, bytes)
}

// ============== shared helpers ==============

// requireLeafCert resolves {id} → cert and 404s for non-leaves. Deploy
// targets only attach to leaves per STORAGE.md §5.6.
func (s *Server) requireLeafCert(w http.ResponseWriter, r *http.Request) (*store.Cert, bool) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return nil, false
	}
	cert, err := store.GetCert(s.db, id)
	if errors.Is(err, store.ErrCertNotFound) {
		http.NotFound(w, r)
		return nil, false
	}
	if err != nil {
		internalServerError(w, "deploy: GetCert", err)
		return nil, false
	}
	if cert.Type != "leaf" {
		http.NotFound(w, r)
		return nil, false
	}
	return cert, true
}

// requireTarget resolves {id} + {tid} → (cert, target). 404s if either
// doesn't exist or the target is attached to a different cert.
func (s *Server) requireTarget(w http.ResponseWriter, r *http.Request) (*store.Cert, *store.DeployTarget, bool) {
	cert, ok := s.requireLeafCert(w, r)
	if !ok {
		return nil, nil, false
	}
	tid := r.PathValue("tid")
	if tid == "" {
		http.NotFound(w, r)
		return nil, nil, false
	}
	t, err := store.GetDeployTarget(s.db, tid)
	if errors.Is(err, store.ErrDeployTargetNotFound) {
		http.NotFound(w, r)
		return nil, nil, false
	}
	if err != nil {
		internalServerError(w, "deploy: GetDeployTarget", err)
		return nil, nil, false
	}
	if t.CertID != cert.ID {
		http.NotFound(w, r)
		return nil, nil, false
	}
	return cert, t, true
}

// buildDeployBytes assembles the cert / key / fullchain PEM blocks the runner
// writes to disk. Caller is responsible for zeroing the returned Key slice.
func (s *Server) buildDeployBytes(cert *store.Cert) (deploy.Bytes, error) {
	chainCerts, err := store.GetChain(s.db, cert.ID)
	if err != nil {
		return deploy.Bytes{}, err
	}
	pkcs8, err := s.loadPKCS8(cert.ID)
	if err != nil {
		return deploy.Bytes{}, err
	}
	if _, err := x509.ParsePKCS8PrivateKey(pkcs8); err != nil {
		// Surface a clearer error than the runner would for the operator.
		crypto.Zero(pkcs8)
		return deploy.Bytes{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: pkcs8})
	crypto.Zero(pkcs8)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: cert.DERCert})
	var fullchain []byte
	fullchain = append(fullchain, certPEM...)
	for _, c := range chainAboveExcludingRoot(chainCerts) {
		fullchain = append(fullchain, pem.EncodeToMemory(&pem.Block{Type: pemBlockCertificate, Bytes: c.DERCert})...)
	}
	return deploy.Bytes{Cert: certPEM, Key: keyPEM, FullChain: fullchain}, nil
}

// runAndRecord runs every supplied target against bytes and persists each
// outcome via store.RecordDeployRun. Errors from RecordDeployRun are logged
// but don't abort the loop — the operator still wants the other targets to
// run.
func (s *Server) runAndRecord(ctx context.Context, cert *store.Cert, targets []*store.DeployTarget, b deploy.Bytes) {
	now := time.Now().UTC()
	for _, t := range targets {
		res := deploy.Run(ctx, t, b)
		if err := store.RecordDeployRun(s.db, t.ID, res.Status, cert.SerialNumber, res.Err, now); err != nil {
			slog.Warn("RecordDeployRun failed", "target", t.ID, "err", err)
		}
		if res.Status != store.DeployStatusOK {
			slog.Warn("deploy target failed", "target", t.ID, "name", t.Name, "err", res.Err)
		}
	}
}

// readDeployForm pulls every editable field out of the request.
func readDeployForm(r *http.Request, certID string) deployFormView {
	return deployFormView{
		CertID:       certID,
		Name:         strings.TrimSpace(r.PostForm.Get("name")),
		CertPath:     strings.TrimSpace(r.PostForm.Get("cert_path")),
		KeyPath:      strings.TrimSpace(r.PostForm.Get("key_path")),
		ChainPath:    strings.TrimSpace(r.PostForm.Get("chain_path")),
		Mode:         strings.TrimSpace(r.PostForm.Get("mode")),
		Owner:        strings.TrimSpace(r.PostForm.Get("owner")),
		Group:        strings.TrimSpace(r.PostForm.Get("group")),
		PostCommand:  strings.TrimSpace(r.PostForm.Get("post_command")),
		AutoOnRotate: r.PostForm.Get("auto_on_rotate") == "1",
	}
}

// validateDeployForm enforces API.md §8.1: name + paths required, paths
// absolute, mode parses as octal. Empty string return = OK.
func validateDeployForm(d deployFormView) string {
	if d.Name == "" {
		return "Name is required."
	}
	if d.CertPath == "" || d.KeyPath == "" {
		return "Cert path and key path are both required."
	}
	if !filepath.IsAbs(d.CertPath) {
		return "Cert path must be absolute."
	}
	if !filepath.IsAbs(d.KeyPath) {
		return "Key path must be absolute."
	}
	if d.ChainPath != "" && !filepath.IsAbs(d.ChainPath) {
		return "Chain path must be absolute."
	}
	if d.Mode == "" {
		return "Mode is required (e.g. 0640)."
	}
	if _, err := strconv.ParseUint(d.Mode, 8, 32); err != nil {
		return "Mode must be octal like 0640."
	}
	return ""
}

func buildTargetFromForm(d deployFormView) *store.DeployTarget {
	t := &store.DeployTarget{
		Name:         d.Name,
		CertPath:     d.CertPath,
		KeyPath:      d.KeyPath,
		Mode:         d.Mode,
		AutoOnRotate: d.AutoOnRotate,
	}
	if d.ChainPath != "" {
		v := d.ChainPath
		t.ChainPath = &v
	}
	if d.Owner != "" {
		v := d.Owner
		t.Owner = &v
	}
	if d.Group != "" {
		v := d.Group
		t.Group = &v
	}
	if d.PostCommand != "" {
		v := d.PostCommand
		t.PostCommand = &v
	}
	return t
}

func (s *Server) renderDeployError(w http.ResponseWriter, r *http.Request, form deployFormView, formToken, msg, action, heading string) {
	form.CSRFToken = CSRFToken(r)
	form.FormToken = formToken
	form.Error = msg
	form.FormAction = action
	form.PageHeading = heading
	if form.PageTitle == "" {
		form.PageTitle = heading
	}
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "deploy_form", form)
}
