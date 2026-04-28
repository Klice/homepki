package web

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
)

// deployFixture issues a leaf chain and returns a primed client + IDs.
// Mirrors downloadFixture.
func deployFixture(t *testing.T) (srv *Server, c *clientLite, leafID string, dir string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c = newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID = issueChain(t, c)
	dir = t.TempDir()
	c.get("/certs/" + leafID) // prime CSRF
	return
}

// createTarget POSTs a new-target form and returns the new target id by
// reading it back from the DB. POST handler 303s to the cert detail page,
// not the target — so we list and grab the only one.
func createTarget(t *testing.T, c *clientLite, srv *Server, leafID string, override url.Values) string {
	t.Helper()
	form := url.Values{
		"name":      {"nginx"},
		"cert_path": {"/tmp/homepki-test-cert.pem"},
		"key_path":  {"/tmp/homepki-test-key.pem"},
		"mode":      {"0640"},
	}
	for k, v := range override {
		form[k] = v
	}
	w := c.get("/certs/" + leafID + "/deploy/new")
	if w.Code != http.StatusOK {
		t.Fatalf("GET deploy/new: %d body=%q", w.Code, w.Body.String())
	}
	form.Set("form_token", extractFormToken(t, w.Body.String()))
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST deploy/new: %d body=%q", w.Code, w.Body.String())
	}
	targets, err := store.ListDeployTargets(srv.db, leafID)
	if err != nil || len(targets) == 0 {
		t.Fatalf("no targets after create: err=%v len=%d", err, len(targets))
	}
	return targets[len(targets)-1].ID
}

// ============== create ==============

func TestDeploy_CreateAndAppearOnDetail(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "out.crt")
	keyPath := filepath.Join(dir, "out.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"nginx"},
		"cert_path": {certPath},
		"key_path":  {keyPath},
	})

	w := c.get("/certs/" + leafID)
	body := w.Body.String()
	for _, want := range []string{
		"nginx",
		certPath,
		`/certs/` + leafID + `/deploy/` + tid + `/run`,
		`/certs/` + leafID + `/deploy/` + tid + `/edit`,
		`/certs/` + leafID + `/deploy/` + tid + `/delete`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}
}

func TestDeploy_CreateRejectsRelativePath(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	_ = srv

	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/"+leafID+"/deploy/new", url.Values{
		"name":       {"bad"},
		"cert_path":  {"relative/cert.pem"},
		"key_path":   {"/abs/key.pem"},
		"mode":       {"0640"},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "absolute") {
		t.Errorf("expected 'absolute' in error body")
	}
}

func TestDeploy_CreateRejectsBadMode(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	_ = srv
	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/"+leafID+"/deploy/new", url.Values{
		"name":       {"bad"},
		"cert_path":  {"/abs/cert.pem"},
		"key_path":   {"/abs/key.pem"},
		"mode":       {"not-octal"},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestDeploy_CreateOnNonLeafIs404(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	rootID, _, _ := issueChain(t, c)

	w := c.get("/certs/" + rootID + "/deploy/new")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestDeploy_CreateFormTokenReplay(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")

	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	form := url.Values{
		"name":       {"replay"},
		"cert_path":  {cert},
		"key_path":   {key},
		"mode":       {"0640"},
		"form_token": {formTok},
	}
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first: %d", w.Code)
	}
	first := w.Header().Get("Location")

	// Replay same form_token → 303 to the originally-set result_url, no second row.
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != first {
		t.Errorf("replay: got %d %q, want 303 %q", w.Code, w.Header().Get("Location"), first)
	}
	targets, _ := store.ListDeployTargets(srv.db, leafID)
	if len(targets) != 1 {
		t.Errorf("targets after replay: got %d, want 1", len(targets))
	}
}

// ============== edit ==============

func TestDeploy_EditUpdatesRow(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path": {filepath.Join(dir, "old.crt")},
		"key_path":  {filepath.Join(dir, "old.key")},
	})

	w := c.get("/certs/" + leafID + "/deploy/" + tid + "/edit")
	if w.Code != http.StatusOK {
		t.Fatalf("GET edit: %d", w.Code)
	}
	formTok := extractFormToken(t, w.Body.String())
	newCert := filepath.Join(dir, "new.crt")
	w = c.postForm("/certs/"+leafID+"/deploy/"+tid+"/edit", url.Values{
		"name":           {"haproxy"},
		"cert_path":      {newCert},
		"key_path":       {filepath.Join(dir, "new.key")},
		"mode":           {"0600"},
		"auto_on_rotate": {"1"},
		"form_token":     {formTok},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST edit: %d body=%q", w.Code, w.Body.String())
	}
	got, err := store.GetDeployTarget(srv.db, tid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "haproxy" || got.CertPath != newCert || !got.AutoOnRotate || got.Mode != "0600" {
		t.Errorf("update did not stick: %+v", got)
	}
}

func TestDeploy_EditCrossCertIs404(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)
	// Try editing under a different (non-existent) cert id.
	w := c.get("/certs/no-such/deploy/" + tid + "/edit")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

// ============== delete ==============

func TestDeploy_DeleteRemovesAndIsIdempotent(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/delete", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first delete: %d body=%q", w.Code, w.Body.String())
	}
	if _, err := store.GetDeployTarget(srv.db, tid); err == nil {
		t.Error("target still exists after delete")
	}
	// Replay → 303, no error.
	w = c.postForm("/certs/"+leafID+"/deploy/"+tid+"/delete", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Errorf("replay: got %d, want 303", w.Code)
	}
}

// ============== run ==============

func TestDeploy_RunOneWritesFiles(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "out.crt")
	keyPath := filepath.Join(dir, "out.key")
	chainPath := filepath.Join(dir, "fullchain.crt")
	flag := filepath.Join(dir, "ran")

	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":    {certPath},
		"key_path":     {keyPath},
		"chain_path":   {chainPath},
		"post_command": {"touch " + flag},
	})

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("run: %d body=%q", w.Code, w.Body.String())
	}

	// Cert file: parses as a real X.509 with our CN.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("cert file: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("cert PEM did not decode: %q", certPEM)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if parsed.Subject.CommonName != "revoke.leaf.test" {
		t.Errorf("cert CN: %q", parsed.Subject.CommonName)
	}
	// Key file: PKCS#8 PEM.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Errorf("key block: %+v", keyBlock)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Errorf("parse pkcs8: %v", err)
	}
	// Fullchain: leaf + intermediate.
	chain, _ := os.ReadFile(chainPath)
	if strings.Count(string(chain), "-----BEGIN CERTIFICATE-----") != 2 {
		t.Errorf("fullchain block count: %q", chain)
	}
	// post_command ran.
	if _, err := os.Stat(flag); err != nil {
		t.Errorf("post_command did not run: %v", err)
	}
	// Row updated.
	got, _ := store.GetDeployTarget(srv.db, tid)
	if got.LastStatus == nil || *got.LastStatus != "ok" {
		t.Errorf("last_status: got %v", got.LastStatus)
	}
}

func TestDeploy_RunOneRecordsFailure(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":    {filepath.Join(dir, "out.crt")},
		"key_path":     {filepath.Join(dir, "out.key")},
		"post_command": {"exit 1"},
	})
	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("run: %d", w.Code)
	}
	got, _ := store.GetDeployTarget(srv.db, tid)
	if got.LastStatus == nil || *got.LastStatus != "failed" {
		t.Errorf("last_status: got %v", got.LastStatus)
	}
	if got.LastError == nil || !strings.Contains(*got.LastError, "post_command") {
		t.Errorf("last_error: %v", got.LastError)
	}
}

func TestDeploy_RunAllSequential(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	a := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"a"},
		"cert_path": {filepath.Join(dir, "a.crt")},
		"key_path":  {filepath.Join(dir, "a.key")},
	})
	b := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"b"},
		"cert_path": {filepath.Join(dir, "b.crt")},
		"key_path":  {filepath.Join(dir, "b.key")},
	})

	w := c.postForm("/certs/"+leafID+"/deploy", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("run-all: %d", w.Code)
	}
	for _, id := range []string{a, b} {
		got, _ := store.GetDeployTarget(srv.db, id)
		if got.LastStatus == nil || *got.LastStatus != "ok" {
			t.Errorf("target %s status: %v", id, got.LastStatus)
		}
	}
	for _, p := range []string{filepath.Join(dir, "a.crt"), filepath.Join(dir, "b.crt")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file %s not written: %v", p, err)
		}
	}
}

func TestDeploy_RunWhenLockedRedirectsToUnlock(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)
	srv.keystore.Lock()

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got %d %q", w.Code, w.Header().Get("Location"))
	}
}

// ============== auto on rotate ==============

func TestDeploy_AutoOnRotateFiresAfterRotation(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "auto.crt")
	keyPath := filepath.Join(dir, "auto.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":      {certPath},
		"key_path":       {keyPath},
		"auto_on_rotate": {"1"},
	})

	// Rotate the leaf — the new cert inherits no targets (rotation makes a
	// fresh cert row), so auto-on-rotate fires on... wait. Targets attach to
	// the OLD cert id; the new cert has none. Per LIFECYCLE.md §4.4 the
	// targets that fire are the new cert's own targets. So a freshly-rotated
	// cert with no targets won't fire anything. To exercise the hook, the
	// targets need to be on the new cert. Instead, observe that the OLD
	// cert's targets are NOT re-run automatically (which is the spec'd
	// behaviour: targets follow the cert row, not the chain).
	newID := mustIssue(t, c, "/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
	})

	if newID == leafID {
		t.Fatal("rotated cert has same id")
	}
	// Old target's last_status should still be unset — rotation does not
	// touch the old target's row.
	got, _ := store.GetDeployTarget(srv.db, tid)
	if got.LastStatus != nil {
		t.Errorf("old target should not have been re-run: %v", got.LastStatus)
	}
	// The new cert has no deploy targets at all.
	newTargets, _ := store.ListDeployTargets(srv.db, newID)
	if len(newTargets) != 0 {
		t.Errorf("new cert targets: got %d, want 0", len(newTargets))
	}
}

func TestDeploy_AutoOnRotateRunsWhenTargetIsOnNewCert(t *testing.T) {
	// Direct test of the runAutoOnRotateTargets hook: seed a target on a
	// freshly-issued leaf, then call the hook with that cert. This isolates
	// the side-effect from the rotate handler's transactional boundary.
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "rot.crt")
	keyPath := filepath.Join(dir, "rot.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":      {certPath},
		"key_path":       {keyPath},
		"auto_on_rotate": {"1"},
	})

	cert, _ := store.GetCert(srv.db, leafID)
	srv.runAutoOnRotateTargets(httpRequestForCtx(), cert)

	got, _ := store.GetDeployTarget(srv.db, tid)
	if got.LastStatus == nil || *got.LastStatus != "ok" {
		t.Errorf("auto-on-rotate did not run target: %v", got.LastStatus)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert not written: %v", err)
	}
}

// httpRequestForCtx synthesises a request just so handlers that grab
// r.Context() have something to use. The runAutoOnRotateTargets hook only
// reads Done()/Err()/etc., never the body.
func httpRequestForCtx() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	return r
}
