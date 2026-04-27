package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// extractFormToken pulls form_token out of a rendered body, mirroring the
// CSRF extraction in handlers_auth_test.go.
func extractFormToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="form_token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("form_token not found in body:\n%s", body[:min(500, len(body))])
	}
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("form_token closing quote not found")
	}
	return rest[:end]
}

func TestIssueRoot_FullFlow(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	// 1. GET the form, get a form_token.
	w := c.get("/certs/new/root")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /certs/new/root: %d", w.Code)
	}
	formTok := extractFormToken(t, w.Body.String())

	// 2. POST with valid fields → 303 to /certs/{id}.
	form := url.Values{
		"subject_cn":      {"E2E Test Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {formTok},
	}
	w = c.postForm("/certs/new/root", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /certs/new/root: status=%d body=%q", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/certs/") {
		t.Fatalf("Location: got %q, want /certs/...", loc)
	}
	rootID := strings.TrimPrefix(loc, "/certs/")

	// 3. GET / shows the new root in the authorities table.
	w = c.get("/")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "E2E Test Root") {
		t.Errorf("index missing the new root cert")
	}
	if !strings.Contains(w.Body.String(), `href="/certs/`+rootID+`"`) {
		t.Errorf("index missing link to /certs/%s", rootID)
	}

	// 4. GET the detail page.
	w = c.get("/certs/" + rootID)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /certs/%s: %d", rootID, w.Code)
	}
	if !strings.Contains(w.Body.String(), "self-signed") {
		t.Error("root detail missing 'self-signed'")
	}
}

func TestIssueRoot_RejectsMissingCN(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/new/root")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/new/root", url.Values{
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Common name is required") {
		t.Errorf("expected CN error in body")
	}
}

func TestIssueRoot_StaleFormTokenRejected(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	c.get("/certs/new/root") // grab a CSRF cookie + token, but don't use the form_token
	w := c.postForm("/certs/new/root", url.Values{
		"subject_cn":      {"X"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {"deadbeef-not-a-real-token"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "stale form") {
		t.Errorf("expected stale-form message")
	}
}

func TestIssueRoot_FormTokenReplayReturnsSameURL(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/new/root")
	formTok := extractFormToken(t, w.Body.String())
	form := url.Values{
		"subject_cn":      {"Replay Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {formTok},
	}
	w = c.postForm("/certs/new/root", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first POST: %d body=%q", w.Code, w.Body.String())
	}
	firstLoc := w.Header().Get("Location")

	// Replay the same form token — should redirect to the same URL without
	// creating a second cert.
	w = c.postForm("/certs/new/root", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("replay POST: %d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("Location") != firstLoc {
		t.Errorf("replay Location: got %q, want %q", w.Header().Get("Location"), firstLoc)
	}

	// Confirm only one cert was created (check the index).
	w = c.get("/")
	if got := strings.Count(w.Body.String(), "Replay Root"); got != 1 {
		t.Errorf("expected 1 'Replay Root' on index, got %d", got)
	}
}

func TestIssueIntermediate_RequiresParent(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// With no roots in the DB, the intermediate form shows a message and no form.
	w := c.get("/certs/new/intermediate")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No root CAs available") {
		t.Errorf("expected 'No root CAs available' message")
	}
}

func TestIssueChain_RootIntermediateLeaf(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// 1. Issue root.
	rootID := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Chain Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	// 2. Issue intermediate under it.
	interID := mustIssue(t, c, "/certs/new/intermediate", url.Values{
		"parent_id":       {rootID},
		"subject_cn":      {"Chain Intermediate"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"1825"},
	})

	// 3. Issue leaf under intermediate.
	leafID := mustIssue(t, c, "/certs/new/leaf", url.Values{
		"parent_id":       {interID},
		"subject_cn":      {"chain.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"chain.leaf.test"},
		"validity_days":   {"90"},
	})

	// 4. Detail page on leaf shows full chain.
	w := c.get("/certs/" + leafID)
	if w.Code != http.StatusOK {
		t.Fatalf("leaf detail: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Chain Root",
		"Chain Intermediate",
		"chain.leaf.test",
		`href="/certs/` + interID + `"`,
		`href="/certs/` + rootID + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("leaf detail missing %q", want)
		}
	}
}

func TestIssueLeaf_RequiresSAN(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	rootID := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"R"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})

	// Leaf form with no SANs.
	w := c.get("/certs/new/leaf")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/new/leaf", url.Values{
		"parent_id":       {rootID},
		"subject_cn":      {"no.sans"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"90"},
		"form_token":      {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "At least one SAN") {
		t.Errorf("expected SAN error in body")
	}
}

func TestIssueRoot_RedirectsToUnlockWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/certs/new/root")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

// mustIssue runs the GET-then-POST cycle for an issue endpoint and returns
// the new cert's id from the redirect Location.
func mustIssue(t *testing.T, c *clientLite, path string, form url.Values) string {
	t.Helper()
	w := c.get(path)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d body=%q", path, w.Code, w.Body.String())
	}
	form.Set("form_token", extractFormToken(t, w.Body.String()))
	w = c.postForm(path, form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST %s: %d body=%q", path, w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/certs/") {
		t.Fatalf("POST %s Location: %q", path, loc)
	}
	return strings.TrimPrefix(loc, "/certs/")
}
