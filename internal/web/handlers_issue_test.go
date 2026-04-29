package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extractFormToken pulls form_token out of a rendered body, mirroring the
// CSRF extraction in handlers_auth_test.go.
func extractFormToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="form_token" value="`
	i := strings.Index(body, marker)
	require.GreaterOrEqual(t, i, 0, "form_token not found in body:\n%s", body[:min(500, len(body))])
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	require.GreaterOrEqual(t, end, 0, "form_token closing quote not found")
	return rest[:end]
}

func TestIssueRoot_FullFlow(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	installSession(t, srv, c)

	// 1. GET the form, get a form_token.
	w := c.get("/certs/new/root")
	require.Equal(t, http.StatusOK, w.Code, "GET /certs/new/root")
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
	require.Equal(t, http.StatusSeeOther, w.Code, "POST /certs/new/root")
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "/certs/"), "Location: got %q, want /certs/...", loc)
	rootID := strings.TrimPrefix(loc, "/certs/")

	// 3. GET / shows the new root in the authorities table.
	w = c.get("/")
	require.Equal(t, http.StatusOK, w.Code, "GET /")
	assert.Contains(t, w.Body.String(), "E2E Test Root", "index missing the new root cert")
	assert.Contains(t, w.Body.String(), `href="/certs/`+rootID+`"`, "index missing link to /certs/%s", rootID)

	// 4. GET the detail page.
	w = c.get("/certs/" + rootID)
	require.Equal(t, http.StatusOK, w.Code, "GET /certs/%s", rootID)
	assert.Contains(t, w.Body.String(), "self-signed", "root detail missing 'self-signed'")
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
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Common name is required")
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
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "stale form")
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
	require.Equal(t, http.StatusSeeOther, w.Code, "first POST")
	firstLoc := w.Header().Get("Location")

	// Replay the same form token — should redirect to the same URL without
	// creating a second cert.
	w = c.postForm("/certs/new/root", form)
	require.Equal(t, http.StatusSeeOther, w.Code, "replay POST")
	assert.Equal(t, firstLoc, w.Header().Get("Location"), "replay Location")

	// Confirm only one cert was created (check the index).
	w = c.get("/")
	assert.Equal(t, 1, strings.Count(w.Body.String(), "Replay Root"), "expected 1 'Replay Root' on index")
}

func TestIssueIntermediate_RequiresParent(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// With no roots in the DB, the intermediate form shows a message and no form.
	w := c.get("/certs/new/intermediate")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "No root CAs available")
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
	require.Equal(t, http.StatusOK, w.Code, "leaf detail")
	body := w.Body.String()
	for _, want := range []string{
		"Chain Root",
		"Chain Intermediate",
		"chain.leaf.test",
		`href="/certs/` + interID + `"`,
		`href="/certs/` + rootID + `"`,
	} {
		assert.Contains(t, body, want)
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
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "At least one SAN")
}

func TestIssueRoot_RedirectsToUnlockWhenLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/certs/new/root")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

// mustIssue runs the GET-then-POST cycle for an issue endpoint and returns
// the new cert's id from the redirect Location.
func mustIssue(t *testing.T, c *clientLite, path string, form url.Values) string {
	t.Helper()
	w := c.get(path)
	require.Equal(t, http.StatusOK, w.Code, "GET %s", path)
	form.Set("form_token", extractFormToken(t, w.Body.String()))
	w = c.postForm(path, form)
	require.Equal(t, http.StatusSeeOther, w.Code, "POST %s", path)
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "/certs/"), "POST %s Location: %q", path, loc)
	return strings.TrimPrefix(loc, "/certs/")
}
