package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hxGet mirrors clientLite.get but stamps HX-Request: true so handlers
// take the htmx branch. Used by the §10 tests to exercise both halves
// of the IsHXRequest split at the same URL.
func (c *clientLite) hxGet(target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set(hdrHXRequest, "true")
	return c.do(req)
}

// hxPostForm is the htmx-flagged version of clientLite.postForm.
func (c *clientLite) hxPostForm(target string, form url.Values) *httptest.ResponseRecorder {
	form.Set(csrfFormField, c.csrfTok)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(hdrHXRequest, "true")
	return c.do(req)
}

// ============== unit: IsHXRequest / SetHXTrigger ==============

func TestIsHXRequest(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"missing header", "", false},
		{"true literal", "true", true},
		{"any other value", "yes", false},
		{"capitalised true", "True", false}, // htmx itself only sends lowercase "true"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.val != "" {
				r.Header.Set(hdrHXRequest, tc.val)
			}
			assert.Equal(t, tc.want, IsHXRequest(r))
		})
	}
}

func TestSetHXTrigger_AppendsEvents(t *testing.T) {
	w := httptest.NewRecorder()
	SetHXTrigger(w, EventCertsChanged)
	assert.Equal(t, "certs:changed", w.Header().Get(hdrHXTrigger))

	// A second call merges into the existing header rather than
	// clobbering — so a handler can fire two events without coordinating.
	SetHXTrigger(w, EventDeployRan)
	assert.Equal(t, "certs:changed,deploy:ran", w.Header().Get(hdrHXTrigger))
}

func TestSetHXTrigger_NoEventsIsNoop(t *testing.T) {
	w := httptest.NewRecorder()
	SetHXTrigger(w)
	assert.Empty(t, w.Header().Get(hdrHXTrigger))
}

// ============== unit: hxRedirect ==============

func TestHXRedirect_NonHTMX_FallsBackToSeeOther(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	hxRedirect(w, r, "/done")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/done", w.Header().Get("Location"))
	assert.Empty(t, w.Header().Get(hdrHXRedirect))
}

func TestHXRedirect_HTMX_SetsHXRedirectAndOK(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(hdrHXRequest, "true")
	hxRedirect(w, r, "/done", EventCertsChanged)
	assert.Equal(t, http.StatusOK, w.Code, "htmx flow uses 200 + HX-Redirect, not 303")
	assert.Equal(t, "/done", w.Header().Get(hdrHXRedirect))
	assert.Empty(t, w.Header().Get("Location"), "Location belongs to 30x flow only")
	assert.Equal(t, "certs:changed", w.Header().Get(hdrHXTrigger))
}

// ============== integration: index filter fragment ==============

func TestIndex_HTMX_RendersFragmentOnly(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.hxGet("/?status=active")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Fragment must omit the layout chrome — no <html>, no header.
	assert.NotContains(t, body, "<html")
	assert.NotContains(t, body, `<header class="app">`)
	// And must NOT contain the filter form — that lives outside the
	// swap region so the search input keeps focus across swaps.
	assert.NotContains(t, body, `name="q"`,
		"the form must stay outside the swap target so input focus is preserved")
	// But must contain the section heads (the actual swappable content).
	assert.Contains(t, body, "Authorities")
	assert.Contains(t, body, "Leaf certificates")
}

func TestIndex_NonHTMX_RendersFullPage(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "<html")
	assert.Contains(t, body, `id="index-fragment"`,
		"the wrapper div (htmx swap target) is part of the layout-rendered page")
	assert.Contains(t, body, `name="q"`,
		"filter form is rendered above the fragment on the full page")
}

// ============== integration: issue form fragment ==============

func TestIssueRoot_HTMX_ValidationErrorRendersFragment(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// Prime form_token via GET, then submit with an empty CN to force a
	// validation error.
	w := c.get("/certs/new/root")
	require.Equal(t, http.StatusOK, w.Code)
	form := url.Values{
		"subject_cn":      {""},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {extractFormToken(t, w.Body.String())},
	}
	resp := c.hxPostForm("/certs/new/root", form)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	body := resp.Body.String()
	assert.NotContains(t, body, "<html",
		"htmx error response must be a fragment, not a full page")
	assert.Contains(t, body, `id="issue-form"`,
		"fragment must be the swap target so htmx replaces just the form")
	assert.Contains(t, body, "Common name is required",
		"the original error text must surface")
}

func TestIssueRoot_HTMX_SuccessSetsHXRedirectAndCertsChanged(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	w := c.get("/certs/new/root")
	require.Equal(t, http.StatusOK, w.Code)
	form := url.Values{
		"subject_cn":      {"Test Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
		"form_token":      {extractFormToken(t, w.Body.String())},
	}
	resp := c.hxPostForm("/certs/new/root", form)
	require.Equal(t, http.StatusOK, resp.Code, "htmx success uses 200 + HX-Redirect")
	loc := resp.Header().Get(hdrHXRedirect)
	require.True(t, strings.HasPrefix(loc, "/certs/"), "HX-Redirect: %q", loc)
	assert.Equal(t, "certs:changed", resp.Header().Get(hdrHXTrigger))
	assert.Empty(t, resp.Header().Get("Location"),
		"Location is for 30x — htmx flow uses HX-Redirect instead")
}

func TestIssueRoot_NonHTMX_StillRedirects303(t *testing.T) {
	// Sanity: non-htmx callers must keep getting 303s. The htmx changes
	// are purely additive at the same URL.
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	id := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Plain Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})
	require.NotEmpty(t, id)
}

// ============== integration: revoke trigger ==============

func TestRevoke_HTMX_EmitsCertsChanged(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	rootID := mustIssue(t, c, "/certs/new/root", url.Values{
		"subject_cn":      {"Revoke Test Root"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"validity_days":   {"3650"},
	})
	resp := c.hxPostForm("/certs/"+rootID+"/revoke", url.Values{"reason": {"4"}})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "/certs/"+rootID, resp.Header().Get(hdrHXRedirect))
	assert.Equal(t, "certs:changed", resp.Header().Get(hdrHXTrigger))
	_ = srv
}

// ============== integration: deploy fragment ==============

func TestDeployRun_HTMX_RendersFragmentAndEmitsDeployRan(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"hxrun"},
		"cert_path": {filepath.Join(dir, "out.crt")},
		"key_path":  {filepath.Join(dir, "out.key")},
	})

	resp := c.hxPostForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	require.Equal(t, http.StatusOK, resp.Code, "body=%q", resp.Body.String())
	body := resp.Body.String()
	// Fragment, not full page.
	assert.NotContains(t, body, "<html")
	assert.Contains(t, body, `id="deploy-targets"`,
		"htmx run response must be the swappable section, not a redirect")
	assert.Equal(t, "deploy:ran", resp.Header().Get(hdrHXTrigger))
}

func TestDeployDelete_HTMX_RendersFragment(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"hxdel"},
		"cert_path": {filepath.Join(dir, "out.crt")},
		"key_path":  {filepath.Join(dir, "out.key")},
	})

	resp := c.hxPostForm("/certs/"+leafID+"/deploy/"+tid+"/delete", url.Values{})
	require.Equal(t, http.StatusOK, resp.Code)
	body := resp.Body.String()
	assert.NotContains(t, body, "<html")
	assert.Contains(t, body, `id="deploy-targets"`)
}
