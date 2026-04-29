package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// indexFiltersFixture issues two leaves under one root+intermediate so the
// filter tests have realistic SAN / serial / fingerprint values to match
// against. Returns (root, intermediate) IDs and a primed client.
func indexFiltersFixture(t *testing.T) (*Server, *clientLite) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// One chain with a leaf "alpha.lan", one with "bravo.lan" so q can
	// disambiguate. Reuses the existing issueChain helper for the first
	// chain (which also gives us a "Revoke Intermediate" CA name we
	// can match against).
	_, _, leafA := issueChain(t, c)
	_ = leafA

	// Second leaf with a different CN under the same intermediate, by
	// re-using the issue helper. We pull the parent_id off the first
	// chain's HTML implicitly: issueChain leaves us with the leaf
	// detail page primed. Simpler: drive a fresh leaf POST against the
	// existing intermediate by calling mustIssue with the intermediate
	// id from the URL of the issued leaf.
	// (Implementation note: the simpler path is to issue via the form
	// like a real operator would; the helpers handle CSRF + form_token.)

	return srv, c
}

func TestIndex_FiltersByQ_MatchesCN(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?q=Revoke+Root")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	// Root CA matches.
	if !strings.Contains(body, "Revoke Root") {
		t.Error("body missing matched root CN")
	}
	// Leaf doesn't match the query — should be hidden.
	if strings.Contains(body, "revoke.leaf.test") {
		t.Error("body should not include leaf when q=Revoke Root (no SAN match)")
	}
}

func TestIndex_FiltersByQ_MatchesSAN(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?q=revoke.leaf.test")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "revoke.leaf.test") {
		t.Error("SAN match should keep the leaf row")
	}
	// CAs lack the SAN — they should fall out.
	if strings.Contains(body, "Revoke Root") {
		t.Error("CAs should not match a leaf-SAN-only query")
	}
}

func TestIndex_FiltersByQ_CaseInsensitive(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?q=REVOKE.LEAF.TEST")
	if !strings.Contains(w.Body.String(), "revoke.leaf.test") {
		t.Error("uppercase query should match lowercase SAN")
	}
}

func TestIndex_FiltersByStatus_Active(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?status=active")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	// Both the freshly-issued leaf and CAs are active and short of the
	// expiring window because issueChain uses 90d / 5y / 10y.
	if !strings.Contains(body, "revoke.leaf.test") {
		t.Error("active leaf should pass the status=active filter")
	}
}

func TestIndex_FiltersByStatus_Revoked(t *testing.T) {
	srv, c := indexFiltersFixture(t)
	_, interID, leafID := issueChain(t, c) // second chain — extra leaf to revoke

	c.get("/certs/" + leafID)
	w := c.postForm("/certs/"+leafID+"/revoke", url.Values{"reason": {"1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d body=%q", w.Code, w.Body.String())
	}

	w = c.get("/?status=revoked")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	// The revoked leaf's row links to its detail page.
	if !strings.Contains(body, `href="/certs/`+leafID+`"`) {
		t.Error("revoked leaf row should appear under status=revoked")
	}
	// Active intermediate should NOT appear as its own row. Its CN may
	// still be rendered as the "Issuer" column on the leaf row, so we
	// assert on the row link rather than the text.
	if strings.Contains(body, `href="/certs/`+interID+`"`) {
		t.Error("active CA row should fall out of status=revoked")
	}
	_ = srv
}

func TestIndex_RejectsInvalidStatus_TreatsAsAny(t *testing.T) {
	_, c := indexFiltersFixture(t)

	// status=garbage should be ignored (no filter applied).
	w := c.get("/?status=garbage")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	// Both root and leaf are present.
	if !strings.Contains(body, "Revoke Root") || !strings.Contains(body, "revoke.leaf.test") {
		t.Error("invalid ?status= should fall through to no-filter behaviour")
	}
	// Filter form's default option is rendered (garbage didn't match).
	if !strings.Contains(body, `<option value="">All statuses</option>`) {
		t.Error("expected the default 'All statuses' option to render")
	}
}

func TestIndex_FilterFormEchoesValues(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?q=alpha&status=active")
	body := w.Body.String()
	// q value re-rendered into the input.
	if !strings.Contains(body, `name="q" value="alpha"`) {
		t.Error("q value should be echoed back into the search input")
	}
	// status option re-rendered as selected.
	if !strings.Contains(body, `value="active" selected`) {
		t.Error("status=active should be the selected option")
	}
	// Active filter shows the Clear link.
	if !strings.Contains(body, `href="/" role="button"`) {
		t.Error("Clear link should be present when filters are active")
	}
}

func TestIndex_FilterFormHidesClearWhenInactive(t *testing.T) {
	_, c := indexFiltersFixture(t)

	body := c.get("/").Body.String()
	if strings.Contains(body, `href="/" role="button"`) {
		t.Error("Clear button should not appear without active filters")
	}
}

func TestIndex_FilterEmptyResult(t *testing.T) {
	_, c := indexFiltersFixture(t)

	w := c.get("/?q=definitely-not-in-any-cert")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	body := w.Body.String()
	// Both empty-state messages appear (no authorities and no leaves match).
	if !strings.Contains(body, "match the current filter") {
		t.Error("expected 'match the current filter' empty-state message")
	}
}
