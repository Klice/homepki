package web

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
)

// settingsFixture issues a leaf chain so the rotation has DEKs to rewrap,
// then primes the client with a CSRF token from /settings.
func settingsFixture(t *testing.T) (srv *Server, c *clientLite, leafID string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c = newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID = issueChain(t, c)
	return
}

func TestSettings_GetRendersForm(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv

	w := c.get("/settings")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`name="current"`,
		`name="new"`,
		`name="new2"`,
		`name="form_token"`,
		`action="/settings/passphrase"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestSettings_GetRedirectsWhenLocked(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	srv.keystore.Lock()

	w := c.get("/settings")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestSettings_RotateHappyPath(t *testing.T) {
	srv, c, leafID := settingsFixture(t)

	// Sanity: the leaf's key opens under the current KEK (via the key.pem
	// download which decrypts inline). After rotation the same call must
	// still succeed because the operator's session stays valid AND the
	// rewrap is correct.
	preWrap, err := store.GetCertKey(srv.db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	preCipher := append([]byte(nil), preWrap.Ciphertext...)

	w := c.get("/settings")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings: %d", w.Code)
	}
	formTok := extractFormToken(t, w.Body.String())

	const newPP = "new-passphrase-67890"
	w = c.postForm("/settings/passphrase", url.Values{
		"current":    {validPassphrase},
		"new":        {newPP},
		"new2":       {newPP},
		"form_token": {formTok},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("rotate: %d body=%q", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/settings") {
		t.Errorf("Location: got %q", loc)
	}

	// 1. Keystore still unlocked, but with a new KEK — the operator who
	//    rotated stays logged in (a fresh session cookie was set).
	if !srv.keystore.IsUnlocked() {
		t.Error("keystore should still be unlocked after rotation")
	}

	// 2. The leaf's wrapped_dek was rewrapped (different bytes) but the
	//    inner ciphertext is unchanged.
	postWrap, _ := store.GetCertKey(srv.db, leafID)
	if string(postWrap.WrappedDEK) == string(preWrap.WrappedDEK) {
		t.Error("wrapped_dek unchanged after rotation")
	}
	if string(postWrap.Ciphertext) != string(preCipher) {
		t.Error("ciphertext changed (should be untouched)")
	}

	// 3. End-to-end: the key.pem download still decrypts and PEM-decodes.
	w = c.get("/")
	if w.Code != http.StatusOK {
		t.Fatalf("post-rotate GET /: %d", w.Code)
	}
	w = c.get("/certs/" + leafID + "/key.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("key.pem: %d body=%q", w.Code, w.Body.String())
	}
	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil {
		t.Fatal("key.pem did not PEM-decode after rotation")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("parse pkcs8 after rotation: %v", err)
	}

	// 4. Re-unlock with the NEW passphrase works; with the OLD one fails.
	srv.keystore.Lock()
	c2 := newClient(t, srv)
	c2.get("/unlock") // CSRF cookie
	w = c2.postForm("/unlock", url.Values{"passphrase": {newPP}})
	if w.Code != http.StatusSeeOther {
		t.Errorf("unlock with new passphrase: %d body=%q", w.Code, w.Body.String())
	}
	srv.keystore.Lock()
	c3 := newClient(t, srv)
	c3.get("/unlock")
	w = c3.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("unlock with old passphrase: got %d, want 400", w.Code)
	}
}

func TestSettings_RotateRejectsWrongCurrent(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv

	w := c.get("/settings")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/settings/passphrase", url.Values{
		"current":    {"definitely-not-the-passphrase"},
		"new":        {"good-new-passphrase-12"},
		"new2":       {"good-new-passphrase-12"},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "incorrect") {
		t.Errorf("expected 'incorrect' in body")
	}
}

func TestSettings_RotateRejectsShortNew(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv

	w := c.get("/settings")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/settings/passphrase", url.Values{
		"current":    {validPassphrase},
		"new":        {"short"},
		"new2":       {"short"},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "at least 12 characters") {
		t.Errorf("expected length error in body")
	}
}

func TestSettings_RotateRejectsMismatchedNew(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv

	w := c.get("/settings")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/settings/passphrase", url.Values{
		"current":    {validPassphrase},
		"new":        {"good-new-passphrase-12"},
		"new2":       {"good-new-passphrase-99"},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "do not match") {
		t.Errorf("expected mismatch error in body")
	}
}

func TestSettings_RotateStaleFormToken(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv
	c.get("/settings") // primes csrf cookie

	w := c.postForm("/settings/passphrase", url.Values{
		"current":    {validPassphrase},
		"new":        {"good-new-passphrase-12"},
		"new2":       {"good-new-passphrase-12"},
		"form_token": {"deadbeef-not-a-real-token"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "stale form") {
		t.Errorf("expected stale-form message")
	}
}

func TestSettings_RotateFormTokenReplay(t *testing.T) {
	srv, c, _ := settingsFixture(t)

	w := c.get("/settings")
	formTok := extractFormToken(t, w.Body.String())
	form := url.Values{
		"current":    {validPassphrase},
		"new":        {"good-new-passphrase-12"},
		"new2":       {"good-new-passphrase-12"},
		"form_token": {formTok},
	}
	w = c.postForm("/settings/passphrase", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("first rotate: %d body=%q", w.Code, w.Body.String())
	}
	first := w.Header().Get("Location")

	// Replay: same form_token POSTed again. Per API.md §4.4 it should 303
	// to /settings WITHOUT re-verifying current (which would now fail
	// because the passphrase has changed).
	w = c.postForm("/settings/passphrase", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("replay: %d body=%q", w.Code, w.Body.String())
	}
	if w.Header().Get("Location") != first {
		t.Errorf("replay Location: got %q, want %q", w.Header().Get("Location"), first)
	}
	// Sanity: srv is still unlocked (replay didn't lock us out).
	if !srv.keystore.IsUnlocked() {
		t.Error("keystore should still be unlocked after replay")
	}
}

func TestSettings_RotateRollsBackOnFailure(t *testing.T) {
	// The store-layer test covers the rewrap-rollback path directly. Here
	// we just confirm the handler surfaces the failure path: if the new
	// passphrase is missing the field-level error short-circuits before
	// any rotation runs and the keystore is untouched.
	srv, c, _ := settingsFixture(t)

	w := c.get("/settings")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/settings/passphrase", url.Values{
		"current":    {validPassphrase},
		"new":        {""},
		"new2":       {""},
		"form_token": {formTok},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
	if !srv.keystore.IsUnlocked() {
		t.Error("keystore should remain unlocked after validation failure")
	}
}

// Index page has a Settings link in the header.
func TestIndex_HasSettingsLink(t *testing.T) {
	srv, c, _ := settingsFixture(t)
	_ = srv

	w := c.get("/")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/settings"`) {
		t.Error("index header missing /settings link")
	}
}
