package web

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// testServer returns a Server backed by a fresh on-disk SQLite (with the v1
// schema applied) and an empty keystore. Tests drive it through ServeHTTP
// using a *clientLite to thread cookies between requests like a browser.
func testServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	srv, err := New(config.Config{}, db, crypto.NewKeystore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, db
}

// clientLite holds cookies between calls so a sequence of requests behaves
// like a single browser session.
type clientLite struct {
	t       *testing.T
	srv     http.Handler
	cookies map[string]*http.Cookie
}

func newClient(t *testing.T, srv http.Handler) *clientLite {
	return &clientLite{t: t, srv: srv, cookies: map[string]*http.Cookie{}}
}

func (c *clientLite) do(req *http.Request) *httptest.ResponseRecorder {
	c.t.Helper()
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return w
}

func (c *clientLite) get(target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return c.do(req)
}

func (c *clientLite) postForm(target string, form url.Values) *httptest.ResponseRecorder {
	form.Set(csrfFormField, c.csrfToken())
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

func (c *clientLite) csrfToken() string {
	if ck := c.cookies[csrfCookieName]; ck != nil {
		return ck.Value
	}
	return ""
}

// validPassphrase is just long enough for MinPassphraseLen.
const validPassphrase = "correct horse battery"

// fastSetup primes the auth state much faster than going through the real
// handler — Argon2id at default params is too slow for unit tests. It writes
// salt+params+verifier into settings and installs a KEK derived with low
// Argon2id params, mirroring what handleSetupPost would have written.
func fastSetup(t *testing.T, srv *Server, db *sql.DB) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	params := crypto.KDFParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32}
	paramsJSON := []byte(`{"time":1,"memory":64,"threads":1,"key_len":32}`)
	kek, err := crypto.DeriveKEK([]byte(validPassphrase), salt, params)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(db, store.SettingKDFSalt, salt); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(db, store.SettingKDFParams, paramsJSON); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(db, store.SettingPassphraseVerifier, crypto.Verifier(kek)); err != nil {
		t.Fatal(err)
	}
	if err := srv.keystore.Install(kek); err != nil {
		t.Fatal(err)
	}
}

// ---------------- index dispatcher ----------------

func TestIndex_RedirectsToSetupWhenNotSetUp(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)

	w := c.get("/")
	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/setup" {
		t.Errorf("Location: got %q, want /setup", loc)
	}
}

func TestIndex_RedirectsToUnlockWhenSetUpButLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/")
	if w.Code != http.StatusSeeOther {
		t.Errorf("status: got %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/unlock" {
		t.Errorf("Location: got %q, want /unlock", loc)
	}
}

func TestIndex_RendersWhenUnlockedWithSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	// Establish a session by setting the cookie ourselves (simulating a
	// successful unlock).
	secret, err := srv.keystore.DeriveSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	value, err := SignSession(secret)
	if err != nil {
		t.Fatal(err)
	}
	c.cookies[SessionCookieName] = &http.Cookie{Name: SessionCookieName, Value: value}

	w := c.get("/")
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200, body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unlocked") {
		t.Errorf("body did not contain unlocked indicator:\n%s", w.Body.String())
	}
}

func TestIndex_OnlyExactRoot(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	w := c.get("/no-such-path")
	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

// ---------------- setup ----------------

func TestSetupGet_RendersForm(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	w := c.get("/setup")
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="passphrase"`) {
		t.Error("setup form missing passphrase field")
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Error("setup form missing csrf_token field")
	}
}

func TestSetupGet_RedirectsToUnlockWhenAlreadySetUp(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	w := c.get("/setup")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestSetupPost_RejectsShortPassphrase(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	c.get("/setup") // prime CSRF cookie

	w := c.postForm("/setup", url.Values{"passphrase": {"short"}, "passphrase2": {"short"}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "at least 12 characters") {
		t.Errorf("expected length error in body, got:\n%s", w.Body.String())
	}
}

func TestSetupPost_RejectsMismatch(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	c.get("/setup")

	w := c.postForm("/setup", url.Values{
		"passphrase":  {"correct horse battery"},
		"passphrase2": {"correct horse battery!"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "do not match") {
		t.Errorf("expected mismatch error in body, got:\n%s", w.Body.String())
	}
}

// ---------------- unlock ----------------

func TestUnlockGet_RedirectsToSetupWhenNotSetUp(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	w := c.get("/unlock")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestUnlockGet_RendersFormWhenSetUpAndLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/unlock")
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `name="passphrase"`) {
		t.Error("unlock form missing passphrase field")
	}
}

func TestUnlockPost_WrongPassphrase(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie
	w := c.postForm("/unlock", url.Values{"passphrase": {"definitely-wrong"}})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Incorrect passphrase") {
		t.Errorf("expected 'Incorrect passphrase' in body, got:\n%s", w.Body.String())
	}
	if srv.keystore.IsUnlocked() {
		t.Error("keystore should remain locked after wrong passphrase")
	}
}

func TestUnlockPost_CorrectPassphraseInstallsKEKAndSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie
	w := c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if !srv.keystore.IsUnlocked() {
		t.Error("keystore should be unlocked after correct passphrase")
	}
	if c.cookies[SessionCookieName] == nil {
		t.Error("session cookie not issued")
	}
}

// ---------------- lock ----------------

func TestLock_ZeroesKEKAndClearsSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	c.get("/unlock")
	if w := c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}}); w.Code != http.StatusSeeOther {
		t.Fatalf("unlock failed: %d %q", w.Code, w.Body.String())
	}
	if c.cookies[SessionCookieName] == nil {
		t.Fatal("session cookie missing after unlock")
	}

	w := c.postForm("/lock", url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if srv.keystore.IsUnlocked() {
		t.Error("keystore should be locked")
	}
	if c.cookies[SessionCookieName] != nil {
		t.Error("session cookie should be cleared")
	}
}

func TestLock_IsIdempotent(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie (locked path is fine)
	w := c.postForm("/lock", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Errorf("first lock: got %d, want 303", w.Code)
	}
	w = c.postForm("/lock", url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Errorf("second lock: got %d, want 303", w.Code)
	}
}

// ---------------- end-to-end ----------------

func TestEndToEnd_SetupUnlockLockUnlock(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)

	// 1. Visit /; redirected to /setup
	if w := c.get("/"); w.Header().Get("Location") != "/setup" {
		t.Fatalf("expected redirect to /setup, got %q (status %d)", w.Header().Get("Location"), w.Code)
	}

	// 2. GET /setup primes CSRF; POST /setup writes verifier and installs KEK
	c.get("/setup")
	w := c.postForm("/setup", url.Values{
		"passphrase":  {validPassphrase},
		"passphrase2": {validPassphrase},
	})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("setup failed: status=%d body=%q", w.Code, w.Body.String())
	}

	// 3. /lock zeroes KEK and clears session
	if w := c.postForm("/lock", url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("lock failed: %d", w.Code)
	}

	// 4. GET / now redirects to /unlock
	if w := c.get("/"); w.Header().Get("Location") != "/unlock" {
		t.Fatalf("expected redirect to /unlock, got %q", w.Header().Get("Location"))
	}

	// 5. Re-unlock; back at /
	c.get("/unlock")
	if w := c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}}); w.Code != http.StatusSeeOther {
		t.Fatalf("unlock failed: %d body=%q", w.Code, w.Body.String())
	}
	w = c.get("/")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 at /, got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unlocked") {
		t.Errorf("index missing 'unlocked' indicator:\n%s", w.Body.String())
	}
}
