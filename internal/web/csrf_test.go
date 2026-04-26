package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// passThrough is a handler that records that it was called and returns 200.
func passThrough() (http.Handler, *bool) {
	called := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), &called
}

func extractCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCSRF_GET_SetsCookieIfMissing(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !*called {
		t.Error("inner handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	c := extractCookie(t, w, "csrf")
	if c == nil {
		t.Fatal("no csrf cookie set")
	}
	if len(c.Value) != csrfTokenLen*2 {
		t.Errorf("token length: got %d, want %d hex chars", len(c.Value), csrfTokenLen*2)
	}
	if !c.HttpOnly {
		t.Error("csrf cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite: got %d, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path: got %q", c.Path)
	}
}

func TestCSRF_GET_PreservesExistingCookie(t *testing.T) {
	inner, _ := passThrough()
	h := CSRF(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "existing-token"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if c := extractCookie(t, w, "csrf"); c != nil {
		t.Errorf("middleware should not overwrite an existing cookie, but set %v", c)
	}
}

func TestCSRF_POST_AcceptsMatchingToken(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	body := url.Values{"csrf_token": {"the-token"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/unlock", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "the-token"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !*called {
		t.Error("inner handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
}

func TestCSRF_POST_RejectsMismatch(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	body := url.Values{"csrf_token": {"wrong-token"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/unlock", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "the-token"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if *called {
		t.Error("inner handler should not be called on CSRF mismatch")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}

func TestCSRF_POST_RejectsMissingCookie(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	body := url.Values{"csrf_token": {"some-value"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/unlock", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if *called {
		t.Error("inner handler should not be called when there's no prior csrf cookie")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}

func TestCSRF_Healthz_IsExempt(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !*called {
		t.Error("inner handler not called for /healthz")
	}
	if c := extractCookie(t, w, "csrf"); c != nil {
		t.Errorf("exempt path should not set csrf cookie, got %v", c)
	}
}

func TestCSRF_CRLEndpoint_IsExempt(t *testing.T) {
	inner, called := passThrough()
	h := CSRF(inner)

	// POST should also pass through on exempt paths (the CRL endpoint is GET
	// only, but the exemption is path-based, not method-based).
	req := httptest.NewRequest(http.MethodGet, "/crl/abc-123.crl", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !*called {
		t.Error("inner handler not called for /crl/...")
	}
	if c := extractCookie(t, w, "csrf"); c != nil {
		t.Errorf("exempt path should not set csrf cookie, got %v", c)
	}
}

func TestIsHTTPS(t *testing.T) {
	cases := []struct {
		name string
		setup func(*http.Request)
		want bool
	}{
		{
			name:  "plain HTTP request",
			setup: func(*http.Request) {},
			want:  false,
		},
		{
			name: "X-Forwarded-Proto=https",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
			},
			want: true,
		},
		{
			name: "X-Forwarded-Proto=http",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "http")
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.setup(req)
			if got := isHTTPS(req); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
