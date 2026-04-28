package web

import (
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// downloadFixture issues root → intermediate → leaf via the real handlers and
// returns their IDs plus a primed client (CSRF token loaded). Shared setup for
// every download-handler test.
func downloadFixture(t *testing.T) (srv *Server, c *clientLite, rootID, interID, leafID string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c = newClient(t, srv)
	installSession(t, srv, c)
	rootID, interID, leafID = issueChain(t, c)
	// Visit detail page so we have a CSRF token in the jar for any
	// subsequent POST (bundle.p12).
	c.get("/certs/" + leafID)
	return
}

// decodePEMBlocks returns every PEM block of the given type in the body.
func decodePEMBlocks(t *testing.T, body []byte, blockType string) []*pem.Block {
	t.Helper()
	var out []*pem.Block
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != blockType {
			t.Fatalf("unexpected PEM block type %q (want %q)", block.Type, blockType)
		}
		out = append(out, block)
	}
	return out
}

// ---- cert.pem ----

func TestDownload_CertPEM_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/cert.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Errorf("Content-Type: %q", got)
	}
	disp := w.Header().Get("Content-Disposition")
	if !strings.Contains(disp, `attachment;`) || !strings.Contains(disp, ".crt") {
		t.Errorf("Content-Disposition: %q", disp)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "private") {
		t.Errorf("Cache-Control should be private (non-sensitive): %q", cc)
	}

	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	if len(blocks) != 1 {
		t.Fatalf("blocks: got %d, want 1", len(blocks))
	}
	parsed, err := x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Subject.CommonName != "revoke.leaf.test" {
		t.Errorf("CN: got %q", parsed.Subject.CommonName)
	}
}

func TestDownload_CertPEM_NotFound(t *testing.T) {
	_, c, _, _, _ := downloadFixture(t)
	w := c.get("/certs/no-such-id/cert.pem")
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
}

func TestDownload_CertPEM_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.get("/certs/" + leafID + "/cert.pem")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

// ---- key.pem ----

func TestDownload_KeyPEM_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/key.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control should be no-store (sensitive): %q", cc)
	}
	if pr := w.Header().Get("Pragma"); pr != "no-cache" {
		t.Errorf("Pragma: %q", pr)
	}
	disp := w.Header().Get("Content-Disposition")
	if !strings.Contains(disp, ".key") {
		t.Errorf("Content-Disposition should end in .key: %q", disp)
	}

	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockPrivateKey)
	if len(blocks) != 1 {
		t.Fatalf("blocks: got %d, want 1", len(blocks))
	}
	priv, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	if err != nil {
		t.Fatalf("parse pkcs8: %v", err)
	}
	if _, ok := priv.(stdcrypto.Signer); !ok {
		t.Errorf("decoded key %T is not a crypto.Signer", priv)
	}
}

func TestDownload_KeyPEM_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.get("/certs/" + leafID + "/key.pem")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

// ---- chain.pem ----

func TestDownload_ChainPEM_LeafExcludesSelfAndRoot(t *testing.T) {
	_, c, _, interID, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/chain.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	if len(blocks) != 1 {
		t.Fatalf("blocks: got %d, want 1 (intermediate only)", len(blocks))
	}
	parsed, err := x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Subject.CommonName != "Revoke Intermediate" {
		t.Errorf("chain[0] CN: got %q, want intermediate", parsed.Subject.CommonName)
	}
	_ = interID // already validated via CN
}

func TestDownload_ChainPEM_IntermediateUnderRootIsEmpty(t *testing.T) {
	_, c, _, interID, _ := downloadFixture(t)

	w := c.get("/certs/" + interID + "/chain.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("intermediate-under-root chain should be empty PEM, got %d bytes", w.Body.Len())
	}
}

func TestDownload_ChainPEM_RootIs404(t *testing.T) {
	_, c, rootID, _, _ := downloadFixture(t)
	w := c.get("/certs/" + rootID + "/chain.pem")
	if w.Code != http.StatusNotFound {
		t.Errorf("root chain: got %d, want 404", w.Code)
	}
}

// ---- fullchain.pem ----

func TestDownload_FullchainPEM_LeafIncludesSelfAndIntermediates(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/fullchain.pem")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	if len(blocks) != 2 {
		t.Fatalf("blocks: got %d, want 2 (leaf + intermediate)", len(blocks))
	}
	leaf, _ := x509.ParseCertificate(blocks[0].Bytes)
	inter, _ := x509.ParseCertificate(blocks[1].Bytes)
	if leaf.Subject.CommonName != "revoke.leaf.test" {
		t.Errorf("block[0] CN: got %q", leaf.Subject.CommonName)
	}
	if inter.Subject.CommonName != "Revoke Intermediate" {
		t.Errorf("block[1] CN: got %q", inter.Subject.CommonName)
	}
}

func TestDownload_FullchainPEM_NonLeafIs404(t *testing.T) {
	_, c, rootID, interID, _ := downloadFixture(t)
	for _, id := range []string{rootID, interID} {
		w := c.get("/certs/" + id + "/fullchain.pem")
		if w.Code != http.StatusNotFound {
			t.Errorf("non-leaf %s fullchain: got %d, want 404", id, w.Code)
		}
	}
}

// ---- bundle.p12 ----

func TestDownload_BundleP12_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{"password": {"hunter2"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pkcs12" {
		t.Errorf("Content-Type: %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control should be no-store: %q", cc)
	}

	priv, leafCert, caCerts, err := pkcs12.DecodeChain(w.Body.Bytes(), "hunter2")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if _, ok := priv.(stdcrypto.Signer); !ok {
		t.Errorf("decoded key %T is not a crypto.Signer", priv)
	}
	if leafCert.Subject.CommonName != "revoke.leaf.test" {
		t.Errorf("leaf CN: %q", leafCert.Subject.CommonName)
	}
	if len(caCerts) != 1 || caCerts[0].Subject.CommonName != "Revoke Intermediate" {
		t.Errorf("ca certs: got %v, want [Revoke Intermediate]", caCerts)
	}
}

func TestDownload_BundleP12_MissingPassword(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)
	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", w.Code)
	}
}

func TestDownload_BundleP12_NonLeafIs404(t *testing.T) {
	_, c, rootID, interID, _ := downloadFixture(t)
	for _, id := range []string{rootID, interID} {
		w := c.postForm("/certs/"+id+"/bundle.p12", url.Values{"password": {"hunter2"}})
		if w.Code != http.StatusNotFound {
			t.Errorf("non-leaf %s p12: got %d, want 404", id, w.Code)
		}
	}
}

func TestDownload_BundleP12_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{"password": {"hunter2"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/unlock" {
		t.Errorf("got status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

// ---- helpers under test ----

func TestSanitizeFilename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"leaf.example.com", "leaf.example.com"},
		{"My Cert", "My_Cert"},
		{"a/b\\c:d*e?f<g>h|i\"j", "a_b_c_d_e_f_g_h_i_j"},
		{"", "cert"},
		{"   ", "cert"},
		{"...", "cert"},
		{"héllo", "h_llo"},
	}
	for _, tc := range cases {
		if got := sanitizeFilename(tc.in); got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// detail page surfaces the download links.
func TestCertDetail_RendersDownloadLinks(t *testing.T) {
	_, c, rootID, interID, leafID := downloadFixture(t)

	for _, tc := range []struct {
		id     string
		want   []string
		notWant []string
	}{
		{
			id:      leafID,
			want:    []string{"/cert.pem", "/key.pem", "/chain.pem", "/fullchain.pem", "/bundle.p12"},
			notWant: nil,
		},
		{
			id:      interID,
			want:    []string{"/cert.pem", "/key.pem", "/chain.pem"},
			notWant: []string{"/fullchain.pem", "/bundle.p12"},
		},
		{
			id:      rootID,
			want:    []string{"/cert.pem", "/key.pem"},
			notWant: []string{"/chain.pem", "/fullchain.pem", "/bundle.p12"},
		},
	} {
		w := c.get("/certs/" + tc.id)
		body := w.Body.String()
		for _, want := range tc.want {
			if !strings.Contains(body, "/certs/"+tc.id+want) {
				t.Errorf("/certs/%s detail missing link %s", tc.id, want)
			}
		}
		for _, no := range tc.notWant {
			if strings.Contains(body, "/certs/"+tc.id+no) {
				t.Errorf("/certs/%s detail should not contain link %s", tc.id, no)
			}
		}
	}
}
