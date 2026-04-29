package web

import (
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.Equal(t, blockType, block.Type, "unexpected PEM block type")
		out = append(out, block)
	}
	return out
}

// ---- cert.pem ----

func TestDownload_CertPEM_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/cert.pem")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pem-file", w.Header().Get("Content-Type"))
	disp := w.Header().Get("Content-Disposition")
	assert.Contains(t, disp, `attachment;`)
	assert.Contains(t, disp, ".crt")
	assert.Contains(t, w.Header().Get("Cache-Control"), "private", "Cache-Control should be private (non-sensitive)")

	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	require.Len(t, blocks, 1, "blocks")
	parsed, err := x509.ParseCertificate(blocks[0].Bytes)
	require.NoError(t, err, "parse")
	assert.Equal(t, "revoke.leaf.test", parsed.Subject.CommonName, "CN")
}

func TestDownload_CertPEM_NotFound(t *testing.T) {
	_, c, _, _, _ := downloadFixture(t)
	w := c.get("/certs/no-such-id/cert.pem")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDownload_CertPEM_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.get("/certs/" + leafID + "/cert.pem")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

// ---- key.pem ----

func TestDownload_KeyPEM_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/key.pem")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", "Cache-Control should be no-store (sensitive)")
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), ".key", "Content-Disposition should end in .key")

	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockPrivateKey)
	require.Len(t, blocks, 1, "blocks")
	priv, err := x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	require.NoError(t, err, "parse pkcs8")
	_, ok := priv.(stdcrypto.Signer)
	assert.True(t, ok, "decoded key %T is not a crypto.Signer", priv)
}

func TestDownload_KeyPEM_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.get("/certs/" + leafID + "/key.pem")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

// ---- chain.pem ----

func TestDownload_ChainPEM_LeafExcludesSelfAndRoot(t *testing.T) {
	_, c, _, interID, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/chain.pem")
	require.Equal(t, http.StatusOK, w.Code)
	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	require.Len(t, blocks, 1, "blocks (intermediate only)")
	parsed, err := x509.ParseCertificate(blocks[0].Bytes)
	require.NoError(t, err, "parse")
	assert.Equal(t, "Revoke Intermediate", parsed.Subject.CommonName, "chain[0] CN")
	_ = interID // already validated via CN
}

func TestDownload_ChainPEM_IntermediateUnderRootIsEmpty(t *testing.T) {
	_, c, _, interID, _ := downloadFixture(t)

	w := c.get("/certs/" + interID + "/chain.pem")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, w.Body.Len(), "intermediate-under-root chain should be empty PEM")
}

func TestDownload_ChainPEM_RootIs404(t *testing.T) {
	_, c, rootID, _, _ := downloadFixture(t)
	w := c.get("/certs/" + rootID + "/chain.pem")
	assert.Equal(t, http.StatusNotFound, w.Code, "root chain")
}

// ---- fullchain.pem ----

func TestDownload_FullchainPEM_LeafIncludesSelfAndIntermediates(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.get("/certs/" + leafID + "/fullchain.pem")
	require.Equal(t, http.StatusOK, w.Code)
	blocks := decodePEMBlocks(t, w.Body.Bytes(), pemBlockCertificate)
	require.Len(t, blocks, 2, "blocks (leaf + intermediate)")
	leaf, _ := x509.ParseCertificate(blocks[0].Bytes)
	inter, _ := x509.ParseCertificate(blocks[1].Bytes)
	assert.Equal(t, "revoke.leaf.test", leaf.Subject.CommonName, "block[0] CN")
	assert.Equal(t, "Revoke Intermediate", inter.Subject.CommonName, "block[1] CN")
}

func TestDownload_FullchainPEM_NonLeafIs404(t *testing.T) {
	_, c, rootID, interID, _ := downloadFixture(t)
	for _, id := range []string{rootID, interID} {
		w := c.get("/certs/" + id + "/fullchain.pem")
		assert.Equal(t, http.StatusNotFound, w.Code, "non-leaf %s fullchain", id)
	}
}

// ---- bundle.p12 ----

func TestDownload_BundleP12_RoundTrip(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)

	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{"password": {"hunter2"}})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-pkcs12", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "no-store", "Cache-Control should be no-store")

	priv, leafCert, caCerts, err := pkcs12.DecodeChain(w.Body.Bytes(), "hunter2")
	require.NoError(t, err, "DecodeChain")
	_, ok := priv.(stdcrypto.Signer)
	assert.True(t, ok, "decoded key %T is not a crypto.Signer", priv)
	assert.Equal(t, "revoke.leaf.test", leafCert.Subject.CommonName, "leaf CN")
	require.Len(t, caCerts, 1, "ca certs count")
	assert.Equal(t, "Revoke Intermediate", caCerts[0].Subject.CommonName, "ca cert CN")
}

func TestDownload_BundleP12_MissingPassword(t *testing.T) {
	_, c, _, _, leafID := downloadFixture(t)
	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDownload_BundleP12_NonLeafIs404(t *testing.T) {
	_, c, rootID, interID, _ := downloadFixture(t)
	for _, id := range []string{rootID, interID} {
		w := c.postForm("/certs/"+id+"/bundle.p12", url.Values{"password": {"hunter2"}})
		assert.Equal(t, http.StatusNotFound, w.Code, "non-leaf %s p12", id)
	}
}

func TestDownload_BundleP12_RedirectsWhenLocked(t *testing.T) {
	srv, c, _, _, leafID := downloadFixture(t)
	srv.keystore.Lock()
	w := c.postForm("/certs/"+leafID+"/bundle.p12", url.Values{"password": {"hunter2"}})
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
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
		assert.Equal(t, tc.want, sanitizeFilename(tc.in), "sanitizeFilename(%q)", tc.in)
	}
}

// detail page surfaces the download links.
func TestCertDetail_RendersDownloadLinks(t *testing.T) {
	_, c, rootID, interID, leafID := downloadFixture(t)

	for _, tc := range []struct {
		id      string
		want    []string
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
			assert.Contains(t, body, "/certs/"+tc.id+want, "/certs/%s detail missing link %s", tc.id, want)
		}
		for _, no := range tc.notWant {
			assert.NotContains(t, body, "/certs/"+tc.id+no, "/certs/%s detail should not contain link %s", tc.id, no)
		}
	}
}
