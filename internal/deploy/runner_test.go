package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr(s string) *string { return &s }

// minimalTarget builds a target whose paths live under dir. Caller can
// override fields after the call.
func minimalTarget(dir string) *store.DeployTarget {
	return &store.DeployTarget{
		ID:       "t1",
		CertID:   "leaf-1",
		Name:     "test",
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(dir, "key.pem"),
		Mode:     "0640",
	}
}

func sampleBytes() Bytes {
	return Bytes{
		Cert:      []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"),
		Key:       []byte("-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n"),
		FullChain: []byte("-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----\n"),
	}
}

func TestRun_WritesCertAndKey(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	res := Run(t.Context(), tgt, sampleBytes())
	require.Equal(t, store.DeployStatusOK, res.Status, "err=%q", res.Err)
	got, _ := os.ReadFile(tgt.CertPath)
	assert.Contains(t, string(got), "AAA")
	got, _ = os.ReadFile(tgt.KeyPath)
	assert.Contains(t, string(got), "BBB")
}

func TestRun_AppliesMode(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.Mode = "0600"
	res := Run(t.Context(), tgt, sampleBytes())
	require.Equal(t, store.DeployStatusOK, res.Status, "res=%+v", res)
	for _, p := range []string{tgt.CertPath, tgt.KeyPath} {
		st, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "path=%s", p)
	}
}

func TestRun_WritesChainWhenSet(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	chain := filepath.Join(dir, "fullchain.pem")
	tgt.ChainPath = &chain
	res := Run(t.Context(), tgt, sampleBytes())
	require.Equal(t, store.DeployStatusOK, res.Status, "res=%+v", res)
	got, _ := os.ReadFile(chain)
	assert.Contains(t, string(got), "CCC")
}

func TestRun_ChainPathSetButNoChainBytes(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	chain := filepath.Join(dir, "fullchain.pem")
	tgt.ChainPath = &chain

	b := sampleBytes()
	b.FullChain = nil
	res := Run(t.Context(), tgt, b)
	assert.Equal(t, store.DeployStatusFailed, res.Status)
	assert.Contains(t, res.Err, "chain")
}

func TestRun_RejectsRelativePath(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.CertPath = "relative/cert.pem"
	res := Run(t.Context(), tgt, sampleBytes())
	assert.Equal(t, store.DeployStatusFailed, res.Status)
	assert.Contains(t, res.Err, "absolute")
}

func TestRun_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	// Pre-write the target with a recognisable marker.
	require.NoError(t, os.WriteFile(tgt.CertPath, []byte("OLD"), 0o600))
	res := Run(t.Context(), tgt, sampleBytes())
	require.Equal(t, store.DeployStatusOK, res.Status, "res=%+v", res)
	got, _ := os.ReadFile(tgt.CertPath)
	assert.Contains(t, string(got), "AAA")
	// No leftover temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".homepki-deploy-"), "temp file leaked: %s", e.Name())
	}
}

func TestRun_PostCommandSucceeds(t *testing.T) {
	dir := t.TempDir()
	flag := filepath.Join(dir, "ran")
	tgt := minimalTarget(dir)
	tgt.PostCommand = ptr("touch " + flag)

	res := Run(t.Context(), tgt, sampleBytes())
	require.Equal(t, store.DeployStatusOK, res.Status, "res=%+v", res)
	_, err := os.Stat(flag)
	assert.NoError(t, err, "post_command did not run")
}

func TestRun_PostCommandFailureRecorded(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.PostCommand = ptr("exit 1")
	res := Run(t.Context(), tgt, sampleBytes())
	assert.Equal(t, store.DeployStatusFailed, res.Status)
	assert.Contains(t, res.Err, "post_command")
}

func TestRun_PostCommandTimesOut(t *testing.T) {
	if testing.Short() {
		t.Skip("timeout test takes a couple seconds")
	}
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.PostCommand = ptr("sleep 60")

	// Use a context with our own short deadline to avoid waiting the full
	// PostCommandTimeout in CI. The runner respects ctx.
	ctx, cancel := context.WithTimeout(t.Context(), 1)
	defer cancel()
	res := Run(ctx, tgt, sampleBytes())
	assert.Equal(t, store.DeployStatusFailed, res.Status)
}

func TestRun_UnknownOwnerFails(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.Owner = ptr("definitely-no-such-user")
	res := Run(t.Context(), tgt, sampleBytes())
	assert.Equal(t, store.DeployStatusFailed, res.Status)
}

func TestRun_NumericOwnerNoChown(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	// Use the current uid so chown is a no-op when the test isn't running
	// as root. resolveOwnership accepts numerics without lookup so we get
	// past the lookup step regardless.
	uid := os.Getuid()
	tgt.Owner = ptr("0")
	if uid != 0 {
		// Non-root tests can't chown to uid 0; expect a permission failure.
		res := Run(t.Context(), tgt, sampleBytes())
		assert.Equal(t, store.DeployStatusFailed, res.Status, "expected failed (non-root chown to 0)")
		return
	}
	// Running as root: should succeed.
	res := Run(t.Context(), tgt, sampleBytes())
	assert.Equal(t, store.DeployStatusOK, res.Status, "expected ok as root, got %+v", res)
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{"0640", 0o640, false},
		{"640", 0o640, false},
		{"0600", 0o600, false},
		{"0777", 0o777, false},
		{"4755", 0o755, false}, // setuid bit masked off
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range cases {
		got, err := parseMode(tc.in)
		if tc.wantErr {
			assert.Error(t, err, "parseMode(%q)", tc.in)
		} else {
			assert.NoError(t, err, "parseMode(%q)", tc.in)
			assert.Equal(t, tc.want, got, "parseMode(%q)", tc.in)
		}
	}
}

func TestIsPermissionError(t *testing.T) {
	assert.True(t, IsPermissionError(os.ErrPermission), "os.ErrPermission should be a permission error")
	assert.False(t, IsPermissionError(errors.New("nope")), "plain error should not be a permission error")
}
