package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Klice/homepki/internal/store"
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
	if res.Status != store.DeployStatusOK {
		t.Fatalf("status=%v err=%q", res.Status, res.Err)
	}
	got, _ := os.ReadFile(tgt.CertPath)
	if !strings.Contains(string(got), "AAA") {
		t.Errorf("cert: %q", got)
	}
	got, _ = os.ReadFile(tgt.KeyPath)
	if !strings.Contains(string(got), "BBB") {
		t.Errorf("key: %q", got)
	}
}

func TestRun_AppliesMode(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.Mode = "0600"
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusOK {
		t.Fatalf("res=%+v", res)
	}
	for _, p := range []string{tgt.CertPath, tgt.KeyPath} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s perm: got %o, want 0600", p, st.Mode().Perm())
		}
	}
}

func TestRun_WritesChainWhenSet(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	chain := filepath.Join(dir, "fullchain.pem")
	tgt.ChainPath = &chain
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusOK {
		t.Fatalf("res=%+v", res)
	}
	got, _ := os.ReadFile(chain)
	if !strings.Contains(string(got), "CCC") {
		t.Errorf("chain: %q", got)
	}
}

func TestRun_ChainPathSetButNoChainBytes(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	chain := filepath.Join(dir, "fullchain.pem")
	tgt.ChainPath = &chain

	b := sampleBytes()
	b.FullChain = nil
	res := Run(t.Context(), tgt, b)
	if res.Status != store.DeployStatusFailed {
		t.Errorf("expected failed, got %v", res.Status)
	}
	if !strings.Contains(res.Err, "chain") {
		t.Errorf("err: %q", res.Err)
	}
}

func TestRun_RejectsRelativePath(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.CertPath = "relative/cert.pem"
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusFailed {
		t.Errorf("expected failed, got %v", res.Status)
	}
	if !strings.Contains(res.Err, "absolute") {
		t.Errorf("err: %q", res.Err)
	}
}

func TestRun_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	// Pre-write the target with a recognisable marker.
	if err := os.WriteFile(tgt.CertPath, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusOK {
		t.Fatalf("res=%+v", res)
	}
	got, _ := os.ReadFile(tgt.CertPath)
	if !strings.Contains(string(got), "AAA") {
		t.Errorf("expected new contents, got %q", got)
	}
	// No leftover temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".homepki-deploy-") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

func TestRun_PostCommandSucceeds(t *testing.T) {
	dir := t.TempDir()
	flag := filepath.Join(dir, "ran")
	tgt := minimalTarget(dir)
	tgt.PostCommand = ptr("touch " + flag)

	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusOK {
		t.Fatalf("res=%+v", res)
	}
	if _, err := os.Stat(flag); err != nil {
		t.Errorf("post_command did not run: %v", err)
	}
}

func TestRun_PostCommandFailureRecorded(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.PostCommand = ptr("exit 1")
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusFailed {
		t.Errorf("expected failed, got %v", res.Status)
	}
	if !strings.Contains(res.Err, "post_command") {
		t.Errorf("err should mention post_command: %q", res.Err)
	}
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
	if res.Status != store.DeployStatusFailed {
		t.Errorf("expected failed, got %v", res.Status)
	}
}

func TestRun_UnknownOwnerFails(t *testing.T) {
	dir := t.TempDir()
	tgt := minimalTarget(dir)
	tgt.Owner = ptr("definitely-no-such-user")
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusFailed {
		t.Errorf("expected failed, got %v", res.Status)
	}
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
		if res.Status != store.DeployStatusFailed {
			t.Errorf("expected failed (non-root chown to 0), got %v", res.Status)
		}
		return
	}
	// Running as root: should succeed.
	res := Run(t.Context(), tgt, sampleBytes())
	if res.Status != store.DeployStatusOK {
		t.Errorf("expected ok as root, got %+v", res)
	}
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
		if (err != nil) != tc.wantErr {
			t.Errorf("parseMode(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseMode(%q) = %o, want %o", tc.in, got, tc.want)
		}
	}
}

func TestIsPermissionError(t *testing.T) {
	if !IsPermissionError(os.ErrPermission) {
		t.Error("os.ErrPermission should be a permission error")
	}
	if IsPermissionError(errors.New("nope")) {
		t.Error("plain error should not be a permission error")
	}
}
