// Package deploy executes a configured deploy_targets row: writes the
// cert/key/chain bytes to disk via temp-file-then-atomic-rename, applies
// mode/owner/group, and (optionally) runs a post-deploy reload command.
//
// The package is intentionally PKI-agnostic — callers in internal/web
// decrypt the key under the keystore's KEK and hand the runner ready-to-go
// PEM bytes. That keeps the keystore boundary inside one package and lets
// the runner stay testable without a live PKI.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Klice/homepki/internal/store"
)

// PostCommandTimeout caps the time a post_command may take. Operator-defined
// reload commands ("nginx -s reload", "systemctl reload caddy") return in
// well under a second; an unbounded run would otherwise pin the request.
const PostCommandTimeout = 30 * time.Second

// Bytes is the precomputed cert / key / fullchain content the runner writes.
// All three are PEM. Chain is empty for "no chain configured" — the runner
// won't touch chain_path even if the target has one.
type Bytes struct {
	Cert      []byte
	Key       []byte
	FullChain []byte
}

// Result is the outcome of a single Run call. Status is the value the caller
// should persist via store.RecordDeployRun. Err is the first thing that went
// wrong, suitable for store.RecordDeployRun's errMsg argument; empty when
// Status == DeployStatusOK.
type Result struct {
	Status store.DeployStatus
	Err    string
}

// Run executes target against the supplied bytes. It writes every requested
// file, applies metadata, and runs post_command. Failures short-circuit:
// the first error wins. Returns the Result the caller persists; never returns
// a Go error directly because the operator-visible failure path is a row
// update + a UI badge, not an HTTP 500.
func Run(ctx context.Context, target *store.DeployTarget, b Bytes) Result {
	if target == nil {
		return failed("target is nil")
	}

	mode, err := parseMode(target.Mode)
	if err != nil {
		return failed("invalid mode: " + err.Error())
	}

	uid, gid, err := resolveOwnership(target.Owner, target.Group)
	if err != nil {
		return failed(err.Error())
	}

	writes := []struct {
		path string
		data []byte
		// label is used in error messages so the operator can tell which
		// of the three files broke.
		label string
	}{
		{target.CertPath, b.Cert, "cert"},
		{target.KeyPath, b.Key, "key"},
	}
	if target.ChainPath != nil && *target.ChainPath != "" {
		if len(b.FullChain) == 0 {
			return failed("chain_path is set but no chain bytes were supplied")
		}
		writes = append(writes, struct {
			path string
			data []byte
			label string
		}{*target.ChainPath, b.FullChain, "chain"})
	}

	for _, w := range writes {
		if !filepath.IsAbs(w.path) {
			return failed(w.label + "_path is not absolute: " + w.path)
		}
		if err := atomicWrite(w.path, w.data, mode, uid, gid); err != nil {
			return failed(fmt.Sprintf("write %s: %v", w.label, err))
		}
	}

	if target.PostCommand != nil && *target.PostCommand != "" {
		if err := runPostCommand(ctx, *target.PostCommand); err != nil {
			return failed("post_command: " + err.Error())
		}
	}
	return Result{Status: store.DeployStatusOK}
}

// atomicWrite creates a temp file in the same directory as path, writes
// data + flushes + chmods + chowns, then renames over path. Same-FS rename
// is atomic, so a concurrent reader sees either the old bytes or the new
// bytes — never a half-written file. Owner/group are skipped when uid/gid
// are -1 (the "not configured" sentinel from resolveOwnership).
func atomicWrite(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".homepki-deploy-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	// Best-effort cleanup if anything below fails. After a successful
	// rename the temp file no longer exists at this name; Remove returns
	// ENOENT and we ignore it.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if uid >= 0 || gid >= 0 {
		if err := os.Chown(tmpName, uid, gid); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return os.Rename(tmpName, path)
}

// runPostCommand shells out via `sh -c` so quoted operator-supplied commands
// like `systemctl reload nginx && touch /var/run/reloaded` work without
// re-implementing argv parsing. The command runs with PostCommandTimeout;
// non-zero exit or timeout is reported with the captured stderr.
func runPostCommand(parent context.Context, cmd string) error {
	ctx, cancel := context.WithTimeout(parent, PostCommandTimeout)
	defer cancel()

	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	out, err := c.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s", PostCommandTimeout)
	}
	if err != nil {
		// Trim stderr to keep the row's last_error reasonable; full output
		// goes to the server log when the caller chooses to log it.
		snippet := string(out)
		if len(snippet) > 500 {
			snippet = snippet[:500] + "…"
		}
		return fmt.Errorf("%v: %s", err, snippet)
	}
	return nil
}

// parseMode accepts an octal-as-text mode like "0640" and returns it as an
// os.FileMode. The leading "0" is optional but conventional.
func parseMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("not octal: %q", s)
	}
	// Mask to permission bits. Operators don't need setuid/setgid/sticky on
	// a TLS cert and unintentionally setting them would be surprising.
	return os.FileMode(v) & os.ModePerm, nil
}

// resolveOwnership turns owner / group (numeric strings or names) into uids
// and gids suitable for os.Chown. Either may be nil/empty; in that case the
// returned id is -1, the "leave unchanged" sentinel from os.Chown.
//
// Lookup happens at run time: a target whose owner refers to a user that
// doesn't exist in the container records last_status=failed at run time, per
// API.md §8.1 ("if either of owner/group resolves fail at run time the
// target run will record failed").
func resolveOwnership(owner, group *string) (int, int, error) {
	uid, gid := -1, -1
	if owner != nil && *owner != "" {
		v, err := lookupUser(*owner)
		if err != nil {
			return 0, 0, err
		}
		uid = v
	}
	if group != nil && *group != "" {
		v, err := lookupGroup(*group)
		if err != nil {
			return 0, 0, err
		}
		gid = v
	}
	return uid, gid, nil
}

func lookupUser(s string) (int, error) {
	if v, err := strconv.Atoi(s); err == nil {
		return v, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("owner %q: %w", s, err)
	}
	v, _ := strconv.Atoi(u.Uid)
	return v, nil
}

func lookupGroup(s string) (int, error) {
	if v, err := strconv.Atoi(s); err == nil {
		return v, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, fmt.Errorf("group %q: %w", s, err)
	}
	v, _ := strconv.Atoi(g.Gid)
	return v, nil
}

func failed(msg string) Result {
	return Result{Status: store.DeployStatusFailed, Err: msg}
}

// IsPermissionError reports whether err looks like it came from a chown /
// chmod / write into a directory the process doesn't own. Used by callers
// that want to surface a hint about running with the right uid in the
// container, but optional — Run's textual Err is already operator-readable.
func IsPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}
