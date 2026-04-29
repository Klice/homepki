package web

import (
	"sync"
	"time"

	"github.com/Klice/homepki/internal/crypto"
)

// idleLocker zeros the keystore after a configurable idle window, per
// LIFECYCLE.md §1.4. Activity is signalled by the request path that already
// gates "needs unlocked" routes (web.Server.requireUnlocked). Activity
// outside an authenticated request — background CRL regen, scheduled
// rotation — is signalled by an explicit Touch from the caller.
//
// "Idle" means no Touch in `timeout`. The first Touch arms the timer; each
// subsequent Touch resets it. When the timer fires we call keystore.Lock(),
// which zeroes the in-memory KEK (LIFECYCLE.md §1.3).
//
// Disabled when timeout <= 0 — the operator opted out by leaving
// CM_AUTO_LOCK_MINUTES unset / 0, or auto-lock is forced off because
// CM_PASSPHRASE is set (we'd just unlock again on next request).
type idleLocker struct {
	keystore *crypto.Keystore
	timeout  time.Duration

	mu    sync.Mutex
	timer *time.Timer
}

// newIdleLocker returns a locker. timeout <= 0 disables it: Touch and Stop
// become no-ops and the keystore is never auto-locked.
func newIdleLocker(ks *crypto.Keystore, timeout time.Duration) *idleLocker {
	return &idleLocker{keystore: ks, timeout: timeout}
}

// Touch records activity and (re)arms the lock timer.
func (l *idleLocker) Touch() {
	if l == nil || l.timeout <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.timer == nil {
		l.timer = time.AfterFunc(l.timeout, l.fire)
		return
	}
	l.timer.Reset(l.timeout)
}

// Stop cancels any pending lock. Safe to call on a nil or disabled locker
// and idempotent on an already-stopped one.
func (l *idleLocker) Stop() {
	if l == nil || l.timeout <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.timer != nil {
		l.timer.Stop()
	}
}

// fire is the timer callback. It locks the keystore unconditionally — if
// the operator already locked manually, Lock is a no-op.
func (l *idleLocker) fire() {
	l.keystore.Lock()
}
