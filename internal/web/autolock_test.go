package web

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCfg(mins int, passphrase string) config.Config {
	return config.Config{
		AutoLockMinutes: mins,
		Passphrase:      passphrase,
	}
}

func waitForLocked(t *testing.T, ks *crypto.Keystore, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !ks.IsUnlocked() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("keystore was not locked within %v", timeout)
}

func newUnlockedKeystore(t *testing.T) *crypto.Keystore {
	t.Helper()
	ks := crypto.NewKeystore()
	require.NoError(t, ks.Install(make([]byte, crypto.KeyLen)))
	return ks
}

func TestIdleLocker_FiresAfterTimeout(t *testing.T) {
	ks := newUnlockedKeystore(t)
	l := newIdleLocker(ks, 30*time.Millisecond)
	defer l.Stop()
	l.Touch()

	waitForLocked(t, ks, 200*time.Millisecond)
}

func TestIdleLocker_TouchResets(t *testing.T) {
	ks := newUnlockedKeystore(t)
	l := newIdleLocker(ks, 50*time.Millisecond)
	defer l.Stop()

	// Touch repeatedly inside the timeout window — keystore must stay unlocked.
	for range 5 {
		l.Touch()
		time.Sleep(20 * time.Millisecond)
		require.True(t, ks.IsUnlocked(), "locker fired despite recent Touch")
	}
	// Stop touching — within ~50ms it should fire.
	waitForLocked(t, ks, 200*time.Millisecond)
}

func TestIdleLocker_DisabledIsNoOp(t *testing.T) {
	ks := newUnlockedKeystore(t)
	l := newIdleLocker(ks, 0) // disabled
	l.Touch()
	time.Sleep(30 * time.Millisecond)
	assert.True(t, ks.IsUnlocked(), "disabled locker should never fire")
	l.Stop() // also a no-op
}

func TestIdleLocker_StopCancelsPending(t *testing.T) {
	ks := newUnlockedKeystore(t)
	l := newIdleLocker(ks, 30*time.Millisecond)
	l.Touch()
	l.Stop()
	time.Sleep(80 * time.Millisecond)
	assert.True(t, ks.IsUnlocked(), "Stop should have cancelled the pending lock")
}

func TestIdleLocker_NilSafe(t *testing.T) {
	// Production code might pass *idleLocker through paths that haven't
	// constructed one yet. Touch / Stop on nil must not panic.
	var l *idleLocker
	l.Touch()
	l.Stop()
}

func TestIdleLocker_ConcurrentTouches(t *testing.T) {
	// Race-detector smoke test — many touches and one Stop, no panic / race.
	ks := newUnlockedKeystore(t)
	l := newIdleLocker(ks, 100*time.Millisecond)
	var wg atomicCounter
	for range 50 {
		wg.start()
		go func() {
			defer wg.done()
			for range 100 {
				l.Touch()
			}
		}()
	}
	wg.waitDone()
	l.Stop()
}

// atomicCounter is a minimal "wait for N goroutines" helper that avoids
// pulling sync.WaitGroup specifically so this file stays focused on the
// locker semantics.
type atomicCounter struct{ n atomic.Int32 }

func (c *atomicCounter) start() { c.n.Add(1) }
func (c *atomicCounter) done()  { c.n.Add(-1) }
func (c *atomicCounter) waitDone() {
	for c.n.Load() > 0 {
		time.Sleep(time.Millisecond)
	}
}

// ============== integration: requireUnlocked touches the locker ==============

func TestRequireUnlocked_TouchesLocker(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)

	// Replace the server's locker with one whose timeout is short enough
	// to observe in-test. fastSetup already unlocked the keystore.
	srv.locker = newIdleLocker(srv.keystore, 40*time.Millisecond)
	defer srv.locker.Stop()

	// Touch repeatedly via authenticated requests — keystore stays unlocked.
	for range 4 {
		c.get("/")
		time.Sleep(20 * time.Millisecond)
		require.True(t, srv.keystore.IsUnlocked(), "keystore locked despite recent authenticated request")
	}
	// Stop touching — within ~40ms idle the locker should fire.
	waitForLocked(t, srv.keystore, 200*time.Millisecond)
}

// ============== autoLockTimeout: env → duration ==============

func TestAutoLockTimeout_DisabledByDefault(t *testing.T) {
	cases := []struct {
		name string
		mins int
		pass string
		want time.Duration
	}{
		{"unset", 0, "", 0},
		{"thirty", 30, "", 30 * time.Minute},
		{"forced off by CM_PASSPHRASE", 30, "secret", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := autoLockTimeout(testCfg(tc.mins, tc.pass))
			assert.Equal(t, tc.want, d)
		})
	}
}
