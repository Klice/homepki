package web

import (
	"time"

	"github.com/Klice/homepki/internal/store"
)

// DeployTargetView wraps a *store.DeployTarget with the few derived fields
// the cert-detail template needs. EffectiveStatus collapses the stored
// status with the "stale" derivation from STORAGE.md §5.6 (computed when
// last_deployed_serial != cert.serial_number).
type DeployTargetView struct {
	*store.DeployTarget

	EffectiveStatus     string // ok | failed | stale | never
	StatusPillClass     string // pill-ok | pill-bad | pill-warn | pill-muted
	LastDeployedDisplay string // "" if never run
}

func newDeployTargetView(t *store.DeployTarget, currentSerial string) *DeployTargetView {
	v := &DeployTargetView{DeployTarget: t}
	switch {
	case t.LastStatus == nil || *t.LastStatus == "":
		v.EffectiveStatus = "never"
		v.StatusPillClass = "pill-muted"
	case *t.LastStatus == string(store.DeployStatusFailed):
		v.EffectiveStatus = "failed"
		v.StatusPillClass = "pill-bad"
	case *t.LastStatus == string(store.DeployStatusOK) &&
		t.LastDeployedSerial != nil && *t.LastDeployedSerial != currentSerial:
		v.EffectiveStatus = "stale"
		v.StatusPillClass = "pill-warn"
	default:
		v.EffectiveStatus = "ok"
		v.StatusPillClass = "pill-ok"
	}
	if t.LastDeployedAt != nil {
		v.LastDeployedDisplay = t.LastDeployedAt.UTC().Format(time.RFC3339)
	}
	return v
}

func newDeployTargetViews(targets []*store.DeployTarget, currentSerial string) []*DeployTargetView {
	out := make([]*DeployTargetView, len(targets))
	for i, t := range targets {
		out[i] = newDeployTargetView(t, currentSerial)
	}
	return out
}
