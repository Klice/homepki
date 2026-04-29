package store

import (
	"errors"
	"testing"
	"time"
)

// seedLeaf inserts a parent + leaf so deploy_targets has a valid cert_id to
// reference. Returns the leaf's id.
func seedLeaf(t *testing.T, db sqlcDBTX) string {
	t.Helper()
	parent := sampleCert("parent-id")
	parent.Type = "intermediate_ca"
	parent.ParentID = nil
	parent.IsCA = true
	parent.SubjectCN = "parent"
	if err := insertCertTx(db, parent, sampleKey("parent-id")); err != nil {
		t.Fatalf("insert parent: %v", err)
	}
	leaf := sampleCert("leaf-id")
	if err := insertCertTx(db, leaf, sampleKey("leaf-id")); err != nil {
		t.Fatalf("insert leaf: %v", err)
	}
	return "leaf-id"
}

func sampleTarget(id, certID string) *DeployTarget {
	chain := "/etc/ssl/full.pem"
	owner := "root"
	post := "nginx -s reload"
	return &DeployTarget{
		ID:           id,
		CertID:       certID,
		Name:         "nginx",
		CertPath:     "/etc/ssl/cert.pem",
		KeyPath:      "/etc/ssl/key.pem",
		ChainPath:    &chain,
		Mode:         "0640",
		Owner:        &owner,
		Group:        nil,
		PostCommand:  &post,
		AutoOnRotate: true,
	}
}

func TestDeploys_InsertAndGet(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)

	in := sampleTarget("t1", leafID)
	if err := InsertDeployTarget(db, in); err != nil {
		t.Fatalf("InsertDeployTarget: %v", err)
	}

	got, err := GetDeployTarget(db, "t1")
	if err != nil {
		t.Fatalf("GetDeployTarget: %v", err)
	}
	in.CreatedAt = got.CreatedAt
	if got.Name != in.Name || got.CertPath != in.CertPath || got.AutoOnRotate != true {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
	if got.ChainPath == nil || *got.ChainPath != "/etc/ssl/full.pem" {
		t.Errorf("ChainPath: got %v", got.ChainPath)
	}
	if got.LastDeployedAt != nil {
		t.Errorf("fresh target should have nil LastDeployedAt")
	}
}

func TestDeploys_GetMissing(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDeployTarget(db, "nope"); !errors.Is(err, ErrDeployTargetNotFound) {
		t.Errorf("got %v, want ErrDeployTargetNotFound", err)
	}
}

func TestDeploys_Update(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}
	in := sampleTarget("t1", leafID)
	in.Name = "haproxy"
	in.AutoOnRotate = false
	in.ChainPath = nil
	if err := UpdateDeployTarget(db, in); err != nil {
		t.Fatalf("UpdateDeployTarget: %v", err)
	}
	got, _ := GetDeployTarget(db, "t1")
	if got.Name != "haproxy" || got.AutoOnRotate != false || got.ChainPath != nil {
		t.Errorf("update did not stick: %+v", got)
	}
}

func TestDeploys_Update_WrongCertIDIsNotFound(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}
	in := sampleTarget("t1", "different-cert")
	if err := UpdateDeployTarget(db, in); !errors.Is(err, ErrDeployTargetNotFound) {
		t.Errorf("cross-cert update: got %v, want ErrDeployTargetNotFound", err)
	}
}

func TestDeploys_DeleteIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDeployTarget(db, "t1", leafID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// Second delete on the same id is a no-op (per API.md §8.2).
	if err := DeleteDeployTarget(db, "t1", leafID); err != nil {
		t.Errorf("replay delete: got %v, want nil", err)
	}
	if _, err := GetDeployTarget(db, "t1"); !errors.Is(err, ErrDeployTargetNotFound) {
		t.Errorf("after delete: got %v, want ErrDeployTargetNotFound", err)
	}
}

func TestDeploys_List_OrderingAndCertScope(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)

	a := sampleTarget("ta", leafID)
	a.Name = "alpha"
	b := sampleTarget("tb", leafID)
	b.Name = "bravo"
	c := sampleTarget("tc", leafID)
	c.Name = "alpha" // duplicate name on same cert → unique violation
	if err := InsertDeployTarget(db, a); err != nil {
		t.Fatal(err)
	}
	if err := InsertDeployTarget(db, b); err != nil {
		t.Fatal(err)
	}
	if err := InsertDeployTarget(db, c); err == nil {
		t.Errorf("duplicate (cert_id, name) should violate UNIQUE")
	}

	got, err := ListDeployTargets(db, leafID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len: got %d, want 2", len(got))
	}
	if got[0].Name != "alpha" || got[1].Name != "bravo" {
		t.Errorf("order: got %s, %s", got[0].Name, got[1].Name)
	}

	// Scoping: a different cert returns nothing.
	other, err := ListDeployTargets(db, "no-such")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Errorf("other cert: got %d, want 0", len(other))
	}
}

func TestDeploys_RecordRun_OKAndFailed(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}

	when := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	if err := RecordDeployRun(db, "t1", DeployStatusOK, "01ab", "", when); err != nil {
		t.Fatal(err)
	}
	got, _ := GetDeployTarget(db, "t1")
	if got.LastStatus == nil || *got.LastStatus != "ok" {
		t.Errorf("LastStatus: %v", got.LastStatus)
	}
	if got.LastDeployedSerial == nil || *got.LastDeployedSerial != "01ab" {
		t.Errorf("LastDeployedSerial: %v", got.LastDeployedSerial)
	}
	if got.LastError != nil {
		t.Errorf("LastError after ok run: got %v, want nil", got.LastError)
	}
	if got.LastDeployedAt == nil || !got.LastDeployedAt.Equal(when) {
		t.Errorf("LastDeployedAt: %v", got.LastDeployedAt)
	}

	// Failed run records the error and overwrites the previous status.
	if err := RecordDeployRun(db, "t1", DeployStatusFailed, "01ab", "boom", when.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = GetDeployTarget(db, "t1")
	if *got.LastStatus != "failed" || *got.LastError != "boom" {
		t.Errorf("after failed run: status=%v error=%v", got.LastStatus, got.LastError)
	}
}

func TestDeploys_RecordRun_RejectsBadStatus(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}
	if err := RecordDeployRun(db, "t1", DeployStatus("stale"), "", "", time.Now()); err == nil {
		t.Error("expected error for status=stale (UI-derived only per STORAGE.md §5.6)")
	}
}

func TestDeploys_RecordRun_MissingTarget(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := RecordDeployRun(db, "no-such", DeployStatusOK, "01", "", time.Now()); !errors.Is(err, ErrDeployTargetNotFound) {
		t.Errorf("got %v, want ErrDeployTargetNotFound", err)
	}
}

func TestDeploys_CreateWithToken_AtomicAndReplay(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	tok, _ := CreateIdemToken(db)
	resultURL := "/certs/" + leafID

	if err := CreateDeployTargetWithToken(db, sampleTarget("t1", leafID), tok, resultURL); err != nil {
		t.Fatalf("first create: %v", err)
	}
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.ResultURL == nil || *row.ResultURL != resultURL {
		t.Errorf("token result_url: got %v, want %s", row.ResultURL, resultURL)
	}

	// Replay path: caller never reaches CreateDeployTargetWithToken — they
	// see a populated ResultURL on lookup and 303 to it. Sanity check that
	// re-running the combinator now would error (the unique index protects
	// against an out-of-band double-insert).
	err = CreateDeployTargetWithToken(db, sampleTarget("t1-other-id", leafID), tok, resultURL)
	if err == nil {
		t.Error("re-running combinator on a used token should fail (token already used)")
	}
}

func TestDeploys_FKCascadeOnCertDelete(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	leafID := seedLeaf(t, db)
	if err := InsertDeployTarget(db, sampleTarget("t1", leafID)); err != nil {
		t.Fatal(err)
	}
	// Hard-delete the cert and confirm the target row vanishes via the
	// schema-declared ON DELETE CASCADE.
	if _, err := db.Exec("DELETE FROM certificates WHERE id = ?", leafID); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDeployTarget(db, "t1"); !errors.Is(err, ErrDeployTargetNotFound) {
		t.Errorf("after cert delete: got %v, want ErrDeployTargetNotFound", err)
	}
}
