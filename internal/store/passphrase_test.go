package store

import (
	"errors"
	"testing"

	"github.com/Klice/homepki/internal/crypto"
)

// seedCertWithRealKey inserts a cert + a real two-tier sealed private-key
// blob under kek. Returns the certID. Lets the rotation test verify that
// after rewrap the key still decrypts under the new KEK and the original
// PKCS#8 plaintext is recoverable.
func seedCertWithRealKey(t *testing.T, db sqlcDBTX, id string, kek []byte) {
	t.Helper()
	plaintext := []byte("PRETEND-PKCS8-" + id)
	sealed, err := crypto.SealPrivateKey(kek, id, plaintext)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	c := sampleCert(id)
	c.ParentID = nil
	c.Type = "root_ca"
	c.IsCA = true
	c.SubjectCN = "rot-" + id
	k := &CertKey{
		CertID:      id,
		KEKTier:     "main",
		WrappedDEK:  sealed.WrappedDEK,
		DEKNonce:    sealed.DEKNonce,
		CipherNonce: sealed.CipherNonce,
		Ciphertext:  sealed.Ciphertext,
	}
	if err := insertCertTx(db, c, k); err != nil {
		t.Fatalf("insertCertTx: %v", err)
	}
}

func TestRotate_HappyPath_RewrapsAllAndUpdatesSettings(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	// Seed the install with a verifier so the rotation has something to
	// "replace" — though RotatePassphrase doesn't read the old verifier
	// itself, we want the test to look like a real install.
	oldKEK := make([]byte, crypto.KeyLen)
	for i := range oldKEK {
		oldKEK[i] = 0xAA
	}
	if err := SetSetting(db, SettingPassphraseVerifier, crypto.Verifier(oldKEK)); err != nil {
		t.Fatal(err)
	}

	// Seed three certs so the rewrap loop has work to do.
	seedCertWithRealKey(t, db, "a", oldKEK)
	seedCertWithRealKey(t, db, "b", oldKEK)
	seedCertWithRealKey(t, db, "c", oldKEK)

	// Stash the original ciphertext blobs so we can confirm they're
	// untouched (only the wrap layer rotates).
	origCT := map[string][]byte{}
	for _, id := range []string{"a", "b", "c"} {
		k, err := GetCertKey(db, id)
		if err != nil {
			t.Fatal(err)
		}
		origCT[id] = append([]byte(nil), k.Ciphertext...)
	}

	newKEK := make([]byte, crypto.KeyLen)
	for i := range newKEK {
		newKEK[i] = 0xBB
	}
	tok, err := CreateIdemToken(db)
	if err != nil {
		t.Fatal(err)
	}
	in := RotatePassphraseInputs{
		NewSalt:       []byte("0123456789abcdef"),
		NewParamsJSON: []byte(`{"time":3,"memory":65536,"threads":2,"key_len":32}`),
		NewVerifier:   crypto.Verifier(newKEK),
	}
	if err := RotatePassphrase(db, in, RewrapWithKEKs(oldKEK, newKEK), tok, "/settings"); err != nil {
		t.Fatalf("RotatePassphrase: %v", err)
	}

	// 1. settings now reflect the new salt / params / verifier.
	if v, _ := GetSetting(db, SettingKDFSalt); string(v) != "0123456789abcdef" {
		t.Errorf("kdf_salt: got %q", v)
	}
	if v, _ := GetSetting(db, SettingPassphraseVerifier); !crypto.VerifierEqual(v, crypto.Verifier(newKEK)) {
		t.Errorf("verifier didn't match new KEK's verifier")
	}

	// 2. Each rewrapped key opens under the NEW KEK and gives back the
	//    original PKCS#8 plaintext, and the ciphertext column is bit-for-bit
	//    unchanged (only the wrap layer rotated).
	for _, id := range []string{"a", "b", "c"} {
		k, err := GetCertKey(db, id)
		if err != nil {
			t.Fatal(err)
		}
		sealed := &crypto.SealedPrivateKey{
			WrappedDEK:  k.WrappedDEK,
			DEKNonce:    k.DEKNonce,
			CipherNonce: k.CipherNonce,
			Ciphertext:  k.Ciphertext,
		}
		got, err := crypto.OpenPrivateKey(newKEK, id, sealed)
		if err != nil {
			t.Errorf("Open under new KEK for %s: %v", id, err)
			continue
		}
		want := "PRETEND-PKCS8-" + id
		if string(got) != want {
			t.Errorf("plaintext for %s: got %q, want %q", id, got, want)
		}
		if string(k.Ciphertext) != string(origCT[id]) {
			t.Errorf("ciphertext for %s changed (should be untouched)", id)
		}
		// And the OLD KEK no longer opens it.
		if _, err := crypto.OpenPrivateKey(oldKEK, id, sealed); err == nil {
			t.Errorf("old KEK should NOT open rewrapped key for %s", id)
		}
	}

	// 3. The form token is now used and points at /settings.
	row, err := LookupIdemToken(db, tok)
	if err != nil {
		t.Fatal(err)
	}
	if row.UsedAt == nil || row.ResultURL == nil || *row.ResultURL != "/settings" {
		t.Errorf("token state: used=%v url=%v", row.UsedAt, row.ResultURL)
	}
}

func TestRotate_RewrapErrorRollsBackEverything(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	oldKEK := make([]byte, crypto.KeyLen)
	for i := range oldKEK {
		oldKEK[i] = 1
	}
	seedCertWithRealKey(t, db, "a", oldKEK)
	seedCertWithRealKey(t, db, "b", oldKEK)

	origAW, _ := GetCertKey(db, "a")
	origBW, _ := GetCertKey(db, "b")

	tok, _ := CreateIdemToken(db)
	rewrapErr := errors.New("simulated wrap failure")
	rewrap := func(certID string, _, _ []byte) ([]byte, []byte, error) {
		if certID == "b" {
			return nil, nil, rewrapErr
		}
		// 'a' rewraps successfully — we want to confirm its update is
		// rolled back when 'b' fails.
		return []byte("dummy-wrapped"), []byte("dummy-nonce"), nil
	}
	in := RotatePassphraseInputs{
		NewSalt:       []byte("ffffffffffffffff"),
		NewParamsJSON: []byte(`{}`),
		NewVerifier:   []byte("verifier"),
	}
	err := RotatePassphrase(db, in, rewrap, tok, "/settings")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// 'a' wrap should be unchanged.
	a, _ := GetCertKey(db, "a")
	if string(a.WrappedDEK) != string(origAW.WrappedDEK) {
		t.Error("'a' wrap was modified despite rollback")
	}
	if string(a.DEKNonce) != string(origAW.DEKNonce) {
		t.Error("'a' nonce was modified despite rollback")
	}
	// 'b' wrap should be unchanged.
	b, _ := GetCertKey(db, "b")
	if string(b.WrappedDEK) != string(origBW.WrappedDEK) {
		t.Error("'b' wrap was modified despite rollback")
	}

	// Settings rows should NOT have been written.
	if v, err := GetSetting(db, SettingKDFSalt); err == nil && string(v) == "ffffffffffffffff" {
		t.Error("kdf_salt was written despite rollback")
	}

	// Form token should NOT be marked used.
	row, _ := LookupIdemToken(db, tok)
	if row.UsedAt != nil {
		t.Error("token was marked used despite rollback")
	}
}

func TestRotate_RejectsMissingInputs(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	tok, _ := CreateIdemToken(db)
	cases := []struct {
		name string
		in   RotatePassphraseInputs
		tok  string
	}{
		{"empty token", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: []byte("{}"), NewVerifier: []byte("v")}, ""},
		{"empty salt", RotatePassphraseInputs{NewSalt: nil, NewParamsJSON: []byte("{}"), NewVerifier: []byte("v")}, tok},
		{"empty params", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: nil, NewVerifier: []byte("v")}, tok},
		{"empty verifier", RotatePassphraseInputs{NewSalt: []byte("x"), NewParamsJSON: []byte("{}"), NewVerifier: nil}, tok},
	}
	for _, tc := range cases {
		err := RotatePassphrase(db, tc.in, RewrapWithKEKs(nil, nil), tc.tok, "/settings")
		if err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

func TestRotate_NoCertsIsValid(t *testing.T) {
	// A fresh install with no issued certs should rotate cleanly — the
	// rewrap loop is a no-op and the settings still update.
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	oldKEK := make([]byte, crypto.KeyLen)
	newKEK := make([]byte, crypto.KeyLen)
	for i := range newKEK {
		newKEK[i] = 9
	}
	tok, _ := CreateIdemToken(db)
	in := RotatePassphraseInputs{
		NewSalt:       []byte("aaaaaaaaaaaaaaaa"),
		NewParamsJSON: []byte(`{"time":3,"memory":1024,"threads":1,"key_len":32}`),
		NewVerifier:   crypto.Verifier(newKEK),
	}
	if err := RotatePassphrase(db, in, RewrapWithKEKs(oldKEK, newKEK), tok, "/settings"); err != nil {
		t.Fatalf("RotatePassphrase: %v", err)
	}
	if v, _ := GetSetting(db, SettingKDFSalt); string(v) != "aaaaaaaaaaaaaaaa" {
		t.Errorf("kdf_salt: got %q", v)
	}
}
