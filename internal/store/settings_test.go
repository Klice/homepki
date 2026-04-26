package store

import (
	"bytes"
	"errors"
	"testing"
)

func TestSettings_GetMissingReturnsSentinel(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	_, err := GetSetting(db, "no-such-key")
	if !errors.Is(err, ErrSettingNotFound) {
		t.Errorf("got %v, want ErrSettingNotFound", err)
	}
}

func TestSettings_SetThenGetRoundTrip(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	want := []byte("hello world")
	if err := SetSetting(db, "greeting", want); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	got, err := GetSetting(db, "greeting")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSettings_SetIsUpsert(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "k", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "k", []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, err := GetSetting(db, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("got %q, want second", got)
	}
}

func TestIsSetUp(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}

	ok, err := IsSetUp(db)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("fresh DB should not be set up")
	}

	if err := SetSetting(db, SettingPassphraseVerifier, []byte("verifier-bytes")); err != nil {
		t.Fatal(err)
	}

	ok, err = IsSetUp(db)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("DB with passphrase_verifier should be set up")
	}
}

func TestSettings_NilValueRoundTrip(t *testing.T) {
	db := openTestDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "k", nil); err != nil {
		t.Fatal(err)
	}
	got, err := GetSetting(db, "k")
	if err != nil {
		t.Fatalf("GetSetting after nil set: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}
