package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettings_GetMissingReturnsSentinel(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := GetSetting(db, "no-such-key")
	assert.ErrorIs(t, err, ErrSettingNotFound)
}

func TestSettings_SetThenGetRoundTrip(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	want := []byte("hello world")
	require.NoError(t, SetSetting(db, "greeting", want), "SetSetting")
	got, err := GetSetting(db, "greeting")
	require.NoError(t, err, "GetSetting")
	assert.Equal(t, want, got)
}

func TestSettings_SetIsUpsert(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	require.NoError(t, SetSetting(db, "k", []byte("first")))
	require.NoError(t, SetSetting(db, "k", []byte("second")))
	got, err := GetSetting(db, "k")
	require.NoError(t, err)
	assert.Equal(t, "second", string(got))
}

func TestIsSetUp(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	ok, err := IsSetUp(db)
	require.NoError(t, err)
	assert.False(t, ok, "fresh DB should not be set up")

	require.NoError(t, SetSetting(db, SettingPassphraseVerifier, []byte("verifier-bytes")))

	ok, err = IsSetUp(db)
	require.NoError(t, err)
	assert.True(t, ok, "DB with passphrase_verifier should be set up")
}

func TestSettings_NilValueRoundTrip(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	require.NoError(t, SetSetting(db, "k", nil))
	got, err := GetSetting(db, "k")
	require.NoError(t, err, "GetSetting after nil set")
	assert.Empty(t, got)
}
