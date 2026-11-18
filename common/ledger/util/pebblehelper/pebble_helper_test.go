/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebblehelper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/pebble/v2"
	"github.com/stretchr/testify/require"
)

func TestPebbleHelperWithoutOpen(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	require.ErrorIs(t, db.Put([]byte("key"), []byte("value"), false), pebble.ErrClosed)
	_, err := db.Get([]byte("key"))
	require.ErrorIs(t, err, pebble.ErrClosed)
}

func TestPebbleHelper(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	t.Cleanup(db.Close)

	require.NoError(t, db.Open())
	require.NoError(t, db.Open())
	empty, err := db.IsEmpty()
	require.NoError(t, err)
	require.True(t, empty)

	require.NoError(t, db.Put([]byte("key1"), []byte("value1"), false))
	require.NoError(t, db.Put([]byte("key2"), []byte("value2"), true))
	require.NoError(t, db.Put([]byte("key3"), []byte("value3"), true))

	value, err := db.Get([]byte("key2"))
	require.NoError(t, err)
	require.Equal(t, []byte("value2"), value)

	require.NoError(t, db.Delete([]byte("key1"), false))
	require.NoError(t, db.Delete([]byte("key2"), true))
	value, err = db.Get([]byte("key2"))
	require.NoError(t, err)
	require.Nil(t, value)

	db.Close()
	db.Close()

	_, err = db.IsEmpty()
	require.ErrorIs(t, err, pebble.ErrClosed)
	_, err = db.Get([]byte("key3"))
	require.ErrorIs(t, err, pebble.ErrClosed)
	require.ErrorIs(t, db.Delete([]byte("key3"), true), pebble.ErrClosed)

	require.NoError(t, db.Open())
	empty, err = db.IsEmpty()
	require.NoError(t, err)
	require.False(t, empty)

	batch := &pebble.Batch{}
	require.NoError(t, batch.Set([]byte("key1"), []byte("value1"), nil))
	require.NoError(t, batch.Set([]byte("key2"), []byte("value2"), nil))
	require.NoError(t, batch.Delete([]byte("key3"), nil))
	require.NoError(t, db.WriteBatch(batch, true))

	// A written batch must be reset and rebuilt before reuse.
	require.Panics(t, func() { _ = db.WriteBatch(batch, false) })
	batch.Reset()
	require.NoError(t, batch.Set([]byte("key1"), []byte("value1"), nil))
	require.NoError(t, db.WriteBatch(batch, false))
	value, err = db.Get([]byte("key3"))
	require.NoError(t, err)
	require.Nil(t, value)
	itr := db.GetIterator(nil, nil)
	var keys, values []string
	for itr.Next() {
		keys = append(keys, string(itr.Key()))
		values = append(values, string(itr.Value()))
	}
	require.NoError(t, itr.Error())
	require.Equal(t, []string{"key1", "key2"}, keys)
	require.Equal(t, []string{"value1", "value2"}, values)
	itr.Release()

	db.Close()
	require.ErrorIs(t, db.WriteBatch(batch, true), pebble.ErrClosed)
}

func TestPebbleMemTableDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	db := CreateDB(&Conf{DBPath: dir})
	t.Cleanup(db.Close)
	require.NoError(t, db.Open())

	files, err := filepath.Glob(filepath.Join(dir, "OPTIONS-*"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	options, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Contains(t, string(options), "mem_table_size=67108864")
}

func TestPebbleBatchResetAndReopen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		size int
	}{
		{name: "small batch", size: 1024},
		{name: "large batch", size: 600 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := CreateDB(&Conf{DBPath: t.TempDir(), MemTableSize: 1 << 20})
			t.Cleanup(db.Close)
			require.NoError(t, db.Open())
			value := bytes.Repeat([]byte("v"), tc.size)
			batch := &pebble.Batch{}
			require.NoError(t, batch.Set([]byte("first"), value, nil))
			require.NoError(t, db.WriteBatch(batch, false))

			batch.Reset()
			require.NoError(t, batch.Set([]byte("second"), []byte("reset"), nil))
			require.NoError(t, db.WriteBatch(batch, true))
			require.NoError(t, batch.Close())
			db.Close()
			require.NoError(t, db.Open())

			got, err := db.Get([]byte("first"))
			require.NoError(t, err)
			require.Equal(t, value, got)
			got, err = db.Get([]byte("second"))
			require.NoError(t, err)
			require.Equal(t, []byte("reset"), got)
		})
	}
}

func TestCreateDBInEmptyDir(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	t.Cleanup(db.Close)

	require.NoError(t, db.Open())
}

func TestCreateDBInNonEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dummyfile.txt"), nil, 0o600))
	db := CreateDB(&Conf{DBPath: dir})
	t.Cleanup(db.Close)

	require.Error(t, db.Open())
}
