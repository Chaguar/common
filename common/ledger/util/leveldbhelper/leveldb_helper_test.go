/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldbhelper

import (
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

	// Writing does not consume the caller's batch.
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

func TestFileLock(t *testing.T) {
	t.Parallel()

	lockPath := filepath.Join(t.TempDir(), "lock")
	lock1 := NewFileLock(lockPath)
	lock2 := NewFileLock(lockPath)
	t.Cleanup(lock1.Unlock)
	t.Cleanup(lock2.Unlock)

	require.False(t, lock1.IsLocked())
	require.NoError(t, lock1.Lock())
	require.True(t, lock1.IsLocked())

	require.Error(t, lock2.Lock())
	require.False(t, lock2.IsLocked())
	require.ErrorContains(t, lock1.Lock(), "lock is already acquired")
	require.True(t, lock1.IsLocked())
	lock1.Unlock()
	require.False(t, lock1.IsLocked())

	require.NoError(t, lock2.Lock())
	lock2.Unlock()
	lock2.Unlock()
	require.False(t, lock2.IsLocked())

	require.NoError(t, lock1.Lock())
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
