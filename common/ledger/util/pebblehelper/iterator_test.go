/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebblehelper

import (
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/v2"
	"github.com/stretchr/testify/require"
)

const iteratorReleaseMode = "release"

// A sync write holds the DB read lock while waiting for disk. Iterator setup and
// release must be able to finish without waiting for that unrelated operation.
func TestDBIteratorLifecycleConcurrentDBReader(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		release bool
	}{
		{name: "create"},
		{name: iteratorReleaseMode, release: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := CreateDB(&Conf{DBPath: t.TempDir()})
			t.Cleanup(db.Close)
			require.NoError(t, db.Open())
			require.NoError(t, db.Put([]byte("key"), []byte("value"), false))
			itr := db.GetIterator(nil, nil)
			t.Cleanup(itr.Release)

			db.mutex.RLock()
			finished := make(chan *DBIterator, 1)
			go func() {
				if tc.release {
					itr.Release()
					finished <- itr
					return
				}
				finished <- db.GetIterator(nil, nil)
			}()
			var result *DBIterator
			completed := false
			select {
			case result = <-finished:
				completed = true
			case <-time.After(time.Second):
			}
			// Unblock and join the worker before asserting, including on failure.
			db.mutex.RUnlock()
			if !completed {
				result = <-finished
			}
			t.Cleanup(result.Release)
			require.True(t, completed, "iterator lifecycle waited for an unrelated DB reader")
			require.NoError(t, result.Error())
			require.Equal(t, !tc.release, result.Next())
		})
	}
}

func TestDBIteratorAfterClose(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		position bool
		exhaust  bool
	}{
		{name: "unpositioned"},
		{name: "positioned", position: true},
		{name: "exhausted", position: true, exhaust: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := CreateDB(&Conf{DBPath: t.TempDir()})
			t.Cleanup(db.Close)
			require.NoError(t, db.Open())
			require.NoError(t, db.Put([]byte("key"), []byte("value"), true))
			itr := db.GetIterator(nil, nil)
			t.Cleanup(itr.Release)
			if tc.position {
				require.True(t, itr.Next())
			}
			if tc.exhaust {
				require.False(t, itr.Next())
			}

			db.Close()
			require.ErrorIs(t, itr.Error(), pebble.ErrClosed)
			require.False(t, itr.Next())
			require.False(t, itr.Prev())
			require.False(t, itr.First())
			require.False(t, itr.Last())
			require.False(t, itr.Seek([]byte("key")))
			require.False(t, itr.Valid())
			require.Nil(t, itr.Key())
			require.Nil(t, itr.Value())
			itr.Release()
			itr.Release()
			require.ErrorIs(t, itr.Error(), pebble.ErrClosed)

			require.NoError(t, db.Open())
			require.False(t, itr.First())
			require.ErrorIs(t, itr.Error(), pebble.ErrClosed)
			fresh := db.GetIterator(nil, nil)
			t.Cleanup(fresh.Release)
			require.True(t, fresh.Next())
			require.Equal(t, []byte("value"), fresh.Value())
		})
	}
}

func TestDBIteratorOwnsReturnedBuffers(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	t.Cleanup(db.Close)
	require.NoError(t, db.Open())
	require.NoError(t, db.Put([]byte("key"), []byte("value"), true))
	itr := db.GetIterator(nil, nil)
	t.Cleanup(itr.Release)
	require.True(t, itr.Next())
	key, value := itr.Key(), itr.Value()
	key[0], value[0] = 'x', 'x'
	require.Equal(t, []byte("key"), itr.Key())
	require.Equal(t, []byte("value"), itr.Value())
	db.Close()
	require.Equal(t, []byte("xey"), key)
	require.Equal(t, []byte("xalue"), value)
}

func TestLogicalIteratorAfterClose(t *testing.T) {
	t.Parallel()

	provider, err := NewProvider(&Conf{DBPath: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(provider.Close)
	handle := provider.GetDBHandle("ledger")
	require.NoError(t, handle.Put([]byte("key"), []byte("value"), true))
	itr, err := handle.GetIterator(nil, nil)
	require.NoError(t, err)
	t.Cleanup(itr.Release)
	require.True(t, itr.Next())
	provider.Close()
	require.ErrorIs(t, itr.Error(), pebble.ErrClosed)
	require.Nil(t, itr.Key())
	require.Nil(t, itr.Value())
	require.False(t, itr.Seek([]byte("key")))
}

func TestDBIteratorConcurrentClose(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
	}{
		{name: "close"},
		{name: iteratorReleaseMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testIteratorConcurrentShutdown(t, tc.name)
		})
	}
}

func TestDBIteratorConcurrentRegistryClose(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	t.Cleanup(db.Close)
	require.NoError(t, db.Open())
	require.NoError(t, db.Put([]byte("key"), []byte("value"), false))
	const workers = 8
	ready, start := make(chan struct{}, workers), make(chan struct{})
	finished := make(chan error, workers)
	for range workers {
		go func() {
			itr := db.GetIterator(nil, nil)
			ready <- struct{}{}
			<-start
			for range 100 {
				itr.First()
				itr.Key()
				itr.Value()
				err := itr.Error()
				itr.Release()
				itr.Release()
				if err != nil && !errors.Is(err, pebble.ErrClosed) {
					finished <- err
					return
				}
				itr = db.GetIterator(nil, nil)
			}
			itr.Release()
			finished <- nil
		}()
	}
	for range workers {
		<-ready
	}
	close(start)
	db.Close()
	for range workers {
		select {
		case err := <-finished:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("iterator lifecycle deadlocked with Close")
		}
	}
	require.NoError(t, db.Open())
	fresh := db.GetIterator(nil, nil)
	t.Cleanup(fresh.Release)
	require.True(t, fresh.Next())
}

func TestDBIteratorReleaseConcurrentClose(t *testing.T) {
	t.Parallel()

	db := CreateDB(&Conf{DBPath: t.TempDir()})
	t.Cleanup(db.Close)
	require.NoError(t, db.Open())
	itr := db.GetIterator(nil, nil)
	t.Cleanup(itr.Release)
	start, released, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		<-start
		itr.Release()
		itr.Release()
		close(released)
	}()
	go func() {
		<-start
		db.Close()
		close(closed)
	}()
	close(start)
	<-released
	<-closed
	if err := itr.Error(); err != nil {
		require.ErrorIs(t, err, pebble.ErrClosed)
	}
	require.False(t, itr.Next())
	require.NoError(t, db.Open())
	fresh := db.GetIterator(nil, nil)
	fresh.Release()
	db.Close()
	// An explicitly released iterator is not invalidated again by DB.Close.
	require.NoError(t, fresh.Error())
}

func testIteratorConcurrentShutdown(t *testing.T, mode string) {
	t.Helper()

	provider, err := NewProvider(&Conf{DBPath: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(provider.Close)
	handle := provider.GetDBHandle("ledger")
	require.NoError(t, handle.Put([]byte("key"), []byte("value"), true))
	itr, err := handle.GetIterator(nil, nil)
	require.NoError(t, err)
	t.Cleanup(itr.Release)
	started, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		itr.First()
		close(started)
		for itr.First() {
			itr.Key()
			itr.Value()
			itr.Next()
			itr.Prev()
			itr.Last()
			itr.Seek([]byte("key"))
			itr.Valid()
			if itr.Error() != nil {
				return
			}
		}
	}()
	<-started
	closed := make(chan struct{})
	go func() {
		if mode == iteratorReleaseMode {
			itr.Release()
		} else {
			provider.Close()
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked while iterator was active", mode)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatalf("iterator did not stop after %s", mode)
	}
	if mode == iteratorReleaseMode {
		require.NoError(t, itr.Error())
	} else {
		require.ErrorIs(t, itr.Error(), pebble.ErrClosed)
	}
	itr.Release()
	itr.Release()
}
