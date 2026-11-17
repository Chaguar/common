/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldbhelper

import (
	"bytes"
	"fmt"
	stdsync "sync"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/v2"
	"github.com/hyperledger/fabric-lib-go/common/flogging"

	"github.com/Chaguar/common/tools/fileutil"
)

var logger = flogging.MustGetLogger("leveldbhelper")

type dbState int32

const (
	closed dbState = iota
	opened
)

// DB - a wrapper on an actual store.
type DB struct {
	conf    *Conf
	db      *pebble.DB
	dbState dbState
	mutex   stdsync.RWMutex

	writeOptsNoSync *pebble.WriteOptions
	writeOptsSync   *pebble.WriteOptions
}

// CreateDB constructs a DB.
func CreateDB(conf *Conf) *DB {
	writeOptsNoSync := &pebble.WriteOptions{}
	writeOptsSync := &pebble.WriteOptions{}
	writeOptsSync.Sync = true

	return &DB{
		conf:            conf,
		dbState:         closed,
		writeOptsNoSync: writeOptsNoSync,
		writeOptsSync:   writeOptsSync,
	}
}

// Open opens the underlying db.
func (dbInst *DB) Open() error {
	dbInst.mutex.Lock()
	defer dbInst.mutex.Unlock()

	if dbInst.dbState == opened {
		return nil
	}

	dbOpts := &pebble.Options{}
	dbPath := dbInst.conf.DBPath
	var err error
	var dirEmpty bool
	if dirEmpty, err = fileutil.CreateDirIfMissing(dbPath); err != nil {
		return errors.Wrap(err, "error creating database directory")
	}

	dbOpts.ErrorIfNotExists = !dirEmpty
	if dbInst.db, err = pebble.Open(dbPath, dbOpts); err != nil {
		return errors.Wrap(err, "error opening pebble")
	}

	dbInst.dbState = opened
	return nil
}

// IsEmpty returns whether or not a database is empty.
func (dbInst *DB) IsEmpty() (bool, error) {
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return false, errors.Wrapf(pebble.ErrClosed,
			"error checking whether pebble at [%s] is empty", dbInst.conf.DBPath)
	}

	iter, err := dbInst.db.NewIter(&pebble.IterOptions{})
	itr := &DBIterator{itr: iter, err: errors.WithStack(err), beforeFirst: true}
	defer itr.Release()

	hasItems := itr.Next()
	if err := itr.Error(); err != nil {
		return false, fmt.Errorf("error checking whether pebble at [%s] is empty: %w", dbInst.conf.DBPath, err)
	}

	return !hasItems, nil
}

// Close closes the underlying db.
func (dbInst *DB) Close() {
	dbInst.mutex.Lock()
	defer dbInst.mutex.Unlock()

	if dbInst.dbState == closed {
		return
	}
	if err := dbInst.db.Close(); err != nil {
		logger.Errorf("Error closing pebble: %s", err)
	}

	dbInst.dbState = closed
}

// Get returns the value for the given key.
func (dbInst *DB) Get(key []byte) ([]byte, error) {
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return nil, errors.Wrap(pebble.ErrClosed, "error retrieving pebble key")
	}

	value, closer, err := dbInst.db.Get(key)
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving pebble key [%#v]", key)
	}

	// Pebble owns the returned buffer until closer.Close.
	value = bytes.Clone(value)
	if err := closer.Close(); err != nil {
		return nil, errors.Wrap(err, "error releasing pebble value")
	}

	return value, nil
}

// Put saves the key/value.
func (dbInst *DB) Put(key, value []byte, sync bool) error { //nolint:revive // Sync controls durability.
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error writing pebble key")
	}

	wo := dbInst.writeOptsNoSync
	if sync {
		wo = dbInst.writeOptsSync
	}

	err := dbInst.db.Set(key, value, wo)
	if err != nil {
		return errors.Wrapf(err, "error writing pebble key [%#v]", key)
	}

	return nil
}

// Delete deletes the given key.
func (dbInst *DB) Delete(key []byte, sync bool) error { //nolint:revive // Sync controls durability.
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error deleting pebble key")
	}

	wo := dbInst.writeOptsNoSync
	if sync {
		wo = dbInst.writeOptsSync
	}

	err := dbInst.db.Delete(key, wo)
	if err != nil {
		return errors.Wrapf(err, "error deleting pebble key [%#v]", key)
	}

	return nil
}

// GetIterator returns an iterator over key-value store. The iterator should be released after the use.
// The resultset contains keys between startKey (inclusive) and endKey (exclusive).
// A nil startKey represents the first available key and a nil endKey represents a logical key
// after the last available key.
func (dbInst *DB) GetIterator(startKey, endKey []byte) *DBIterator {
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return &DBIterator{err: errors.WithStack(pebble.ErrClosed)}
	}

	itr, err := dbInst.db.NewIter(&pebble.IterOptions{LowerBound: startKey, UpperBound: endKey})
	return &DBIterator{itr: itr, err: errors.WithStack(err), beforeFirst: true}
}

// WriteBatch writes a batch without consuming it.
func (dbInst *DB) WriteBatch(batch *pebble.Batch, sync bool) error { //nolint:revive // Sync controls durability.
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error writing batch to pebble")
	}

	wo := dbInst.writeOptsNoSync
	if sync {
		wo = dbInst.writeOptsSync
	}

	// Commit a private batch so callers can reuse or reset their update batch.
	pending := dbInst.db.NewBatch()
	defer func() {
		if err := pending.Close(); err != nil {
			logger.Errorf("Error closing pebble batch: %s", err)
		}
	}()

	if err := pending.Apply(batch, nil); err != nil {
		return errors.Wrap(err, "error preparing batch for pebble")
	}

	if err := pending.Commit(wo); err != nil {
		return errors.Wrap(err, "error writing batch to pebble")
	}

	return nil
}

// FileLock encapsulates the DB that holds the file lock.
// As the FileLock is to be used by a single process/goroutine,
// there is no need for the semaphore to synchronize the
// FileLock usage.
type FileLock struct {
	db       *pebble.DB
	filePath string
}

// NewFileLock returns a new file based lock manager.
func NewFileLock(filePath string) *FileLock {
	return &FileLock{
		filePath: filePath,
	}
}

// Lock acquires a file lock. We achieve this by opening
// a db for the given filePath. Internally, Pebble acquires a
// file lock while opening a db. If the db is opened again by the same or
// another process, an error is returned. When the db is closed
// or the owner process dies, the lock is released and hence
// the other process can open the db.
func (f *FileLock) Lock() error {
	if f.db != nil {
		return errors.Newf("lock is already acquired on file %s", f.filePath)
	}
	db, err := pebble.Open(f.filePath, nil)
	if err != nil {
		return errors.Wrapf(err, "error acquiring lock on file %s", f.filePath)
	}

	// Only mutate the lock db reference AFTER validating that the lock was held.
	f.db = db

	return nil
}

// IsLocked determines if the lock is currently held open.
func (f *FileLock) IsLocked() bool {
	return f.db != nil
}

// Unlock releases a previously acquired lock. We achieve this by closing
// the previously opened db. Unlock can be called multiple times.
func (f *FileLock) Unlock() {
	if f.db == nil {
		return
	}
	if err := f.db.Close(); err != nil {
		logger.Warnf("Unable to release lock on file %s: %s", f.filePath, err)
		return
	}
	f.db = nil
}
