/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebblehelper

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/v2"
	"github.com/hyperledger/fabric-lib-go/common/flogging"

	"github.com/Chaguar/common/tools/fileutil"
)

var logger = flogging.MustGetLogger("pebblehelper")

type dbState int32

const (
	closed dbState = iota
	opened

	defaultMemTableSize = 64 << 20
)

// DB - a wrapper on an actual store.
type DB struct {
	conf    *Conf
	db      *pebble.DB
	dbState dbState

	// mutex keeps the DB open while it is in use. Reads, writes, and iterator calls
	// share it, so they can run at the same time. Open and Close take it alone, so
	// Close waits for running calls and no call can use Pebble after it is closed.
	//
	// Lock order: mutex, then DBIterator.mutex, then iteratorsMutex.
	mutex sync.RWMutex

	// iteratorsMutex protects the iterators map. GetIterator and Release could take
	// mutex alone instead, but then they would wait behind slow sync writes. They
	// share mutex for speed, so the map needs its own small lock. Close does not
	// need it because it holds mutex alone.
	iteratorsMutex sync.Mutex
	// iterators holds the live iterators that Close must release before closing Pebble.
	iterators map[*DBIterator]struct{}

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
		iterators:       make(map[*DBIterator]struct{}),
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

	memTableSize := dbInst.conf.MemTableSize
	if memTableSize == 0 {
		memTableSize = defaultMemTableSize
	}
	dbOpts := &pebble.Options{MemTableSize: memTableSize, Logger: logger}
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

	// This iterator stays under the DB read lock, so Close cannot invalidate it.
	itr, err := dbInst.db.NewIter(&pebble.IterOptions{})
	if err != nil {
		return false, errors.Wrap(err, "error creating pebble iterator")
	}
	hasItems := itr.First()
	err = errors.Join(errors.WithStack(itr.Error()), errors.WithStack(itr.Close()))
	if err != nil {
		return false, fmt.Errorf("error checking whether pebble at [%s] is empty: %w", dbInst.conf.DBPath, err)
	}

	return !hasItems, nil
}

// Close invalidates outstanding iterators before closing the underlying DB.
// Invalidated iterators report pebble.ErrClosed and remain invalid after reopening.
func (dbInst *DB) Close() {
	dbInst.mutex.Lock()
	defer dbInst.mutex.Unlock()

	if dbInst.dbState == closed {
		return
	}
	// The exclusive lifecycle lock excludes iterator operations and registry updates.
	for itr := range dbInst.iterators {
		itr.release()
		if itr.err != nil {
			logger.Errorf("Error closing pebble iterator: %s", itr.err)
		}
		itr.err = errors.Join(itr.err, errors.WithStack(pebble.ErrClosed))
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
func (dbInst *DB) Put(key, value []byte, syncToDisk bool) error { //nolint:revive // Preserve the durability flag API.
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error writing pebble key")
	}

	wo := dbInst.writeOptsNoSync
	if syncToDisk {
		wo = dbInst.writeOptsSync
	}

	err := dbInst.db.Set(key, value, wo)
	if err != nil {
		return errors.Wrapf(err, "error writing pebble key [%#v]", key)
	}

	return nil
}

// Delete deletes the given key.
func (dbInst *DB) Delete(key []byte, syncToDisk bool) error { //nolint:revive // Preserve the durability flag API.
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error deleting pebble key")
	}

	wo := dbInst.writeOptsNoSync
	if syncToDisk {
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
// after the last available key. Closing the DB invalidates outstanding iterators.
func (dbInst *DB) GetIterator(startKey, endKey []byte) *DBIterator {
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return &DBIterator{db: dbInst, err: errors.WithStack(pebble.ErrClosed)}
	}

	iter, err := dbInst.db.NewIter(&pebble.IterOptions{LowerBound: startKey, UpperBound: endKey})
	itr := &DBIterator{db: dbInst, itr: iter, err: errors.WithStack(err), beforeFirst: true}
	if iter != nil {
		dbInst.iteratorsMutex.Lock()
		dbInst.iterators[itr] = struct{}{}
		dbInst.iteratorsMutex.Unlock()
	}
	return itr
}

// WriteBatch writes a batch once. Reset and rebuild the batch before writing it again.
//
//nolint:revive // Preserve the durability flag API.
func (dbInst *DB) WriteBatch(batch *pebble.Batch, syncToDisk bool) error {
	dbInst.mutex.RLock()
	defer dbInst.mutex.RUnlock()

	if dbInst.dbState == closed {
		return errors.Wrap(pebble.ErrClosed, "error writing batch to pebble")
	}

	wo := dbInst.writeOptsNoSync
	if syncToDisk {
		wo = dbInst.writeOptsSync
	}

	if err := dbInst.db.Apply(batch, wo); err != nil {
		return errors.Wrap(err, "error writing batch to pebble")
	}

	return nil
}
