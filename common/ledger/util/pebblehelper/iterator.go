/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebblehelper

import (
	"bytes"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/v2"
)

// DBIterator adapts Pebble positioning and is invalidated when its owning DB closes.
// Use one goroutine per iterator; Release and DB.Close are synchronized with iterator operations.
type DBIterator struct {
	db *DB
	// mutex stops Release from closing the Pebble iterator while another call is
	// using it. Release shares the DB lock for speed, so the DB lock cannot stop
	// this by itself.
	mutex sync.Mutex
	itr   *pebble.Iterator
	err   error

	// beforeFirst means the iterator is before its first key.
	// It starts true and becomes true again when Prev moves back past the first key.
	// When true, Next calls First instead of Pebble's Next, matching goleveldb behavior.
	// Moving past the last key does not set this flag, so Next does not start over.
	//
	// For keys a and b:
	//   - New iterator: Next returns a, then b, then false.
	//   - At a: Prev returns false, then Next returns a again.
	beforeFirst bool
}

// Next advances to the next key, or the first key on an unpositioned iterator.
func (itr *DBIterator) Next() bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	if itr.beforeFirst {
		itr.beforeFirst = false
		return itr.itr.First()
	}
	return itr.itr.Next()
}

// Prev moves to the previous key.
func (itr *DBIterator) Prev() bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	if itr.beforeFirst {
		return false
	}
	ok := itr.itr.Prev()
	itr.beforeFirst = !ok && itr.itr.Error() == nil
	return ok
}

// First positions the iterator at its first key.
func (itr *DBIterator) First() bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	itr.beforeFirst = false
	return itr.itr.First()
}

// Last positions the iterator at its last key.
func (itr *DBIterator) Last() bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	itr.beforeFirst = false
	return itr.itr.Last()
}

// Seek positions the iterator at the first key greater than or equal to key.
func (itr *DBIterator) Seek(key []byte) bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	itr.beforeFirst = false
	return itr.itr.SeekGE(key)
}

// Valid reports whether the iterator is positioned at a key.
func (itr *DBIterator) Valid() bool {
	if !itr.lock() {
		return false
	}
	defer itr.unlock()

	return itr.itr.Valid()
}

// Key returns a caller-owned copy of the current key, or nil if invalid.
func (itr *DBIterator) Key() []byte {
	if !itr.lock() {
		return nil
	}
	defer itr.unlock()

	if !itr.itr.Valid() {
		return nil
	}
	// Closing the DB must not invalidate bytes already returned to a caller.
	return bytes.Clone(itr.itr.Key())
}

// Value returns a caller-owned copy of the current value, or nil if invalid.
func (itr *DBIterator) Value() []byte {
	if !itr.lock() {
		return nil
	}
	defer itr.unlock()

	if !itr.itr.Valid() {
		return nil
	}
	return bytes.Clone(itr.itr.Value())
}

// Error returns the accumulated error, including pebble.ErrClosed after DB invalidation.
func (itr *DBIterator) Error() error {
	if itr.db == nil {
		return itr.err
	}
	itr.db.mutex.RLock()
	itr.mutex.Lock()
	defer itr.unlock()

	if itr.err != nil {
		return itr.err
	}
	if itr.itr == nil {
		return nil
	}
	return itr.itr.Error()
}

// Release releases the iterator and records any close error. Repeated calls are safe.
func (itr *DBIterator) Release() {
	if itr.db == nil {
		return
	}
	itr.db.mutex.RLock()
	itr.mutex.Lock()
	defer itr.unlock()

	itr.release()
}

// lock protects a live iterator operation against Release and DB.Close.
// On success the caller must call unlock without calling another wrapper method.
func (itr *DBIterator) lock() bool {
	if itr.db == nil {
		return false
	}
	itr.db.mutex.RLock()
	itr.mutex.Lock()
	if itr.db.dbState == closed || itr.itr == nil {
		itr.unlock()
		return false
	}
	return true
}

// unlock releases the iterator lock before the DB lifecycle lock.
func (itr *DBIterator) unlock() {
	itr.mutex.Unlock()
	itr.db.mutex.RUnlock()
}

// release requires the DB write lock, or the DB read lock and the iterator lock.
func (itr *DBIterator) release() {
	if itr.itr == nil {
		return
	}
	itr.err = errors.Join(itr.err, errors.WithStack(itr.itr.Close()))
	itr.itr = nil
	itr.db.iteratorsMutex.Lock()
	delete(itr.db.iterators, itr)
	itr.db.iteratorsMutex.Unlock()
}
