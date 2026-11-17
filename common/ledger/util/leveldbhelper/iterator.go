/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldbhelper

import "github.com/cockroachdb/pebble/v2"

// DBIterator adapts Pebble's positioning to the blockstore's unpositioned iterator contract.
type DBIterator struct {
	itr *pebble.Iterator
	err error

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
	if itr.itr == nil {
		return false
	}

	if itr.beforeFirst {
		return itr.First()
	}

	return itr.itr.Next()
}

// Prev moves to the previous key.
func (itr *DBIterator) Prev() bool {
	if itr.itr == nil {
		return false
	}

	if itr.beforeFirst {
		return false
	}

	ok := itr.itr.Prev()
	itr.beforeFirst = !ok && itr.itr.Error() == nil
	return ok
}

// First positions the iterator at its first key.
func (itr *DBIterator) First() bool {
	itr.beforeFirst = false
	return itr.itr != nil && itr.itr.First()
}

// Last positions the iterator at its last key.
func (itr *DBIterator) Last() bool {
	itr.beforeFirst = false
	return itr.itr != nil && itr.itr.Last()
}

// Seek positions the iterator at the first key greater than or equal to key.
func (itr *DBIterator) Seek(key []byte) bool {
	itr.beforeFirst = false
	return itr.itr != nil && itr.itr.SeekGE(key)
}

// Valid reports whether the iterator is positioned at a key.
func (itr *DBIterator) Valid() bool {
	return itr.itr != nil && itr.itr.Valid()
}

// Key returns the current key, valid until the next positioning operation.
func (itr *DBIterator) Key() []byte {
	if !itr.Valid() {
		return nil
	}

	return itr.itr.Key()
}

// Value returns the current value, valid until the next positioning operation.
func (itr *DBIterator) Value() []byte {
	if !itr.Valid() {
		return nil
	}

	return itr.itr.Value()
}

// Error returns the iterator's accumulated error.
func (itr *DBIterator) Error() error {
	if itr.err != nil {
		return itr.err
	}

	if itr.itr == nil {
		return nil
	}

	return itr.itr.Error()
}

// Release releases the iterator and records any close error.
func (itr *DBIterator) Release() {
	if itr.itr == nil {
		return
	}

	itr.err = itr.itr.Close()
	itr.itr = nil
}
