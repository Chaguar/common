/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldbhelper

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/cockroachdb/pebble/v2"

	"github.com/Chaguar/common/common/ledger/dataformat"
)

const (
	// internalDBName is used to keep track of data related to internals such as data format.
	// _ is used as name because this is not allowed as a channelname.
	internalDBName = "_"
	// maxBatchSize limits each deletion batch to 1MB of key bytes.
	maxBatchSize = 1000000
)

var (
	dbNameKeySep     = []byte{0x00}
	lastKeyIndicator = byte(0x01)
	formatVersionKey = []byte{'f'} // a single key in db whose value indicates the version of the data format
)

// closeFunc closes the db handle.
type closeFunc func()

// Conf configures a Provider.
//
// ExpectedFormat is the expected value of the internal format key. Opening a nonempty
// database with a different format returns an error. An empty database is initialized
// with ExpectedFormat unless it is empty, in which case no format record is written.
type Conf struct {
	DBPath         string
	ExpectedFormat string
}

// Provider partitions one Pebble database into multiple logical databases.
type Provider struct {
	db *DB

	mux       sync.Mutex
	dbHandles map[string]*DBHandle
}

// DataFormatInfo contains the information about the version of the data format.
type DataFormatInfo struct {
	FormatVerison string // version of the data format
	IsDBEmpty     bool   // set to true if the db does not contain any data
}

// RetrieveDataFormatInfo retrieves the DataFormatInfo for the db at the supplied `dbPath`.
func RetrieveDataFormatInfo(dbPath string) (*DataFormatInfo, error) {
	db := CreateDB(&Conf{DBPath: dbPath})
	if err := db.Open(); err != nil {
		return nil, err
	}
	defer db.Close()

	dbEmpty, err := db.IsEmpty()
	if err != nil {
		return nil, err
	}

	internalDB := &DBHandle{
		db:     db,
		dbName: internalDBName,
	}

	formatVersion, err := internalDB.Get(formatVersionKey)
	if err != nil {
		return nil, err
	}

	return &DataFormatInfo{
		IsDBEmpty:     dbEmpty,
		FormatVerison: string(formatVersion),
	}, nil
}

// NewProvider constructs a Provider.
func NewProvider(conf *Conf) (*Provider, error) {
	db, err := openDBAndCheckFormat(conf)
	if err != nil {
		return nil, err
	}
	return &Provider{
		db:        db,
		dbHandles: make(map[string]*DBHandle),
	}, nil
}

func openDBAndCheckFormat(conf *Conf) (d *DB, e error) {
	db := CreateDB(conf)
	if err := db.Open(); err != nil {
		return nil, err
	}

	defer func() {
		if e != nil {
			db.Close()
		}
	}()

	internalDB := &DBHandle{
		db:     db,
		dbName: internalDBName,
	}

	dbEmpty, err := db.IsEmpty()
	if err != nil {
		return nil, err
	}

	if dbEmpty && conf.ExpectedFormat != "" {
		logger.Infof("DB is empty Setting db format as %s", conf.ExpectedFormat)
		if err = internalDB.Put(formatVersionKey, []byte(conf.ExpectedFormat), true); err != nil {
			return nil, err
		}
		return db, nil
	}

	formatVersion, err := internalDB.Get(formatVersionKey)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Checking for db format at path [%s]", conf.DBPath)

	if !bytes.Equal(formatVersion, []byte(conf.ExpectedFormat)) {
		logger.Errorf("Unexpected format at [%s]: expected [%s], got [%s]",
			conf.DBPath, conf.ExpectedFormat, formatVersion)
		return nil, &dataformat.ErrFormatMismatch{
			ExpectedFormat: conf.ExpectedFormat,
			Format:         string(formatVersion),
			DBInfo:         fmt.Sprintf("pebble at [%s]", conf.DBPath),
		}
	}
	logger.Debug("format is latest, nothing to do")
	return db, nil
}

// GetDataFormat returns the format of the data.
func (p *Provider) GetDataFormat() (string, error) {
	f, err := p.GetDBHandle(internalDBName).Get(formatVersionKey)
	return string(f), err
}

// SetDataFormat sets the format of the data.
func (p *Provider) SetDataFormat(format string) error {
	db := p.GetDBHandle(internalDBName)
	return db.Put(formatVersionKey, []byte(format), true)
}

// GetDBHandle returns a handle to a named db.
func (p *Provider) GetDBHandle(dbName string) *DBHandle {
	p.mux.Lock()
	defer p.mux.Unlock()
	dbHandle := p.dbHandles[dbName]
	if dbHandle == nil {
		closeFunc := func() {
			p.mux.Lock()
			defer p.mux.Unlock()
			delete(p.dbHandles, dbName)
		}
		dbHandle = &DBHandle{dbName, p.db, closeFunc}
		p.dbHandles[dbName] = dbHandle
	}
	return dbHandle
}

// Close closes the underlying pebble.
func (p *Provider) Close() {
	p.db.Close()
}

// Drop drops all the data for the given dbName.
func (p *Provider) Drop(dbName string) error {
	dbHandle := p.GetDBHandle(dbName)
	defer dbHandle.Close()
	return dbHandle.deleteAll()
}

// DBHandle is a handle to a named logical database.
type DBHandle struct {
	dbName    string
	db        *DB
	closeFunc closeFunc
}

// Get returns the value for the given key.
func (h *DBHandle) Get(key []byte) ([]byte, error) {
	return h.db.Get(constructLevelKey(h.dbName, key))
}

// Put saves the key/value.
func (h *DBHandle) Put(key, value []byte, syncToDisk bool) error {
	return h.db.Put(constructLevelKey(h.dbName, key), value, syncToDisk)
}

// Delete deletes the given key.
func (h *DBHandle) Delete(key []byte, syncToDisk bool) error {
	return h.db.Delete(constructLevelKey(h.dbName, key), syncToDisk)
}

// DeleteAll deletes all the keys that belong to the channel (dbName).
func (h *DBHandle) deleteAll() error {
	iter, err := h.GetIterator(nil, nil)
	if err != nil {
		return err
	}
	defer iter.Release()

	// use pebble iterator directly to be more efficient.
	dbIter := iter.DBIterator

	// Key lengths vary between ledgers, so limit batches by key bytes rather than key count.
	numKeys := 0
	batchSize := 0
	batch := &pebble.Batch{}
	for dbIter.Next() {
		if err := dbIter.Error(); err != nil {
			return errors.Wrap(err, "internal pebble error while retrieving data from db iterator")
		}
		key := dbIter.Key()
		numKeys++
		batchSize += len(key)
		if err := batch.Delete(key, nil); err != nil {
			return errors.Wrap(err, "error preparing pebble deletion")
		}
		if batchSize >= maxBatchSize {
			if err := h.db.WriteBatch(batch, true); err != nil {
				return err
			}
			logger.Infof("Have removed %d entries for channel %s in pebble %s", numKeys, h.dbName, h.db.conf.DBPath)
			batchSize = 0
			batch.Reset()
		}
	}
	if err := dbIter.Error(); err != nil {
		return errors.Wrap(err, "internal pebble error while retrieving data from db iterator")
	}
	if batch.Count() > 0 {
		return h.db.WriteBatch(batch, true)
	}
	return nil
}

// IsEmpty returns true if no data exists for the DBHandle.
func (h *DBHandle) IsEmpty() (bool, error) {
	itr, err := h.GetIterator(nil, nil)
	if err != nil {
		return false, err
	}
	defer itr.Release()

	hasItems := itr.Next()
	if err := itr.Error(); err != nil {
		return false, fmt.Errorf("internal pebble error while obtaining next entry from iterator: %w", err)
	}
	return !hasItems, nil
}

// NewUpdateBatch returns a new UpdateBatch that can be used to update the db.
func (h *DBHandle) NewUpdateBatch() *UpdateBatch {
	return &UpdateBatch{
		dbName:      h.dbName,
		pebbleBatch: &pebble.Batch{},
	}
}

// WriteBatch writes a batch in an atomic way.
func (h *DBHandle) WriteBatch(batch *UpdateBatch, syncToDisk bool) error {
	if batch == nil {
		return nil
	}
	if batch.err != nil {
		return batch.err
	}
	if batch.Len() == 0 {
		return nil
	}
	return h.db.WriteBatch(batch.pebbleBatch, syncToDisk)
}

// GetIterator returns an iterator over [startKey, endKey) within this logical database.
// Nil bounds cover all keys. The caller must release the iterator before closing the provider.
func (h *DBHandle) GetIterator(startKey, endKey []byte) (*Iterator, error) {
	sKey := constructLevelKey(h.dbName, startKey)
	eKey := constructLevelKey(h.dbName, endKey)
	if endKey == nil {
		// replace the last byte 'dbNameKeySep' by 'lastKeyIndicator'.
		eKey[len(eKey)-1] = lastKeyIndicator
	}
	logger.Debugf("Getting iterator for range [%#v] - [%#v]", sKey, eKey)
	itr := h.db.GetIterator(sKey, eKey)
	if err := itr.Error(); err != nil {
		itr.Release()
		return nil, errors.Wrapf(err, "internal pebble error while obtaining db iterator")
	}
	return &Iterator{h.dbName, itr}, nil
}

// Close closes the DBHandle after its db data have been deleted.
func (h *DBHandle) Close() {
	if h.closeFunc != nil {
		h.closeFunc()
	}
}

// UpdateBatch encloses the details of multiple `updates`.
type UpdateBatch struct {
	pebbleBatch *pebble.Batch
	dbName      string
	size        int
	err         error
}

// Put adds a KV.
func (b *UpdateBatch) Put(key, value []byte) {
	if value == nil {
		panic("Nil value not allowed")
	}
	k := constructLevelKey(b.dbName, key)
	if err := b.pebbleBatch.Set(k, value, nil); err != nil {
		b.err = errors.Wrap(err, "error preparing pebble update")
	}
	b.size += len(k) + len(value)
}

// Delete deletes a Key and associated value.
func (b *UpdateBatch) Delete(key []byte) {
	k := constructLevelKey(b.dbName, key)
	b.size += len(k)
	if err := b.pebbleBatch.Delete(k, nil); err != nil {
		b.err = errors.Wrap(err, "error preparing pebble deletion")
	}
}

// Size returns the current size of the batch.
func (b *UpdateBatch) Size() int {
	return b.size
}

// Len returns number of records in the batch.
func (b *UpdateBatch) Len() int {
	return int(b.pebbleBatch.Count())
}

// Reset resets the batch.
func (b *UpdateBatch) Reset() {
	b.pebbleBatch.Reset()
	b.size = 0
	b.err = nil
}

// Iterator extends actual pebble iterator.
type Iterator struct {
	dbName string
	*DBIterator
}

// Key wraps actual pebble iterator method.
func (itr *Iterator) Key() []byte {
	if !itr.Valid() {
		return nil
	}
	return retrieveAppKey(itr.DBIterator.Key())
}

// Seek moves to the first key/value pair whose key is greater than or equal to key.
// It returns whether such a pair exists.
func (itr *Iterator) Seek(key []byte) bool {
	levelKey := constructLevelKey(itr.dbName, key)
	return itr.DBIterator.Seek(levelKey)
}

func constructLevelKey(dbName string, key []byte) []byte {
	return append(append([]byte(dbName), dbNameKeySep...), key...)
}

func retrieveAppKey(levelKey []byte) []byte {
	return bytes.SplitN(levelKey, dbNameKeySep, 2)[1]
}
