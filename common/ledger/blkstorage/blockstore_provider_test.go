/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blkstorage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"

	"github.com/Chaguar/common/common/ledger"
	"github.com/Chaguar/common/common/ledger/testutil"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/pkg/txflags"
)

func TestIndexConfig(t *testing.T) {
	ic := &IndexConfig{
		AttrsToIndex: []IndexableAttr{
			IndexableAttrBlockNum,
			IndexableAttrTxID,
		},
	}

	require := require.New(t)
	require.True(ic.Contains(IndexableAttrBlockNum))
	require.True(ic.Contains(IndexableAttrTxID))
	require.False(ic.Contains(IndexableAttrBlockNumTranNum))
}

func TestMultipleBlockStores(t *testing.T) {
	tempdir := t.TempDir()

	env := newTestEnv(t, NewConf(tempdir, 0))
	provider := env.provider
	defer provider.Close()

	subdirs, err := provider.List()
	require.NoError(t, err)
	require.Empty(t, subdirs)

	store1, err := provider.Open("ledger1")
	require.NoError(t, err)
	defer store1.Shutdown()
	store2, err := provider.Open("ledger2")
	require.NoError(t, err)
	defer store2.Shutdown()

	blocks1 := addBlocksToStore(t, store1, 5)
	blocks2 := addBlocksToStore(t, store2, 10)

	checkBlocks(t, blocks1, store1)
	checkBlocks(t, blocks2, store2)
	checkWithWrongInputs(t, store1, 5)
	checkWithWrongInputs(t, store2, 10)

	store1.Shutdown()
	store2.Shutdown()
	provider.Close()

	// Reopen provider
	newenv := newTestEnv(t, NewConf(tempdir, 0))
	newprovider := newenv.provider
	defer newprovider.Close()

	subdirs, err = newprovider.List()
	require.NoError(t, err)
	require.Len(t, subdirs, 2)

	newstore1, err := newprovider.Open("ledger1")
	require.NoError(t, err)
	defer newstore1.Shutdown()
	newstore2, err := newprovider.Open("ledger2")
	require.NoError(t, err)
	defer newstore2.Shutdown()

	checkBlocks(t, blocks1, newstore1)
	checkBlocks(t, blocks2, newstore2)
	checkWithWrongInputs(t, newstore1, 5)
	checkWithWrongInputs(t, newstore2, 10)
}

func addBlocksToStore(t *testing.T, store *BlockStore, numBlocks int) []*common.Block {
	blocks := testutil.ConstructTestBlocks(t, numBlocks)
	for _, b := range blocks {
		err := store.AddBlock(b)
		require.NoError(t, err)
	}
	return blocks
}

func checkBlocks(t *testing.T, expectedBlocks []*common.Block, store *BlockStore) {
	bcInfo, _ := store.GetBlockchainInfo()
	require.Equal(t, uint64(len(expectedBlocks)), bcInfo.Height)
	require.Equal(t, protoutil.BlockHeaderHash(expectedBlocks[len(expectedBlocks)-1].GetHeader()), bcInfo.CurrentBlockHash)

	itr, _ := store.RetrieveBlocks(0)
	for i := range expectedBlocks {
		block, _ := itr.Next(t.Context())
		require.Equal(t, expectedBlocks[i], block)
	}

	for blockNum := range expectedBlocks {
		block := expectedBlocks[blockNum]
		flags := txflags.ValidationFlags(block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER])
		retrievedBlock, _ := store.RetrieveBlockByNumber(uint64(blockNum))
		require.Equal(t, block, retrievedBlock)

		retrievedBlock, _ = store.RetrieveBlockByHash(protoutil.BlockHeaderHash(block.Header))
		require.Equal(t, block, retrievedBlock)

		for txNum := 0; txNum < len(block.Data.Data); txNum++ {
			txEnvBytes := block.Data.Data[txNum]
			txEnv, _ := protoutil.GetEnvelopeFromBlock(txEnvBytes)
			txid, err := protoutil.GetOrComputeTxIDFromEnvelope(txEnvBytes)
			require.NoError(t, err)

			retrievedBlock, _ := store.RetrieveBlockByTxID(txid)
			require.Equal(t, block, retrievedBlock)

			retrievedTxEnv, _ := store.RetrieveTxByID(txid)
			require.Equal(t, txEnv, retrievedTxEnv)

			retrievedTxEnv, _ = store.RetrieveTxByBlockNumTranNum(uint64(blockNum), uint64(txNum))
			require.Equal(t, txEnv, retrievedTxEnv)

			retrievedTxValCode, blkNum, err := store.RetrieveTxValidationCodeByTxID(txid)
			require.NoError(t, err)
			require.Equal(t, flags.Flag(txNum), retrievedTxValCode)
			require.Equal(t, uint64(blockNum), blkNum)
		}
	}
}

func checkWithWrongInputs(t *testing.T, store *BlockStore, numBlocks int) {
	block, err := store.RetrieveBlockByHash([]byte("non-existent-hash"))
	require.Nil(t, block)
	requireNotFoundError(t, err, "block hash")

	block, err = store.RetrieveBlockByTxID("non-existent-txid")
	require.Nil(t, block)
	requireNotFoundError(t, err, "transaction ID [non-existent-txid]")

	tx, err := store.RetrieveTxByID("non-existent-txid")
	require.Nil(t, tx)
	requireNotFoundError(t, err, "transaction ID [non-existent-txid]")

	tx, err = store.RetrieveTxByBlockNumTranNum(uint64(numBlocks+1), uint64(0))
	require.Nil(t, tx)
	requireNotFoundError(t, err, fmt.Sprintf("blockNumber, transactionNumber <%d, 0>", numBlocks+1))

	txCode, blkNum, err := store.RetrieveTxValidationCodeByTxID("non-existent-txid")
	require.Equal(t, peer.TxValidationCode(-1), txCode)
	require.Equal(t, uint64(0), blkNum)
	requireNotFoundError(t, err, "transaction ID [non-existent-txid]")
}

func TestBlockStoreProvider(t *testing.T) {
	env := newTestEnv(t, NewConf(t.TempDir(), 0))
	defer env.Cleanup()

	provider := env.provider
	storeNames, err := provider.List()
	require.NoError(t, err)
	require.Empty(t, storeNames)

	var stores []*BlockStore
	numStores := 10
	for i := range numStores {
		store, _ := provider.Open(constructLedgerid(i))
		defer store.Shutdown()
		stores = append(stores, store)
	}
	require.Equal(t, numStores, len(stores))

	storeNames, err = provider.List()
	require.NoError(t, err)
	require.Equal(t, numStores, len(storeNames))

	for i := range numStores {
		exists, err := provider.Exists(constructLedgerid(i))
		require.NoError(t, err)
		require.Equal(t, true, exists)
	}

	exists, err := provider.Exists(constructLedgerid(numStores + 1))
	require.NoError(t, err)
	require.Equal(t, false, exists)
}

func TestDrop(t *testing.T) {
	env := newTestEnv(t, NewConf(t.TempDir(), 0))
	defer env.Cleanup()

	provider := env.provider
	store1, err := provider.Open("ledger1")
	require.NoError(t, err)
	defer store1.Shutdown()
	store2, err := provider.Open("ledger2")
	require.NoError(t, err)
	defer store2.Shutdown()

	blocks1 := addBlocksToStore(t, store1, 5)
	blocks2 := addBlocksToStore(t, store2, 10)

	checkBlocks(t, blocks1, store1)
	checkBlocks(t, blocks2, store2)
	storeNames, err := provider.List()
	require.NoError(t, err)
	require.ElementsMatch(t, storeNames, []string{"ledger1", "ledger2"})

	require.NoError(t, provider.Drop("ledger1"))

	// verify ledger1 block dir and block indexes are deleted
	exists, err := provider.Exists("ledger1")
	require.NoError(t, err)
	require.False(t, exists)

	empty, err := provider.pebbleProvider.GetDBHandle("ledger1").IsEmpty()
	require.NoError(t, err)
	require.True(t, empty)

	// verify ledger2 ledger data are remained same
	checkBlocks(t, blocks2, store2)
	storeNames, err = provider.List()
	require.NoError(t, err)
	require.ElementsMatch(t, storeNames, []string{"ledger2"})

	// drop again should return no error
	require.NoError(t, provider.Drop("ledger1"))

	// verify "ledger1" store can be opened again after remove, but it is an empty store
	newstore1, err := provider.Open("ledger1")
	require.NoError(t, err)
	bcInfo, err := newstore1.GetBlockchainInfo()
	require.NoError(t, err)
	require.Equal(t, &common.BlockchainInfo{}, bcInfo)

	// negative test
	provider.Close()
	require.EqualError(t, provider.Drop("ledger2"), "internal pebble error while obtaining db iterator: pebble: closed")
}

func TestBlocksItrContextCancel(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, NewConf(t.TempDir(), 0))
	t.Cleanup(env.Cleanup)
	store, err := env.provider.Open("testledger-ctx")
	require.NoError(t, err)
	t.Cleanup(store.Shutdown)

	// Add one block so the store is initialized
	blocks := testutil.ConstructTestBlocks(t, 1)
	require.NoError(t, store.AddBlock(blocks[0]))

	// Create a cancellable context and an iterator starting at block 1 (not yet available)
	ctx, cancel := context.WithCancel(t.Context())
	itr, err := store.RetrieveBlocks(1)
	require.NoError(t, err)
	t.Cleanup(itr.Close)

	// Next() should block waiting for block 1. Cancel the context to unblock it.
	done := make(chan any)
	var result ledger.QueryResult
	var nextErr error
	go func() {
		result, nextErr = itr.Next(ctx)
		close(done)
	}()

	// Cancel the context — this should wake up waitForBlock
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Next() did not return after context cancellation")
	}

	require.Nil(t, result)
	require.ErrorIs(t, nextErr, context.Canceled)
}

func TestBlockStorePebbleReopen(t *testing.T) {
	t.Parallel()

	conf := NewConf(t.TempDir(), 0)
	indexConfig := &IndexConfig{AttrsToIndex: attrsToIndex}
	provider, err := NewProvider(conf, indexConfig, &disabled.Provider{})
	require.NoError(t, err)
	store, err := provider.Open("ledger")
	require.NoError(t, err)

	blocks := testutil.ConstructTestBlocks(t, 2)
	require.NoError(t, store.AddBlock(blocks[0]))

	store.Shutdown()
	provider.Close()

	// Read the persisted index with Pebble, not the blockstore wrapper.
	db, err := pebble.Open(conf.getIndexDir(), &pebble.Options{ErrorIfNotExists: true})
	require.NoError(t, err)
	value, closer, err := db.Get([]byte("_\x00f"))
	require.NoError(t, err)
	require.Equal(t, dataFormatVersion(indexConfig), string(value))
	require.NoError(t, closer.Close())
	require.NoError(t, db.Close())

	provider, err = NewProvider(conf, indexConfig, &disabled.Provider{})
	require.NoError(t, err)
	t.Cleanup(provider.Close)
	store, err = provider.Open("ledger")
	require.NoError(t, err)
	t.Cleanup(store.Shutdown)

	checkBlocks(t, blocks[:1], store)

	require.NoError(t, store.AddBlock(blocks[1]))
	checkBlocks(t, blocks, store)
}

func TestBlockStoreIndexMemTableSize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		size uint64
		want string
	}{
		{name: "default", want: "mem_table_size=67108864"},
		{name: "smaller override", size: 16 << 20, want: "mem_table_size=16777216"},
		{name: "larger override", size: 128 << 20, want: "mem_table_size=134217728"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := NewConf(t.TempDir(), 0)
			conf.IndexMemTableSize = tc.size
			provider, err := NewProvider(conf, &IndexConfig{AttrsToIndex: attrsToIndex}, &disabled.Provider{})
			require.NoError(t, err)
			t.Cleanup(provider.Close)

			files, err := filepath.Glob(filepath.Join(conf.getIndexDir(), "OPTIONS-*"))
			require.NoError(t, err)
			require.Len(t, files, 1)
			options, err := os.ReadFile(files[0])
			require.NoError(t, err)
			require.Contains(t, string(options), tc.want)
		})
	}
}

func constructLedgerid(id int) string {
	return fmt.Sprintf("ledger_%d", id)
}
