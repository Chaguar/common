<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->
# Chaguar Common

[![Coverage Status](https://coveralls.io/repos/github/Chaguar/common/badge.svg?branch=main)](https://coveralls.io/github/Chaguar/common?branch=main)

This library encapsulates some common code across the Chaguar ecosystem.

## Origin of this code

Most of this code has been taken from [Hyperledger Fabric](https://github.com/hyperledger/fabric) v3.0.0-rc1, and has since been updated and augmented to suit Chaguar's needs.

### Config
Uses [Hyperledger Fabric Config](https://github.com/hyperledger/fabric-config) v0.3.0

- common/configtx
- tools/configtxgen

This modifies Fabric's config block:
* Added ARMA field for orderer type

### MSP
- hyperledger/fabric/msp
- hyperledger/fabric/common/channelconfig
    - bundle.go: (b *Bundle) ValidateNew(nb Resources)
- hyperledger/fabric/common/capabilities
- hyperledger/fabric/common/configtx
- hyperledger/fabric/common/policies

### Block storage

`common/ledger/blkstorage` stores block bytes in files and indexes and metadata in
[Pebble](https://github.com/cockroachdb/pebble), replacing Fabric's goleveldb backend.
Block-file and index-key encodings are unchanged. Existing goleveldb index directories
are unsupported; no migration is provided for this unreleased product.

The index memtable defaults to 64 MiB. Set `blkstorage.Conf.IndexMemTableSize` (bytes)
when constructing the provider to override it; zero selects the default. This applies
to the shared physical index DB, not each ledger. Pebble can queue roughly twice this
size before stopping writes (128 MiB with the default); cache and other allocations
are additional. Lower values reduce memory pressure but can reduce write throughput.

`pebblehelper` update batches are written once; call `Reset` and rebuild before
writing a batch again. The unused `FileLock` helper has been removed.

Closing the index provider releases and invalidates its outstanding iterators.
Subsequent movement returns false, keys/values return nil, and `Error()` reports
`pebble.ErrClosed`; reopening the provider does not revive old iterators. Keys and
values returned before close are caller-owned copies. Release iterators after use
to free resources promptly; ordinary iterator operations still require one goroutine
per iterator.

### Tools
- hyperledger/fabric/cmd/configtxgen
- hyperledger/fabric/cmd/configtxlator
- hyperledger/fabric/cmd/cryptogen
