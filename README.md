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

### Tools
- hyperledger/fabric/cmd/configtxgen
- hyperledger/fabric/cmd/configtxlator
- hyperledger/fabric/cmd/cryptogen
