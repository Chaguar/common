/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package modify implements the `fxadmin modify` commands, which apply a
// structured configuration change directly to a config block file (automating
// the manual decode/hand-edit step). Each command reads the block, applies the
// change to the embedded common.Config, and writes the block back so further
// modify commands can accumulate onto it; `compute-update --pb` then computes
// the ConfigUpdate from the original and edited blocks.
package modify

import (
	"fmt"
	"maps"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/msp"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
)

var logger = flogging.MustGetLogger("fxadmin.modify")

// Handler executes the modify commands.
type Handler struct{}

// New returns a modify command handler.
func New() *Handler {
	return &Handler{}
}

// readAndDecodeConfigBlock reads the config block file at path and decodes it
// down to its config.
func readAndDecodeConfigBlock(path string) (*helpers.ConfigBlock, error) {
	block, err := helpers.ReadConfigBlock(path)
	if err != nil {
		return nil, err
	}
	configBlock, err := helpers.DecodeConfigBlock(block)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config block %q: %w", path, err)
	}
	return configBlock, nil
}

// validateEncodeAndWriteConfigBlock checks that the block's edited config still
// builds a channel config bundle, encodes the config back into the block, and
// writes the block to the file at path, in place. An invalid edit is rejected
// here, before the file is written, rather than after the update has collected
// its endorsements.
// TODO: remove the bundle check once the orderer's ValidateNewConfig is
// integrated into fxadmin: building the same bundle is its first step.
func validateEncodeAndWriteConfigBlock(block *helpers.ConfigBlock, path string) error {
	channelID := block.ChannelHeader.GetChannelId()
	if _, err := channelconfig.NewBundle(channelID, block.Config(), factory.GetDefault()); err != nil {
		return fmt.Errorf("the edited config is not a valid channel config: %w", err)
	}
	if err := block.Encode(); err != nil {
		return err
	}
	return helpers.WriteBlock(block.Block, path)
}

// missingOrgError returns the error for an org that is not in the group named
// groupKey. When org is the MSP ID of an org of the group, the error names that
// org, as its MSP ID was likely given in place of its name; otherwise the error
// lists the orgs of the group.
func missingOrgError(groupKey string, group *cb.ConfigGroup, org string) error {
	names := slices.Sorted(maps.Keys(group.GetGroups()))
	for _, name := range names {
		if mspID, err := mspIDOf(group.GetGroups()[name]); err == nil && mspID == org {
			return errors.Newf("the %s group has no org %q; %q is the MSP ID of org %q: give the org's name",
				groupKey, org, org, name)
		}
	}
	if len(names) == 0 {
		return errors.Newf("the %s group has no org %q; it has no orgs", groupKey, org)
	}
	return errors.Newf("the %s group has no org %q; its orgs are %q", groupKey, org, names)
}

// mspIDOf returns the MSP ID of the org: the name of its MSP, a Fabric or an
// idemix one.
func mspIDOf(org *cb.ConfigGroup) (string, error) {
	value := org.GetValues()[channelconfig.MSPKey]
	if value == nil {
		return "", errors.Newf("no %s value", channelconfig.MSPKey)
	}
	mspConfig := &mspproto.MSPConfig{}
	if err := proto.Unmarshal(value.GetValue(), mspConfig); err != nil {
		return "", errors.Wrap(err, "failed to unmarshal the MSP value")
	}
	var config interface {
		proto.Message
		GetName() string
	}
	switch mspConfig.GetType() {
	case int32(msp.FABRIC):
		config = &mspproto.FabricMSPConfig{}
	case int32(msp.IDEMIX):
		config = &mspproto.IdemixMSPConfig{}
	default:
		return "", errors.Newf("unsupported MSP type %d", mspConfig.GetType())
	}
	if err := proto.Unmarshal(mspConfig.GetConfig(), config); err != nil {
		return "", errors.Wrap(err, "failed to unmarshal the MSP config")
	}
	if config.GetName() == "" {
		return "", errors.New("the MSP has no name")
	}
	return config.GetName(), nil
}
