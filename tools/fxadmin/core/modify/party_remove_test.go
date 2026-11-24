/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"fmt"
	"os"
	"slices"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/ordererpb"
	"github.com/Chaguar/common/api/types"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/common/policies"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/configtxgen"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/utils/test"
)

const (
	// Orderer orgs of the blocks the remove tests edit: removeTestOrg1 runs
	// party 1, removeTestOrg2 runs party 2, and removeTestSharedOrg runs both.
	removeTestOrg1      = "orderer-org-1"
	removeTestOrg2      = "orderer-org-2"
	removeTestSharedOrg = "orderer-org-shared"
	// removeTestMaxPartyID is the MaxPartyID of the blocks the remove tests edit.
	removeTestMaxPartyID = 2
	// Ports of each party's router, assembler and consenter.
	removeTestRouterPort    = 7050
	removeTestAssemblerPort = 7060
	removeTestConsenterPort = 7052
)

// TestPartyRemove removes each party of a block of two parties, each with its
// own orderer org, and checks every place of the block that holds a party: the
// shared config's PartiesConfig, where MaxPartyID is kept; the Orderers
// consenter mapping; the orderer org group, which is removed; and the
// BlockValidation policy. Nothing else in the config changes, and the edited
// block still loads as a channel config.
func TestPartyRemove(t *testing.T) {
	t.Parallel()

	baseBlock := newRemoveTestBlock(t, removeTestOrg(removeTestOrg1, 1), removeTestOrg(removeTestOrg2, 2))

	for _, tc := range []struct {
		name       string
		partyID    uint32
		removedOrg string
		keptOrg    string
	}{
		{name: "the first party", partyID: 1, removedOrg: removeTestOrg1, keptOrg: removeTestOrg2},
		{name: "the last party", partyID: 2, removedOrg: removeTestOrg2, keptOrg: removeTestOrg1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, baseBlock)
			require.NoError(t, modify.New().PartyRemove(tc.partyID, blockPath))

			editedBlock := readNodeTestFile(t, blockPath)
			base := nodeTestOrderer(t, baseBlock)
			edited := nodeTestOrderer(t, editedBlock)

			// The shared config no longer lists the party, and MaxPartyID is kept.
			wantShared := nodeTestSharedConfig(t, base)
			wantShared.PartiesConfig = removeTestPartiesWithout(wantShared.GetPartiesConfig(), tc.partyID)
			test.RequireProtoEqual(t, wantShared, nodeTestSharedConfig(t, edited))
			require.EqualValues(t, removeTestMaxPartyID, nodeTestSharedConfig(t, edited).GetMaxPartyID())

			// The consenter mapping no longer lists the party's consenter.
			wantConsenters := removeTestConsentersWithout(consentersFromGroup(t, base), tc.partyID)
			test.RequireProtoEqual(t,
				&cb.Orderers{ConsenterMapping: wantConsenters},
				&cb.Orderers{ConsenterMapping: consentersFromGroup(t, edited)})

			// The party's org is removed, and the other org is unchanged.
			require.NotContains(t, edited.GetGroups(), tc.removedOrg)
			test.RequireProtoEqual(t, base.GetGroups()[tc.keptOrg], edited.GetGroups()[tc.keptOrg])

			// BlockValidation is a BFT quorum over the remaining consenters, with
			// the same mod_policy and version as before.
			requireBlockValidation(t, base, edited, wantConsenters)

			// Apart from those places, the whole config is unchanged.
			restored := nodeTestConfigOf(t, editedBlock)
			restoredOrderer := restored.GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
			restoredOrderer.Values[channelconfig.ConsensusTypeKey] = base.GetValues()[channelconfig.ConsensusTypeKey]
			restoredOrderer.Values[channelconfig.OrderersKey] = base.GetValues()[channelconfig.OrderersKey]
			blockValidation := policies.BlockValidationPolicyKey
			restoredOrderer.Policies[blockValidation] = base.GetPolicies()[blockValidation]
			restoredOrderer.Groups[tc.removedOrg] = base.GetGroups()[tc.removedOrg]
			test.RequireProtoEqual(t, nodeTestConfigOf(t, baseBlock), restored)

			// The edited block loads as a channel config of the other org alone.
			material, err := channelconfig.LoadConfigBlockMaterialFromFile(blockPath)
			require.NoError(t, err)
			mspIDs := make([]string, 0, len(material.OrdererOrganizations))
			for _, ordererOrg := range material.OrdererOrganizations {
				mspIDs = append(mspIDs, ordererOrg.MspID)
			}
			require.Equal(t, []string{tc.keptOrg}, mspIDs)

			// The block was written in place.
			info, err := os.Stat(blockPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(nodeTestBlockMode), info.Mode().Perm())
		})
	}
}

// TestPartyRemoveKeepsSharedOrg removes a party whose orderer org also runs
// another party. The org is kept, and only the removed party's endpoints are
// removed from its Endpoints value.
func TestPartyRemoveKeepsSharedOrg(t *testing.T) {
	t.Parallel()

	baseBlock := newRemoveTestBlock(t, removeTestOrg(removeTestSharedOrg, 1, 2))
	base := nodeTestOrderer(t, baseBlock)
	require.Equal(t,
		slices.Concat(removeTestSharedOrgEndpoints(1), removeTestSharedOrgEndpoints(2)),
		removeTestOrgEndpoints(t, base, removeTestSharedOrg))
	blockPath := writeNodeTestBlock(t, baseBlock)

	require.NoError(t, modify.New().PartyRemove(2, blockPath))

	edited := nodeTestOrderer(t, readNodeTestFile(t, blockPath))
	wantShared := nodeTestSharedConfig(t, base)
	wantShared.PartiesConfig = removeTestPartiesWithout(wantShared.GetPartiesConfig(), 2)
	test.RequireProtoEqual(t, wantShared, nodeTestSharedConfig(t, edited))
	wantConsenters := removeTestConsentersWithout(consentersFromGroup(t, base), 2)
	test.RequireProtoEqual(t,
		&cb.Orderers{ConsenterMapping: wantConsenters},
		&cb.Orderers{ConsenterMapping: consentersFromGroup(t, edited)})
	requireBlockValidation(t, base, edited, wantConsenters)

	// The org lists only party 1's endpoints; apart from them, it is unchanged.
	require.Equal(t,
		removeTestSharedOrgEndpoints(1),
		removeTestOrgEndpoints(t, edited, removeTestSharedOrg))
	baseOrg := base.GetGroups()[removeTestSharedOrg]
	keptOrg := edited.GetGroups()[removeTestSharedOrg]
	require.NotNil(t, keptOrg)
	keptOrg.Values[channelconfig.EndpointsKey].Value = baseOrg.GetValues()[channelconfig.EndpointsKey].GetValue()
	test.RequireProtoEqual(t, baseOrg, keptOrg)
}

// TestPartyRemoveRejects covers removals that must fail, and asserts that a
// failed removal leaves the block file unchanged.
func TestPartyRemoveRejects(t *testing.T) {
	t.Parallel()

	baseBlock := newRemoveTestBlock(t, removeTestOrg(removeTestOrg1, 1), removeTestOrg(removeTestOrg2, 2))
	sharedOrgBlock := newRemoveTestBlock(t, removeTestOrg(removeTestSharedOrg, 1, 2))
	baseConsenters := consentersFromGroup(t, nodeTestOrderer(t, baseBlock))
	unknownMSPConsenters := consentersFromGroup(t, nodeTestOrderer(t, baseBlock))
	unknownMSPConsenters[1].MspId = "unknown-org"

	for _, tc := range []struct {
		name    string
		block   []byte
		partyID uint32
		wantErr string
	}{
		{
			name:    "an unknown party",
			block:   baseBlock,
			partyID: 3,
			wantErr: "the shared config has no party 3",
		},
		{
			name:    "the only party",
			block:   newRemoveTestBlock(t, removeTestOrg(removeTestOrg1, 1)),
			partyID: 1,
			wantErr: "party 1 is the only party of the shared config, and cannot be removed",
		},
		{
			name:    "a party without a consenter",
			block:   withRemoveTestConsenters(t, baseBlock, removeTestConsentersWithout(baseConsenters, 2)),
			partyID: 2,
			wantErr: "the consenter mapping has no consenter of party 2",
		},
		{
			name:    "a consenter of no orderer org",
			block:   withRemoveTestConsenters(t, baseBlock, unknownMSPConsenters),
			partyID: 2,
			wantErr: `the orderer org of party 2: no orderer org has MSP ID "unknown-org"`,
		},
		{
			name:    "a consenter of two orderer orgs",
			block:   withRemoveTestOrgCopy(t, baseBlock, removeTestOrg2, removeTestOrg2+"-copy"),
			partyID: 2,
			wantErr: `orderer orgs ["orderer-org-2" "orderer-org-2-copy"] all have MSP ID "orderer-org-2"`,
		},
		{
			name: "a malformed endpoint of a kept org",
			block: withRemoveTestOrgEndpoints(t, sharedOrgBlock, removeTestSharedOrg,
				slices.Concat(removeTestSharedOrgEndpoints(1), []string{"id=x,broadcast,router-2:7050"})...),
			partyID: 2,
			wantErr: `orderer org "orderer-org-shared": failed to parse endpoint "id=x,broadcast,router-2:7050"`,
		},
		{
			name:    nonConfigBlockCase,
			block:   []byte("not a block"),
			partyID: 1,
			wantErr: errNotConfigBlock,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			err := modify.New().PartyRemove(tc.partyID, blockPath)
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, tc.block)
		})
	}
}

// newRemoveTestBlock returns a marshaled ARMA config block of the given orderer
// orgs. Its shared config lists a party for each consenter of the orgs, whose
// ConsenterConfig is the consenter's endpoint and certificates, so that the
// shared config and the consenter mapping agree. Its MaxPartyID is
// removeTestMaxPartyID, and its BlockValidation version nodeTestPolicyVersion,
// so a test can tell that an edit keeps them.
func newRemoveTestBlock(t *testing.T, orgs ...cryptogen.OrganizationParameters) []byte {
	t.Helper()
	return newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{Organizations: orgs})
}

// newPartiesTestBlock returns the block of newRemoveTestBlock, generated with
// params, for the test's channel and the Chaguar sample profile.
func newPartiesTestBlock(t *testing.T, params cryptogen.ConfigBlockParameters) []byte {
	t.Helper()
	params.TargetPath = t.TempDir()
	params.BaseProfile = configtxgen.SampleChaguar
	params.ChannelID = testChannelID
	block, err := cryptogen.CreateOrExtendConfigBlockWithCrypto(params)
	require.NoError(t, err)
	configBlock, err := helpers.DecodeConfigBlock(block)
	require.NoError(t, err)
	orderer := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]

	consenters := consentersFromGroup(t, orderer)
	parties := make([]*ordererpb.PartyConfig, 0, len(consenters))
	for _, consenter := range consenters {
		parties = append(parties, &ordererpb.PartyConfig{
			PartyID: consenter.GetId(),
			ConsenterConfig: &ordererpb.ConsenterNodeConfig{NodeConfig: &ordererpb.NodeConfig{
				Host:          consenter.GetHost(),
				Port:          consenter.GetPort(),
				ClientTlsCert: consenter.GetClientTlsCert(),
				ServerTlsCert: consenter.GetServerTlsCert(),
				SignCert:      consenter.GetIdentity(),
			}},
		})
	}
	consensusType := &ab.ConsensusType{}
	value := orderer.GetValues()[channelconfig.ConsensusTypeKey]
	require.NoError(t, proto.Unmarshal(value.GetValue(), consensusType))
	consensusType.Metadata = protoutil.MarshalOrPanic(&ordererpb.SharedConfig{
		PartiesConfig: parties,
		MaxPartyID:    removeTestMaxPartyID,
	})
	value.Value = protoutil.MarshalOrPanic(consensusType)
	orderer.GetPolicies()[policies.BlockValidationPolicyKey].Version = nodeTestPolicyVersion

	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// removeTestOrg returns the parameters of an orderer org that runs the given
// parties, given in ascending order. Each party has a consenter, and its
// router's and assembler's endpoints are the org's.
func removeTestOrg(name string, partyIDs ...uint32) cryptogen.OrganizationParameters {
	org := cryptogen.OrganizationParameters{Name: name, Domain: name + ".com"}
	for _, id := range partyIDs {
		org.OrdererEndpoints = append(org.OrdererEndpoints,
			&types.OrdererEndpoint{
				ID: id, Host: fmt.Sprintf("router-%d", id), Port: removeTestRouterPort,
				API: []string{types.Broadcast},
			},
			&types.OrdererEndpoint{
				ID: id, Host: fmt.Sprintf("assembler-%d", id), Port: removeTestAssemblerPort,
				API: []string{types.Deliver},
			},
		)
		org.ConsenterNodes = append(org.ConsenterNodes, cryptogen.Node{
			PartyName:  fmt.Sprintf("party-%d", id),
			CommonName: fmt.Sprintf("consenter-%d", id),
			Hostname:   fmt.Sprintf("consenter-%d:%d", id, removeTestConsenterPort),
		})
	}
	return org
}

// removeTestSharedOrgEndpoints returns a party's endpoints, as the Endpoints
// value of removeTestSharedOrg lists them.
func removeTestSharedOrgEndpoints(partyID uint32) []string {
	org := removeTestSharedOrg
	return []string{
		fmt.Sprintf("id=%d,msp-id=%s,broadcast,router-%d:%d", partyID, org, partyID, removeTestRouterPort),
		fmt.Sprintf("id=%d,msp-id=%s,deliver,assembler-%d:%d", partyID, org, partyID, removeTestAssemblerPort),
	}
}

// removeTestOrgEndpoints returns the addresses of an orderer org's Endpoints
// value.
func removeTestOrgEndpoints(t *testing.T, orderer *cb.ConfigGroup, org string) []string {
	t.Helper()
	require.Contains(t, orderer.GetGroups(), org)
	addresses := &cb.OrdererAddresses{}
	value := orderer.GetGroups()[org].GetValues()[channelconfig.EndpointsKey]
	require.NoError(t, proto.Unmarshal(value.GetValue(), addresses))
	return addresses.GetAddresses()
}

// withRemoveTestOrgEndpoints returns the marshaled block with the addresses of
// the orderer org's Endpoints value replaced by addresses.
func withRemoveTestOrgEndpoints(t *testing.T, marshaledBlock []byte, org string, addresses ...string) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	orderer := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	require.Contains(t, orderer.GetGroups(), org)
	orderer.GetGroups()[org].GetValues()[channelconfig.EndpointsKey].Value = protoutil.MarshalOrPanic(
		&cb.OrdererAddresses{Addresses: addresses})
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// removeTestPartiesWithout returns the parties, except the party of partyID.
func removeTestPartiesWithout(parties []*ordererpb.PartyConfig, partyID uint32) []*ordererpb.PartyConfig {
	return slices.DeleteFunc(slices.Clone(parties), func(p *ordererpb.PartyConfig) bool {
		return p.GetPartyID() == partyID
	})
}

// removeTestConsentersWithout returns the consenters, except the consenter of
// partyID.
func removeTestConsentersWithout(consenters []*cb.Consenter, partyID uint32) []*cb.Consenter {
	return slices.DeleteFunc(slices.Clone(consenters), func(c *cb.Consenter) bool {
		return c.GetId() == partyID
	})
}

// withRemoveTestConsenters returns the marshaled block with the consenter
// mapping of its Orderers value replaced by consenters.
func withRemoveTestConsenters(t *testing.T, marshaledBlock []byte, consenters []*cb.Consenter) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	orderer := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	orderer.GetValues()[channelconfig.OrderersKey].Value = protoutil.MarshalOrPanic(&cb.Orderers{
		ConsenterMapping: consenters,
	})
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// withRemoveTestOrgCopy returns the marshaled block with a copy of the orderer
// org added under copyName, with the same MSP ID.
func withRemoveTestOrgCopy(t *testing.T, marshaledBlock []byte, org, copyName string) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	orderer := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	require.Contains(t, orderer.GetGroups(), org)
	content := protoutil.MarshalOrPanic(orderer.GetGroups()[org])
	orgCopy := &cb.ConfigGroup{}
	require.NoError(t, proto.Unmarshal(content, orgCopy))
	orderer.Groups[copyName] = orgCopy
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}
