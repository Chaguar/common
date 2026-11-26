/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"maps"
	"os"
	"slices"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/common/policydsl"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/utils/test"
)

const (
	// appRemoveTestKey is a name under the Application group that differs
	// from the MSP ID of its org, appTestNewOrg.
	appRemoveTestKey = "peer2-org"
	// appRemoveTestACL is an API of the ACLs value of the Application group.
	appRemoveTestACL = "/committerpb.QueryService/GetRows"
	// appRemoveTestPolicy is the name of the policy the tests add or replace.
	appRemoveTestPolicy = "Endorsement"
)

// TestAppRemove removes an application org, and checks the edited block: the
// org's whole group is gone, nothing else in the config changes, and the block
// still loads as a channel config of the orgs that remain. A policy or an ACL
// that still refers to the org is kept, as Fabric keeps it: the command only
// warns about it.
func TestAppRemove(t *testing.T) {
	t.Parallel()

	baseBlock := newAppRemoveTestBlock(t)

	for _, tc := range []struct {
		name  string
		block []byte
		// org is the name of the org to remove, and wantOrgs the names of the
		// application orgs that remain.
		org      string
		wantOrgs []string
	}{
		{
			name: "an org whose name is its MSP ID", block: baseBlock, org: appTestNewOrg,
			wantOrgs: []string{appTestExistingOrg},
		},
		{
			name:  "an org whose name differs from its MSP ID",
			block: withAppTestOrgKey(t, baseBlock, appTestNewOrg, appRemoveTestKey), org: appRemoveTestKey,
			wantOrgs: []string{appTestExistingOrg},
		},
		{
			// The policy that names the org's MSP ID is still satisfied by the
			// copy of the org, which keeps that MSP ID.
			name: "an org whose MSP ID another org keeps",
			block: withAppTestSignaturePolicy(t, withAppTestOrgCopy(t, baseBlock, appTestNewOrg, appTestOtherName),
				appRemoveTestPolicy, appTestNewOrg),
			org: appTestNewOrg, wantOrgs: []string{appTestExistingOrg, appTestOtherName},
		},
		{
			name:  "an org while an ACL refers to a policy of another org",
			block: withAppTestACL(t, baseBlock, "/Channel/Application/"+appTestExistingOrg+"/Readers"),
			org:   appTestNewOrg, wantOrgs: []string{appTestExistingOrg},
		},
		{
			name:  "an org that an Application policy names",
			block: withAppTestSignaturePolicy(t, baseBlock, appRemoveTestPolicy, appTestNewOrg), org: appTestNewOrg,
			wantOrgs: []string{appTestExistingOrg},
		},
		{
			name: "an org that a channel policy names", block: withAppTestChannelPolicy(t, baseBlock),
			org: appTestNewOrg, wantOrgs: []string{appTestExistingOrg},
		},
		{
			name:  "an org that an ACL refers to",
			block: withAppTestACL(t, baseBlock, "/Channel/Application/peer2/Readers"), org: appTestNewOrg,
			wantOrgs: []string{appTestExistingOrg},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			require.NoError(t, modify.New().AppRemove(tc.org, blockPath))

			// Apart from the removed org, the whole config is unchanged.
			want := nodeTestConfigOf(t, tc.block)
			delete(want.GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].Groups, tc.org)
			edited := nodeTestConfigOf(t, readNodeTestFile(t, blockPath))
			test.RequireProtoEqual(t, want, edited)
			orgs := edited.GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].GetGroups()
			require.ElementsMatch(t, tc.wantOrgs, slices.Collect(maps.Keys(orgs)))

			// The edited block still loads as a channel config.
			_, err := channelconfig.LoadConfigBlockMaterialFromFile(blockPath)
			require.NoError(t, err)

			// The block was written in place.
			info, err := os.Stat(blockPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(nodeTestBlockMode), info.Mode().Perm())
		})
	}
}

// TestAppRemoveRejects covers removals that must fail, and asserts that a
// failed removal leaves the block file unchanged.
func TestAppRemoveRejects(t *testing.T) {
	t.Parallel()

	baseBlock := newAppRemoveTestBlock(t)

	for _, tc := range []struct {
		name    string
		block   []byte
		org     string
		wantErr string
	}{
		{
			name: "an org that is not in the Application group", block: baseBlock, org: appTestOtherName,
			wantErr: `the Application group has no org "peer3"; its orgs are ["peer-org-1" "peer2"]`,
		},
		{
			name: "an orderer org", block: baseBlock, org: nodeTestOrg,
			wantErr: `the Application group has no org "orderer-org-1"; its orgs are ["peer-org-1" "peer2"]`,
		},
		{
			name:    "an org's MSP ID in place of its name",
			block:   withAppTestOrgKey(t, baseBlock, appTestNewOrg, appRemoveTestKey),
			org:     appTestNewOrg,
			wantErr: `the Application group has no org "peer2"; "peer2" is the MSP ID of org "peer2-org"`,
		},
		{
			// With no org, the Application policies would be satisfied by anyone.
			name: "the only application org", block: newAppTestBlock(t), org: appTestExistingOrg,
			wantErr: `application org "peer-org-1" is the only org of the Application group, and cannot be removed`,
		},
		{
			name: "a block with no Application group", block: withoutAppTestApplication(t, baseBlock),
			org: appTestNewOrg, wantErr: "the config has no Application group",
		},
		{
			name: "a file that is not a config block", block: []byte("not a block"), org: appTestNewOrg,
			wantErr: "unmarshal config block",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			err := modify.New().AppRemove(tc.org, blockPath)
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, tc.block)
		})
	}
}

// newAppRemoveTestBlock returns a marshaled ARMA config block of an orderer
// org, nodeTestOrg, and of two application orgs, appTestExistingOrg and
// appTestNewOrg.
func newAppRemoveTestBlock(t *testing.T) []byte {
	t.Helper()
	return newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{
		Organizations: []cryptogen.OrganizationParameters{
			removeTestOrg(nodeTestOrg, nodeTestParty),
			appTestPeerOrg(appTestExistingOrg),
			appTestPeerOrg(appTestNewOrg),
		},
	})
}

// withAppTestOrgKey returns the marshaled block with the application org under
// the name from moved to the name to. Its MSP ID is kept.
func withAppTestOrgKey(t *testing.T, marshaledBlock []byte, from, to string) []byte {
	t.Helper()
	configBlock := decodeAppTestBlock(t, marshaledBlock)
	orgs := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].GetGroups()
	require.Contains(t, orgs, from)
	orgs[to] = orgs[from]
	delete(orgs, from)
	return encodeAppTestBlock(t, configBlock)
}

// withAppTestOrgCopy returns the marshaled block with a copy of the
// application org org under the name copyName, with the same MSP ID.
func withAppTestOrgCopy(t *testing.T, marshaledBlock []byte, org, copyName string) []byte {
	t.Helper()
	configBlock := decodeAppTestBlock(t, marshaledBlock)
	orgs := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].GetGroups()
	require.Contains(t, orgs, org)
	orgs[copyName] = proto.CloneOf(orgs[org])
	return encodeAppTestBlock(t, configBlock)
}

// withAppTestSignaturePolicy returns the marshaled block with the policy
// appRemoveTestPolicy of its Application group replaced by a signature
// policy that any member of the given MSPs satisfies.
func withAppTestSignaturePolicy(t *testing.T, marshaledBlock []byte, policy string, mspIDs ...string) []byte {
	t.Helper()
	configBlock := decodeAppTestBlock(t, marshaledBlock)
	application := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
	application.GetPolicies()[policy] = appTestSignaturePolicy(mspIDs...)
	return encodeAppTestBlock(t, configBlock)
}

// withAppTestChannelPolicy returns the marshaled block with a signature
// policy, appRemoveTestPolicy, added to its channel group, that any member of
// appTestNewOrg satisfies.
func withAppTestChannelPolicy(t *testing.T, marshaledBlock []byte) []byte {
	t.Helper()
	configBlock := decodeAppTestBlock(t, marshaledBlock)
	configBlock.Config().GetChannelGroup().GetPolicies()[appRemoveTestPolicy] = appTestSignaturePolicy(appTestNewOrg)
	return encodeAppTestBlock(t, configBlock)
}

// withAppTestACL returns the marshaled block with the ACL of appRemoveTestACL
// in the Application group set to the policy reference policyRef.
func withAppTestACL(t *testing.T, marshaledBlock []byte, policyRef string) []byte {
	t.Helper()
	configBlock := decodeAppTestBlock(t, marshaledBlock)
	application := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
	value := application.GetValues()[channelconfig.ACLsKey]
	require.NotNil(t, value)
	acls := &pb.ACLs{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), acls))
	acls.Acls[appRemoveTestACL] = &pb.APIResource{PolicyRef: policyRef}
	value.Value = protoutil.MarshalOrPanic(acls)
	return encodeAppTestBlock(t, configBlock)
}

// appTestSignaturePolicy returns a config policy that any member of the given
// MSPs satisfies.
func appTestSignaturePolicy(mspIDs ...string) *cb.ConfigPolicy {
	return &cb.ConfigPolicy{
		ModPolicy: channelconfig.AdminsPolicyKey,
		Policy: &cb.Policy{
			Type:  int32(cb.Policy_SIGNATURE),
			Value: protoutil.MarshalOrPanic(policydsl.SignedByAnyMember(mspIDs)),
		},
	}
}

// decodeAppTestBlock decodes the marshaled block down to its config, for a
// helper to edit it.
func decodeAppTestBlock(t *testing.T, marshaledBlock []byte) *helpers.ConfigBlock {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	return configBlock
}

// encodeAppTestBlock encodes the edited config back into the block, and
// returns the block marshaled.
func encodeAppTestBlock(t *testing.T, configBlock *helpers.ConfigBlock) []byte {
	t.Helper()
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}
