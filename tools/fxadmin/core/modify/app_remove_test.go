/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/utils/test"
)

// TestAppRemove removes one of the two application orgs of a block, and checks
// the edited block: the org's group is gone, nothing else in the config
// changes, and the block still loads as a channel config of the other org.
func TestAppRemove(t *testing.T) {
	t.Parallel()

	baseBlock := newAppRemoveTestBlock(t)
	blockPath := writeNodeTestBlock(t, baseBlock)
	require.NoError(t, modify.New().AppRemove(appTestNewOrg, blockPath))

	// Apart from the removed org, the whole config is unchanged.
	want := nodeTestConfigOf(t, baseBlock)
	delete(want.GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].Groups, appTestNewOrg)
	test.RequireProtoEqual(t, want, nodeTestConfigOf(t, readNodeTestFile(t, blockPath)))

	// The edited block loads as a channel config of the other org only.
	material, err := channelconfig.LoadConfigBlockMaterialFromFile(blockPath)
	require.NoError(t, err)
	require.Len(t, material.ApplicationOrganizations, 1)
	require.Equal(t, appTestExistingOrg, material.ApplicationOrganizations[0].MspID)

	// The block was written in place.
	info, err := os.Stat(blockPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(nodeTestBlockMode), info.Mode().Perm())
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
			wantErr: `the Application group has no org "peer3"; give the org's name in the group, not its MSP ID`,
		},
		{
			name: "an orderer org", block: baseBlock, org: nodeTestOrg,
			wantErr: `the Application group has no org "orderer-org-1"`,
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
