/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/tools/fxadmin/core/modify/change"
	"github.com/Chaguar/common/utils/test"
)

// The operations of `modify app|orderer known-certs`, and the org of the
// Application group of the blocks the known-certs tests edit. The org of the
// Orderer group is nodeTestOrg.
const (
	knownTestAdd     = "add"
	knownTestRemove  = "remove"
	knownTestSet     = "set"
	knownTestPeerOrg = "peer-org-1"
)

// knownTestOrg is an org whose known certificates a test changes: its config
// group and its name in the group.
type knownTestOrg struct {
	group string
	name  string
}

// TestKnownCerts applies each operation to the known certificates of an
// application org and of an orderer org, and checks that the org's MSP holds
// the wanted list and that nothing else in the config changes: the other org's
// MSP is left as it was.
func TestKnownCerts(t *testing.T) {
	t.Parallel()

	baseBlock := newKnownTestBlock(t)
	for _, org := range []knownTestOrg{
		{group: channelconfig.ApplicationGroupKey, name: knownTestPeerOrg},
		{group: channelconfig.OrdererGroupKey, name: nodeTestOrg},
	} {
		known := knownTestCertsOf(t, baseBlock, org)
		require.GreaterOrEqual(t, len(known), 2)
		paths := writeKnownTestCerts(t, known)
		last := len(known) - 1
		// withoutLastBlock is the block without the org's last known certificate.
		withoutLastBlock := withKnownTestCerts(t, baseBlock, org, known[:last])

		for _, tc := range []struct {
			name  string
			block []byte
			op    string
			certs []string
			want  [][]byte
		}{
			{
				name: "add a certificate", block: withoutLastBlock, op: knownTestAdd,
				certs: []string{paths[last]}, want: known,
			},
			{
				name: "add skips a certificate the list holds", block: baseBlock, op: knownTestAdd,
				certs: []string{paths[0]}, want: known,
			},
			{
				name: "remove a certificate", block: baseBlock, op: knownTestRemove,
				certs: []string{paths[0]}, want: known[1:],
			},
			{
				name: "remove every certificate", block: baseBlock, op: knownTestRemove,
				certs: paths, want: nil,
			},
			{
				name: "set replaces the list, in the order given", block: baseBlock, op: knownTestSet,
				certs: []string{paths[1], paths[0]}, want: [][]byte{known[1], known[0]},
			},
		} {
			t.Run(fmt.Sprintf("%s org: %s", org.group, tc.name), func(t *testing.T) {
				t.Parallel()

				blockPath := writeNodeTestBlock(t, tc.block)
				require.NoError(t, modify.New().KnownCerts(change.KnownCerts{
					Op: tc.op, Group: org.group, Org: org.name, Certs: tc.certs, BlockPath: blockPath,
				}))
				editedBlock := readNodeTestFile(t, blockPath)
				require.Equal(t, knownTestDER(t, tc.want), knownTestDER(t, knownTestCertsOf(t, editedBlock, org)))

				// Apart from the org's known certificates, the whole config is unchanged.
				restored := withKnownTestCerts(t, editedBlock, org, knownTestCertsOf(t, tc.block, org))
				test.RequireProtoEqual(t, nodeTestConfigOf(t, tc.block), nodeTestConfigOf(t, restored))
			})
		}
	}
}

// TestKnownCertsRejects covers requests that must fail, and asserts that a
// failed request leaves the block file unchanged.
func TestKnownCertsRejects(t *testing.T) {
	t.Parallel()

	baseBlock := newKnownTestBlock(t)
	peerOrg := knownTestOrg{group: channelconfig.ApplicationGroupKey, name: knownTestPeerOrg}
	ordererOrg := knownTestOrg{group: channelconfig.OrdererGroupKey, name: nodeTestOrg}
	peerKnown := knownTestCertsOf(t, baseBlock, peerOrg)
	peerPaths := writeKnownTestCerts(t, peerKnown)
	ordererPaths := writeKnownTestCerts(t, knownTestCertsOf(t, baseBlock, ordererOrg))
	dir := t.TempDir()
	peerCA := nodeTestFabricMSPConfig(t, nodeTestConfigOf(t, baseBlock).GetChannelGroup().
		GetGroups()[channelconfig.ApplicationGroupKey].GetGroups()[knownTestPeerOrg]).GetRootCerts()[0]
	caPath := writeNodeTestFile(t, dir, "ca.pem", peerCA)
	notPEMPath := writeNodeTestFile(t, dir, "not-pem.pem", []byte("not a certificate"))
	copyPath := writeNodeTestFile(t, dir, "copy.pem", peerKnown[0])
	withoutFirstBlock := withKnownTestCerts(t, baseBlock, peerOrg, peerKnown[1:])

	for _, tc := range []struct {
		name    string
		block   []byte
		op      string
		org     knownTestOrg
		certs   []string
		wantErr string
	}{
		{
			name: "an unknown operation", block: baseBlock, op: "replace", org: peerOrg,
			certs:   []string{peerPaths[0]},
			wantErr: `unknown operation "replace"`,
		},
		{
			name: "an unknown group", block: baseBlock, op: knownTestAdd,
			org:     knownTestOrg{group: "Consortiums", name: knownTestPeerOrg},
			certs:   []string{peerPaths[0]},
			wantErr: `unknown group "Consortiums"`,
		},
		{
			name: "no certificate", block: baseBlock, op: knownTestAdd, org: peerOrg,
			wantErr: "nothing to change: no known certificate is given",
		},
		{
			name: "a file that is not PEM", block: baseBlock, op: knownTestAdd, org: peerOrg,
			certs:   []string{notPEMPath},
			wantErr: `invalid known certificates: "` + notPEMPath + `" is not a PEM-encoded certificate`,
		},
		{
			name: "a CA certificate", block: baseBlock, op: knownTestAdd, org: peerOrg,
			certs: []string{caPath},
			wantErr: `invalid known certificates: "` + caPath +
				`" is a CA certificate; a known certificate must be an identity certificate`,
		},
		{
			name: "the same certificate twice", block: baseBlock, op: knownTestSet, org: peerOrg,
			certs:   []string{peerPaths[0], copyPath},
			wantErr: "hold the same certificate",
		},
		{
			// The orderer org is not in the Application group: the tool assumes
			// that the application and the orderer orgs are different orgs.
			name: "an org of the other group", block: baseBlock, op: knownTestAdd,
			org:   knownTestOrg{group: channelconfig.ApplicationGroupKey, name: nodeTestOrg},
			certs: []string{peerPaths[0]},
			wantErr: `the Application group has no org "orderer-org-1"; ` +
				"give the org's name in the group, not its MSP ID",
		},
		{
			name: "removing a certificate the list does not hold", block: withoutFirstBlock, op: knownTestRemove,
			org: peerOrg, certs: []string{peerPaths[0]},
			wantErr: `Application org "peer-org-1": the known certificates do not hold the certificate of "` +
				peerPaths[0] + `"`,
		},
		{
			// A known certificate must be issued by a CA of the org's MSP; the
			// channel config check rejects one of another org.
			name: "a certificate of another org's CA", block: baseBlock, op: knownTestAdd, org: peerOrg,
			certs:   []string{ordererPaths[0]},
			wantErr: errUnknownAuthority,
		},
		{
			name: nonConfigBlockCase, block: []byte("not a block"), op: knownTestAdd, org: peerOrg,
			certs:   []string{peerPaths[0]},
			wantErr: errNotConfigBlock,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			err := modify.New().KnownCerts(change.KnownCerts{
				Op: tc.op, Group: tc.org.group, Org: tc.org.name, Certs: tc.certs, BlockPath: blockPath,
			})
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, tc.block)
		})
	}
}

// newKnownTestBlock returns a marshaled ARMA config block of two different
// orgs, as fxadmin assumes: the orderer org nodeTestOrg, running nodeTestParty,
// and the application org knownTestPeerOrg. Each org's MSP lists known
// certificates, issued by the org's CA.
func newKnownTestBlock(t *testing.T) []byte {
	t.Helper()
	return newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{
		Organizations: []cryptogen.OrganizationParameters{
			removeTestOrg(nodeTestOrg, nodeTestParty),
			{
				Name:   knownTestPeerOrg,
				Domain: knownTestPeerOrg + ".com",
				PeerNodes: []cryptogen.Node{
					{CommonName: "peer0", Hostname: "peer0"},
					{CommonName: "peer1", Hostname: "peer1"},
				},
			},
		},
	})
}

// knownTestCertsOf returns the known certificates of the org's MSP in the
// marshaled block.
func knownTestCertsOf(t *testing.T, marshaledBlock []byte, org knownTestOrg) [][]byte {
	t.Helper()
	group := nodeTestConfigOf(t, marshaledBlock).GetChannelGroup().GetGroups()[org.group].GetGroups()[org.name]
	require.NotNil(t, group)
	return nodeTestFabricMSPConfig(t, group).GetKnownCerts()
}

// withKnownTestCerts returns the marshaled block with the known certificates of
// the org's MSP set to certs.
func withKnownTestCerts(t *testing.T, marshaledBlock []byte, org knownTestOrg, certs [][]byte) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	group := configBlock.Config().GetChannelGroup().GetGroups()[org.group].GetGroups()[org.name]
	require.NotNil(t, group)
	fabricConfig := nodeTestFabricMSPConfig(t, group)
	fabricConfig.KnownCerts = certs
	setCATestFabricMSPConfig(t, group, fabricConfig)
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// writeKnownTestCerts writes each certificate to a file of a fresh directory
// and returns the files' paths, in the order of certs.
func writeKnownTestCerts(t *testing.T, certs [][]byte) []string {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(certs))
	for i, cert := range certs {
		paths = append(paths, writeNodeTestFile(t, dir, fmt.Sprintf("known-%d.pem", i), cert))
	}
	return paths
}

// knownTestDER returns the DER encoding of each PEM-encoded certificate, so
// that lists compare regardless of how their PEM is formatted.
func knownTestDER(t *testing.T, certs [][]byte) [][]byte {
	t.Helper()
	ders := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		block, _ := pem.Decode(cert)
		require.NotNil(t, block)
		ders = append(ders, block.Bytes)
	}
	return ders
}
