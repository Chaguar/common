/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"slices"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/api/ordererpb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/common/crypto/tlsgen"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/tools/fxadmin/core/modify/change"
	"github.com/Chaguar/common/utils/test"
)

// The operations of `modify party ca`.
const (
	caTestAdd     = "add"
	caTestRemove  = "remove"
	caTestSet     = "set"
	caTestNodeOUs = "node-ous"
)

// caTestCerts is the CA material of a CA test: the CA and TLS CA certificates
// of the tested org, the old ones, and of another org, the new ones, each with
// the path of a file that holds it.
type caTestCerts struct {
	oldCA, oldTLSCA, newCA, newTLSCA                 []byte
	oldCAPath, oldTLSCAPath, newCAPath, newTLSCAPath string
}

// caTestLists are the CA and TLS CA lists of an org's MSP and its parties. A
// nil list is the org MSP's list as the block has it.
type caTestLists struct {
	caCerts, tlsCACerts [][]byte
}

// caTestWant is what a CA test expects of the edited block: the org whose
// parties' lists change, the lists, and the CA its MSP's node OUs pin, nil if
// they keep the pin of the block.
type caTestWant struct {
	org         string
	lists       caTestLists
	nodeOUsCert []byte
}

// TestPartyCA applies each operation to a party's CA list, its TLS CA list, or
// both, and checks both places of the block that hold each list: the party's
// entry of the shared config, and its orderer org's Fabric MSP. Nothing else in
// the config changes.
func TestPartyCA(t *testing.T) {
	t.Parallel()

	baseBlock := newNodeTestMaterial(t).block
	certs := newCATestCerts(t, baseBlock, nodeTestOrg)
	// twoCAsBlock holds both the old and the new CAs, in each list.
	twoCAsBlock := withCATestOrgLists(t, baseBlock, nodeTestOrg, caTestLists{
		caCerts:    [][]byte{certs.oldCA, certs.newCA},
		tlsCACerts: [][]byte{certs.oldTLSCA, certs.newTLSCA},
	})

	for _, tc := range []struct {
		name      string
		block     []byte
		op        string
		signCerts []string
		tlsCerts  []string
		wantCA    [][]byte
		wantTLSCA [][]byte
	}{
		{
			name: "add a CA", block: baseBlock, op: caTestAdd,
			signCerts: []string{certs.newCAPath},
			wantCA:    [][]byte{certs.oldCA, certs.newCA}, wantTLSCA: [][]byte{certs.oldTLSCA},
		},
		{
			name: "add a TLS CA", block: baseBlock, op: caTestAdd,
			tlsCerts: []string{certs.newTLSCAPath},
			wantCA:   [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.oldTLSCA, certs.newTLSCA},
		},
		{
			name: "add to both lists", block: baseBlock, op: caTestAdd,
			signCerts: []string{certs.newCAPath}, tlsCerts: []string{certs.newTLSCAPath},
			wantCA: [][]byte{certs.oldCA, certs.newCA}, wantTLSCA: [][]byte{certs.oldTLSCA, certs.newTLSCA},
		},
		{
			name: "add skips a CA the list holds", block: baseBlock, op: caTestAdd,
			signCerts: []string{certs.oldCAPath, certs.newCAPath},
			wantCA:    [][]byte{certs.oldCA, certs.newCA}, wantTLSCA: [][]byte{certs.oldTLSCA},
		},
		{
			name: "remove a CA", block: twoCAsBlock, op: caTestRemove,
			signCerts: []string{certs.newCAPath},
			wantCA:    [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.oldTLSCA, certs.newTLSCA},
		},
		{
			name: "remove a TLS CA", block: twoCAsBlock, op: caTestRemove,
			tlsCerts: []string{certs.oldTLSCAPath},
			wantCA:   [][]byte{certs.oldCA, certs.newCA}, wantTLSCA: [][]byte{certs.newTLSCA},
		},
		{
			name: "remove from both lists", block: twoCAsBlock, op: caTestRemove,
			signCerts: []string{certs.newCAPath}, tlsCerts: []string{certs.newTLSCAPath},
			wantCA: [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.oldTLSCA},
		},
		{
			name: "set a TLS CA", block: baseBlock, op: caTestSet,
			tlsCerts: []string{certs.newTLSCAPath},
			wantCA:   [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.newTLSCA},
		},
		{
			name: "set both lists", block: twoCAsBlock, op: caTestSet,
			signCerts: []string{certs.oldCAPath}, tlsCerts: []string{certs.newTLSCAPath},
			wantCA: [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.newTLSCA},
		},
		{
			name: "set replaces a list of two CAs with another one", block: twoCAsBlock, op: caTestSet,
			tlsCerts: []string{certs.newTLSCAPath},
			wantCA:   [][]byte{certs.oldCA, certs.newCA}, wantTLSCA: [][]byte{certs.newTLSCA},
		},
		{
			name: "set replaces a list of one CA with two, in the order given", block: baseBlock, op: caTestSet,
			signCerts: []string{certs.newCAPath, certs.oldCAPath},
			tlsCerts:  []string{certs.newTLSCAPath, certs.oldTLSCAPath},
			wantCA:    [][]byte{certs.newCA, certs.oldCA}, wantTLSCA: [][]byte{certs.newTLSCA, certs.oldTLSCA},
		},
		{
			name: "set a list as it is", block: baseBlock, op: caTestSet,
			signCerts: []string{certs.oldCAPath},
			wantCA:    [][]byte{certs.oldCA}, wantTLSCA: [][]byte{certs.oldTLSCA},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			require.NoError(t, modify.New().PartyCA(change.CA{
				Op: tc.op, Party: nodeTestParty, SignCerts: tc.signCerts, TLSCerts: tc.tlsCerts, BlockPath: blockPath,
			}))
			requireCATestBlock(t, tc.block, readNodeTestFile(t, blockPath), caTestWant{
				org:   nodeTestOrg,
				lists: caTestLists{caCerts: tc.wantCA, tlsCACerts: tc.wantTLSCA},
			})
		})
	}
}

// TestPartyCAChangesEveryPartyOfTheOrg changes the CA lists of a party whose
// orderer org runs two parties. The org's parties all trust the org's MSP, so
// the lists of both parties change, whichever of them the request names.
func TestPartyCAChangesEveryPartyOfTheOrg(t *testing.T) {
	t.Parallel()

	baseBlock := withCATestOrgLists(t,
		newRemoveTestBlock(t, removeTestOrg(removeTestSharedOrg, 1, 2)), removeTestSharedOrg, caTestLists{})
	certs := newCATestCerts(t, baseBlock, removeTestSharedOrg)
	twoCAsBlock := withCATestOrgLists(t, baseBlock, removeTestSharedOrg, caTestLists{
		caCerts:    [][]byte{certs.oldCA, certs.newCA},
		tlsCACerts: [][]byte{certs.oldTLSCA, certs.newTLSCA},
	})

	for _, tc := range []struct {
		name      string
		block     []byte
		op        string
		party     uint32
		signCerts []string
		tlsCerts  []string
		want      caTestLists
	}{
		{
			name: "add through the first party", block: baseBlock, op: caTestAdd, party: 1,
			signCerts: []string{certs.newCAPath},
			want:      caTestLists{caCerts: [][]byte{certs.oldCA, certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA}},
		},
		{
			name: "remove through the second party", block: twoCAsBlock, op: caTestRemove, party: 2,
			tlsCerts: []string{certs.oldTLSCAPath},
			want: caTestLists{
				caCerts: [][]byte{certs.oldCA, certs.newCA}, tlsCACerts: [][]byte{certs.newTLSCA},
			},
		},
		{
			name: "set through the second party", block: baseBlock, op: caTestSet, party: 2,
			tlsCerts: []string{certs.newTLSCAPath},
			want:     caTestLists{caCerts: [][]byte{certs.oldCA}, tlsCACerts: [][]byte{certs.newTLSCA}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			require.NoError(t, modify.New().PartyCA(change.CA{
				Op: tc.op, Party: tc.party, SignCerts: tc.signCerts, TLSCerts: tc.tlsCerts, BlockPath: blockPath,
			}))
			editedBlock := readNodeTestFile(t, blockPath)
			require.Len(t, nodeTestSharedConfig(t, nodeTestOrderer(t, editedBlock)).GetPartiesConfig(), 2)
			requireCATestBlock(t, tc.block, editedBlock, caTestWant{org: removeTestSharedOrg, lists: tc.want})
		})
	}
}

// TestPartyCANodeOUs changes the CA lists, or the node OUs, of a party whose
// org's MSP has node OUs. node-ous points the node OUs at a CA of the list and
// keeps the lists; add, remove and set change the lists and keep the node OUs,
// so once node-ous has moved them, set and remove can drop the old CA. Unless
// the case starts after `ca add`, the org's MSP has no known certificates,
// which would have to be issued by a CA of the list too.
func TestPartyCANodeOUs(t *testing.T) {
	t.Parallel()

	nodeOUsBlock := newCATestNodeOUsBlock(t)
	baseBlock := withoutCATestKnownCerts(t, nodeOUsBlock, nodeTestOrg)
	certs := newCATestCerts(t, baseBlock, nodeTestOrg)
	baseMSP := nodeTestFabricMSPConfig(t, nodeTestOrderer(t, baseBlock).GetGroups()[nodeTestOrg])
	require.Equal(t, certs.oldCA, baseMSP.GetFabricNodeOus().GetAdminOuIdentifier().GetCertificate())
	// twoCAsBlock is the block after `ca add` of the new CA: it trusts the old
	// and the new CAs, its node OUs pin the old CA, and its known certificates
	// are the old CA's.
	twoCAsBlock := withCATestOrgLists(t, nodeOUsBlock, nodeTestOrg,
		caTestLists{caCerts: [][]byte{certs.oldCA, certs.newCA}})
	// movedBlock is the block after `ca node-ous` of the new CA: it trusts the
	// old and the new CAs, and its node OUs pin the new CA.
	movedBlock := withCATestNodeOUsPin(t,
		withCATestOrgLists(t, baseBlock, nodeTestOrg, caTestLists{caCerts: [][]byte{certs.oldCA, certs.newCA}}),
		nodeTestOrg, certs.newCA)
	// intermediateBlock trusts the old CA and another root CA, and its node OUs
	// pin an intermediate CA of that root, as the MSP allows.
	root, intermediate := newCATestIntermediateCA(t)
	intermediateBlock := withCATestNodeOUsPin(t,
		withCATestMSPCerts(t,
			withCATestOrgLists(t, baseBlock, nodeTestOrg, caTestLists{caCerts: [][]byte{certs.oldCA, root}}),
			nodeTestOrg, caTestMSPCerts{intermediateCerts: [][]byte{intermediate}}),
		nodeTestOrg, intermediate)

	for _, tc := range []struct {
		name        string
		block       []byte
		op          string
		signCerts   []string
		tlsCerts    []string
		want        caTestLists
		nodeOUsCert []byte
	}{
		{
			name: "node-ous moves the node OUs, and keeps the lists", block: twoCAsBlock, op: caTestNodeOUs,
			signCerts: []string{certs.newCAPath},
			want: caTestLists{
				caCerts: [][]byte{certs.oldCA, certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA},
			},
			nodeOUsCert: certs.newCA,
		},
		{
			name: "set after node-ous drops the old CA, and keeps the node OUs", block: movedBlock, op: caTestSet,
			signCerts: []string{certs.newCAPath},
			want:      caTestLists{caCerts: [][]byte{certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA}},
		},
		{
			name: "remove after node-ous drops the old CA, and keeps the node OUs", block: movedBlock,
			op: caTestRemove, signCerts: []string{certs.oldCAPath},
			want: caTestLists{caCerts: [][]byte{certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA}},
		},
		{
			name: "set keeps the node OUs, whatever the order of the CAs", block: baseBlock, op: caTestSet,
			signCerts: []string{certs.newCAPath, certs.oldCAPath},
			want: caTestLists{
				caCerts: [][]byte{certs.newCA, certs.oldCA}, tlsCACerts: [][]byte{certs.oldTLSCA},
			},
		},
		{
			name: "add a CA", block: baseBlock, op: caTestAdd, signCerts: []string{certs.newCAPath},
			want: caTestLists{
				caCerts: [][]byte{certs.oldCA, certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA},
			},
		},
		{
			name: "set the TLS CA list", block: baseBlock, op: caTestSet, tlsCerts: []string{certs.newTLSCAPath},
			want: caTestLists{caCerts: [][]byte{certs.oldCA}, tlsCACerts: [][]byte{certs.newTLSCA}},
		},
		{
			name: "add a CA while the node OUs pin an intermediate CA", block: intermediateBlock, op: caTestAdd,
			signCerts: []string{certs.newCAPath},
			want: caTestLists{
				caCerts: [][]byte{certs.oldCA, root, certs.newCA}, tlsCACerts: [][]byte{certs.oldTLSCA},
			},
		},
		{
			name: "set the TLS CA list while the node OUs pin an intermediate CA", block: intermediateBlock,
			op: caTestSet, tlsCerts: []string{certs.newTLSCAPath},
			want: caTestLists{caCerts: [][]byte{certs.oldCA, root}, tlsCACerts: [][]byte{certs.newTLSCA}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			require.NoError(t, modify.New().PartyCA(change.CA{
				Op: tc.op, Party: nodeTestParty, SignCerts: tc.signCerts, TLSCerts: tc.tlsCerts, BlockPath: blockPath,
			}))
			requireCATestBlock(t, tc.block, readNodeTestFile(t, blockPath), caTestWant{
				org: nodeTestOrg, lists: tc.want, nodeOUsCert: tc.nodeOUsCert,
			})
		})
	}
}

// TestPartyCARejects covers requests that must fail, and asserts that a failed
// request leaves the block file unchanged.
func TestPartyCARejects(t *testing.T) {
	t.Parallel()

	material := newNodeTestMaterial(t)
	baseBlock := material.block
	certs := newCATestCerts(t, baseBlock, nodeTestOrg)
	nodeOUsBlock := newCATestNodeOUsBlock(t)
	nodeOUsCerts := newCATestCerts(t, nodeOUsBlock, nodeTestOrg)
	nodeOUsTwoCAsBlock := withCATestOrgLists(t, withoutCATestKnownCerts(t, nodeOUsBlock, nodeTestOrg), nodeTestOrg,
		caTestLists{caCerts: [][]byte{nodeOUsCerts.oldCA, nodeOUsCerts.newCA}})
	// nodeOUsMovedBlock trusts the old and the new CAs, its node OUs pin the new
	// CA, and its known certificates are still the old CA's.
	nodeOUsMovedBlock := withCATestNodeOUsPin(t, withCATestOrgLists(t, nodeOUsBlock, nodeTestOrg,
		caTestLists{caCerts: [][]byte{nodeOUsCerts.oldCA, nodeOUsCerts.newCA}}), nodeTestOrg, nodeOUsCerts.newCA)
	// nodeOUsDivergedBlock lists the new CA in the party's CA list but not in
	// its org MSP's root certificates.
	nodeOUsDivergedBlock := withCATestMSPCerts(t, nodeOUsTwoCAsBlock, nodeTestOrg,
		caTestMSPCerts{rootCerts: [][]byte{nodeOUsCerts.oldCA}})
	dir := t.TempDir()
	notPEMPath := writeNodeTestFile(t, dir, "not-pem.pem", []byte("not a certificate"))
	nodeCertPath := writeNodeTestFile(t, dir, "node.pem", material.newSignCert)
	oldCACopyPath := writeNodeTestFile(t, dir, "old-ca-copy.pem", certs.oldCA)
	bundlePath := writeNodeTestFile(t, dir, "bundle.pem", slices.Concat(certs.oldCA, certs.newCA))

	for _, tc := range []struct {
		name      string
		block     []byte
		op        string
		party     uint32
		signCerts []string
		tlsCerts  []string
		wantErr   string
	}{
		{
			name: "an unknown operation", block: baseBlock, op: "replace", party: nodeTestParty,
			signCerts: []string{certs.newCAPath},
			wantErr:   `unknown operation "replace"`,
		},
		{
			name: "no certificate", block: baseBlock, op: caTestAdd, party: nodeTestParty,
			wantErr: "nothing to change: no CA or TLS CA certificate is given",
		},
		{
			name: "a file that is not PEM", block: baseBlock, op: caTestAdd, party: nodeTestParty,
			signCerts: []string{notPEMPath},
			wantErr:   "invalid CA certificates: " + `"` + notPEMPath + `" is not a PEM-encoded certificate`,
		},
		{
			name: "a certificate that is not a CA", block: baseBlock, op: caTestAdd, party: nodeTestParty,
			tlsCerts: []string{nodeCertPath},
			wantErr:  "invalid TLS CA certificates: " + `"` + nodeCertPath + `" is not a CA certificate`,
		},
		{
			name: "the same certificate twice", block: baseBlock, op: caTestSet, party: nodeTestParty,
			signCerts: []string{certs.oldCAPath, oldCACopyPath},
			wantErr:   "hold the same certificate",
		},
		{
			// Only the first certificate of a bundle would be read, and set would
			// drop the others.
			name: "a file of several certificates", block: baseBlock, op: caTestSet, party: nodeTestParty,
			signCerts: []string{bundlePath},
			wantErr: `"` + bundlePath + `" holds more than one PEM block; ` +
				"give each CA certificate in a file of its own",
		},
		{
			name: "an unknown party", block: baseBlock, op: caTestAdd, party: nodeTestParty + 1,
			signCerts: []string{certs.newCAPath},
			wantErr:   "the shared config has no party 2",
		},
		{
			name: "a party without a consenter", block: withRemoveTestConsenters(t, baseBlock, nil),
			op: caTestAdd, party: nodeTestParty, signCerts: []string{certs.newCAPath},
			wantErr: "the consenter mapping has no consenter of party 1",
		},
		{
			name: "removing a CA the list does not hold", block: baseBlock, op: caTestRemove, party: nodeTestParty,
			signCerts: []string{certs.newCAPath},
			wantErr:   `the CA list of party 1 does not hold the certificate of "` + certs.newCAPath + `"`,
		},
		{
			name: "removing the only TLS CA", block: baseBlock, op: caTestRemove, party: nodeTestParty,
			tlsCerts: []string{certs.oldTLSCAPath},
			wantErr:  "the TLS CA list of party 1 cannot be left empty",
		},
		{
			// Without node OUs, the org's MSP lists its admin certificate, which
			// the old CA issued, so it rejects a CA list without the old CA.
			name: "setting a CA that did not issue the org's admins", block: baseBlock, op: caTestSet,
			party: nodeTestParty, signCerts: []string{certs.newCAPath},
			wantErr: "the supplied identity is not valid: x509: certificate signed by unknown authority",
		},
		{
			// The node OUs already pin the new CA, but the org's MSP still lists
			// known certificates, which the old CA issued, so it rejects a CA
			// list without the old CA.
			name: "setting a CA that did not issue the org's known certificates", block: nodeOUsMovedBlock,
			op: caTestSet, party: nodeTestParty, signCerts: []string{nodeOUsCerts.newCAPath},
			wantErr: "the supplied identity is not valid: x509: certificate signed by unknown authority",
		},
		{
			// Only node-ous moves the node OUs, so set may not drop the CA they
			// pin.
			name: "setting a list without the CA the node OUs pin", block: nodeOUsBlock, op: caTestSet,
			party: nodeTestParty, signCerts: []string{nodeOUsCerts.newCAPath},
			wantErr: "which is not in the CA list; first point them at a CA of the list, " +
				"with `fxadmin modify party ca node-ous`",
		},
		{
			name: "removing the CA the node OUs pin", block: nodeOUsTwoCAsBlock, op: caTestRemove,
			party: nodeTestParty, signCerts: []string{nodeOUsCerts.oldCAPath},
			wantErr: `orderer org "orderer-org-1": the node OUs pin the CA "CN=orderer-org-1-CA,`,
		},
		{
			name: "node-ous with two CAs", block: nodeOUsBlock, op: caTestNodeOUs, party: nodeTestParty,
			signCerts: []string{nodeOUsCerts.oldCAPath, nodeOUsCerts.newCAPath},
			wantErr:   "node-ous takes exactly one CA certificate, and no TLS CA certificate",
		},
		{
			name: "node-ous with a TLS CA", block: nodeOUsBlock, op: caTestNodeOUs, party: nodeTestParty,
			signCerts: []string{nodeOUsCerts.oldCAPath}, tlsCerts: []string{nodeOUsCerts.oldTLSCAPath},
			wantErr: "node-ous takes exactly one CA certificate, and no TLS CA certificate",
		},
		{
			// The node OUs can only pin a CA the MSP trusts: `ca add` it first.
			name: "node-ous with a CA the list does not hold", block: nodeOUsBlock, op: caTestNodeOUs,
			party: nodeTestParty, signCerts: []string{nodeOUsCerts.newCAPath},
			wantErr: `orderer org "orderer-org-1": the CA list of party 1 does not hold the certificate of "` +
				nodeOUsCerts.newCAPath + `"`,
		},
		{
			// The party's CA list holds the CA, but the org MSP does not.
			name: "node-ous with a CA the MSP does not hold", block: nodeOUsDivergedBlock, op: caTestNodeOUs,
			party: nodeTestParty, signCerts: []string{nodeOUsCerts.newCAPath},
			wantErr: `orderer org "orderer-org-1": the root and intermediate certificates of the MSP ` +
				`do not hold the certificate of "` + nodeOUsCerts.newCAPath + `"`,
		},
		{
			name: "node-ous on an MSP without node OUs", block: baseBlock, op: caTestNodeOUs, party: nodeTestParty,
			signCerts: []string{certs.oldCAPath},
			wantErr:   "the MSP has no node OUs that pin a CA",
		},
		{
			name: "a non-config block", block: []byte("not a block"), op: caTestAdd, party: nodeTestParty,
			signCerts: []string{certs.newCAPath},
			wantErr:   "failed to unmarshal config block",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			err := modify.New().PartyCA(change.CA{
				Op: tc.op, Party: tc.party, SignCerts: tc.signCerts, TLSCerts: tc.tlsCerts, BlockPath: blockPath,
			})
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, tc.block)
		})
	}
}

// requireCATestBlock asserts that the edited block holds the wanted CA lists in
// the shared config entry of each party, all of which are the org's, and in the
// org's MSP, whose node OUs pin the wanted CA. Nothing else in the config
// changes.
func requireCATestBlock(t *testing.T, baseBlock, editedBlock []byte, want caTestWant) {
	t.Helper()
	base := nodeTestOrderer(t, baseBlock)
	edited := nodeTestOrderer(t, editedBlock)

	// Each party's entry holds the lists; nothing else of the shared config changes.
	wantShared := nodeTestSharedConfig(t, base)
	for _, party := range wantShared.GetPartiesConfig() {
		party.CACerts = want.lists.caCerts
		party.TLSCACerts = want.lists.tlsCACerts
	}
	test.RequireProtoEqual(t, wantShared, nodeTestSharedConfig(t, edited))

	// The org's MSP holds the same lists, and its node OUs pin the wanted CA;
	// nothing else of the MSP changes.
	wantMSP := nodeTestFabricMSPConfig(t, base.GetGroups()[want.org])
	wantMSP.RootCerts = want.lists.caCerts
	wantMSP.TlsRootCerts = want.lists.tlsCACerts
	if want.nodeOUsCert != nil {
		nodeOUs := wantMSP.GetFabricNodeOus()
		for _, identifier := range []*mspproto.FabricOUIdentifier{
			nodeOUs.GetClientOuIdentifier(), nodeOUs.GetPeerOuIdentifier(),
			nodeOUs.GetAdminOuIdentifier(), nodeOUs.GetOrdererOuIdentifier(),
		} {
			require.NotEmpty(t, identifier.GetCertificate())
			identifier.Certificate = want.nodeOUsCert
		}
	}
	test.RequireProtoEqual(t, wantMSP, nodeTestFabricMSPConfig(t, edited.GetGroups()[want.org]))

	// Apart from those two values, the whole config is unchanged.
	restored := nodeTestConfigOf(t, editedBlock)
	restoredOrderer := restored.GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	restoredOrderer.Values[channelconfig.ConsensusTypeKey] = base.GetValues()[channelconfig.ConsensusTypeKey]
	baseMSP := base.GetGroups()[want.org].GetValues()[channelconfig.MSPKey]
	restoredOrderer.Groups[want.org].Values[channelconfig.MSPKey] = baseMSP
	test.RequireProtoEqual(t, nodeTestConfigOf(t, baseBlock), restored)
}

// newCATestCerts returns the CA material of a CA test of the org of the block:
// the old CAs are the org's, as its MSP lists them, and the new ones those of
// another org, generated for the test.
func newCATestCerts(t *testing.T, marshaledBlock []byte, org string) *caTestCerts {
	t.Helper()
	orgMSP := nodeTestFabricMSPConfig(t, nodeTestOrderer(t, marshaledBlock).GetGroups()[org])
	require.Len(t, orgMSP.GetRootCerts(), 1)
	require.Len(t, orgMSP.GetTlsRootCerts(), 1)
	joining, _ := newJoiningParty(t)

	dir := t.TempDir()
	certs := &caTestCerts{
		oldCA:    orgMSP.GetRootCerts()[0],
		oldTLSCA: orgMSP.GetTlsRootCerts()[0],
		newCA:    joining.GetCACerts()[0],
		newTLSCA: joining.GetTLSCACerts()[0],
	}
	certs.oldCAPath = writeNodeTestFile(t, dir, "old-ca.pem", certs.oldCA)
	certs.oldTLSCAPath = writeNodeTestFile(t, dir, "old-tlsca.pem", certs.oldTLSCA)
	certs.newCAPath = writeNodeTestFile(t, dir, "new-ca.pem", certs.newCA)
	certs.newTLSCAPath = writeNodeTestFile(t, dir, "new-tlsca.pem", certs.newTLSCA)
	return certs
}

// newCATestNodeOUsBlock returns a marshaled ARMA config block of nodeTestOrg
// alone, running nodeTestParty, whose MSP has node OUs that pin the org's CA,
// and lists the org's nodes as known certificates. The party's CA and TLS CA
// lists are the org MSP's.
func newCATestNodeOUsBlock(t *testing.T) []byte {
	t.Helper()
	return withCATestOrgLists(t, newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{
		Organizations: []cryptogen.OrganizationParameters{removeTestOrg(nodeTestOrg, nodeTestParty)},
		EnableNodeOUs: true,
	}), nodeTestOrg, caTestLists{})
}

// withoutCATestKnownCerts returns the marshaled block with no known
// certificates in the org's MSP.
func withoutCATestKnownCerts(t *testing.T, marshaledBlock []byte, org string) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	group := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey].GetGroups()[org]
	require.NotNil(t, group)
	fabricConfig := nodeTestFabricMSPConfig(t, group)
	require.NotEmpty(t, fabricConfig.GetKnownCerts())
	fabricConfig.KnownCerts = nil
	setCATestFabricMSPConfig(t, group, fabricConfig)
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// withCATestNodeOUsPin returns the marshaled block with every node OU of the
// org's MSP that pins a CA pinning cert instead.
func withCATestNodeOUsPin(t *testing.T, marshaledBlock []byte, org string, cert []byte) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	group := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey].GetGroups()[org]
	require.NotNil(t, group)
	fabricConfig := nodeTestFabricMSPConfig(t, group)
	nodeOUs := fabricConfig.GetFabricNodeOus()
	for _, identifier := range []*mspproto.FabricOUIdentifier{
		nodeOUs.GetClientOuIdentifier(), nodeOUs.GetPeerOuIdentifier(),
		nodeOUs.GetAdminOuIdentifier(), nodeOUs.GetOrdererOuIdentifier(),
	} {
		require.NotEmpty(t, identifier.GetCertificate())
		identifier.Certificate = cert
	}
	setCATestFabricMSPConfig(t, group, fabricConfig)
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// caTestMSPCerts are certificate lists to set in an org's MSP alone, not in its
// parties' shared config entries. A nil list is left as the block has it.
type caTestMSPCerts struct {
	rootCerts, intermediateCerts [][]byte
}

// withCATestMSPCerts returns the marshaled block with the org's MSP holding the
// given root and intermediate certificates.
func withCATestMSPCerts(t *testing.T, marshaledBlock []byte, org string, certs caTestMSPCerts) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	group := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey].GetGroups()[org]
	require.NotNil(t, group)
	fabricConfig := nodeTestFabricMSPConfig(t, group)
	if certs.rootCerts != nil {
		fabricConfig.RootCerts = certs.rootCerts
	}
	if certs.intermediateCerts != nil {
		fabricConfig.IntermediateCerts = certs.intermediateCerts
	}
	setCATestFabricMSPConfig(t, group, fabricConfig)
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// newCATestIntermediateCA returns a root CA certificate and the certificate of
// an intermediate CA it issued, both PEM-encoded.
func newCATestIntermediateCA(t *testing.T) (root, intermediate []byte) {
	t.Helper()
	rootCA, err := tlsgen.NewCA()
	require.NoError(t, err)
	intermediateCA, err := rootCA.NewIntermediateCA()
	require.NoError(t, err)
	return rootCA.CertBytes(), intermediateCA.CertBytes()
}

// withCATestOrgLists returns the marshaled block with the CA and TLS CA lists
// of the org's MSP, and of every party of the shared config, set to lists. All
// the parties of the block must be the org's.
func withCATestOrgLists(t *testing.T, marshaledBlock []byte, org string, lists caTestLists) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	orderer := configBlock.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	require.Contains(t, orderer.GetGroups(), org)

	group := orderer.GetGroups()[org]
	fabricConfig := nodeTestFabricMSPConfig(t, group)
	if lists.caCerts != nil {
		fabricConfig.RootCerts = lists.caCerts
	}
	if lists.tlsCACerts != nil {
		fabricConfig.TlsRootCerts = lists.tlsCACerts
	}
	setCATestFabricMSPConfig(t, group, fabricConfig)

	shared := nodeTestSharedConfig(t, orderer)
	for _, party := range shared.GetPartiesConfig() {
		party.CACerts = fabricConfig.GetRootCerts()
		party.TLSCACerts = fabricConfig.GetTlsRootCerts()
	}
	setCATestSharedConfig(t, orderer, shared)

	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// setCATestSharedConfig sets the shared config of the Orderer group, the
// metadata of its ConsensusType value.
func setCATestSharedConfig(t *testing.T, orderer *cb.ConfigGroup, shared *ordererpb.SharedConfig) {
	t.Helper()
	value := orderer.GetValues()[channelconfig.ConsensusTypeKey]
	consensusType := &ab.ConsensusType{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), consensusType))
	consensusType.Metadata = protoutil.MarshalOrPanic(shared)
	value.Value = protoutil.MarshalOrPanic(consensusType)
}

// setCATestFabricMSPConfig sets the Fabric MSP config of an org group.
func setCATestFabricMSPConfig(t *testing.T, org *cb.ConfigGroup, fabricConfig *msppb.FabricMSPConfig) {
	t.Helper()
	value := org.GetValues()[channelconfig.MSPKey]
	mspConfig := &mspproto.MSPConfig{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), mspConfig))
	mspConfig.Config = protoutil.MarshalOrPanic(fabricConfig)
	value.Value = protoutil.MarshalOrPanic(mspConfig)
}
