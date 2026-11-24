/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/protolator/protoext/peerext"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/tools/cryptogen"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
	"github.com/Chaguar/common/tools/fxadmin/core/modify"
	"github.com/Chaguar/common/utils/test"
)

const (
	// appTestNewOrg is the name and MSP ID of the application org the tests
	// add, and appTestExistingOrg the application org of the block they edit.
	// appTestOtherName is a name that no org of the block has.
	appTestNewOrg      = "peer2"
	appTestExistingOrg = "peer-org-1"
	appTestOtherName   = "peer3"
	// The peers of each application org the tests generate.
	appTestPeer0 = "peer0"
	appTestPeer1 = "peer1"
	// The formats an organization definition is written in.
	appTestFormatYAML = "yaml"
	appTestFormatJSON = "json"
	// The keys of an organization definition.
	appTestNameKey        = "name"
	appTestConfigGroupKey = "config_group"
	// appTestRootCertsField is the field of an MSP config that holds its root
	// certificates.
	appTestRootCertsField = "root_certs"
	// appTestClientOU is the OU of the clients of an org.
	appTestClientOU = "client"
)

// TestAppAdd adds an application org from its definition, the org's name and
// its config group in the form it has in the config block, with the paths of
// its certificate files, and checks the edited block: the org's group is
// exactly the group of the definition, nothing else in the config changes, and
// the block still loads as a channel config.
func TestAppAdd(t *testing.T) {
	t.Parallel()

	baseBlock := newAppTestBlock(t)
	org := newAppTestOrgGroup(t)

	for _, tc := range []struct {
		name   string
		format string
	}{
		{name: "YAML definition", format: appTestFormatYAML},
		{name: "JSON definition, as fxadmin decode prints the group", format: appTestFormatJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, baseBlock)
			orgPath := writeAppTestDefinition(t, appTestDefinition(t, appTestNewOrg, org, tc.format))
			require.NoError(t, modify.New().AppAdd(orgPath, blockPath))

			// The org is added exactly as defined.
			editedBlock := readNodeTestFile(t, blockPath)
			edited := nodeTestConfigOf(t, editedBlock)
			application := edited.GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
			test.RequireProtoEqual(t, org, application.GetGroups()[appTestNewOrg])

			// Apart from the new org, the whole config is unchanged.
			delete(application.Groups, appTestNewOrg)
			test.RequireProtoEqual(t, nodeTestConfigOf(t, baseBlock), edited)

			// The edited block loads as a channel config that includes the new org.
			material, err := channelconfig.LoadConfigBlockMaterialFromFile(blockPath)
			require.NoError(t, err)
			mspIDs := make([]string, 0, len(material.ApplicationOrganizations))
			for _, appOrg := range material.ApplicationOrganizations {
				mspIDs = append(mspIDs, appOrg.MspID)
			}
			require.ElementsMatch(t, []string{appTestExistingOrg, appTestNewOrg}, mspIDs)

			// The block was written in place.
			info, err := os.Stat(blockPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(nodeTestBlockMode), info.Mode().Perm())
		})
	}
}

// TestAppAddREADMEDefinition adds an application org from the definition the
// fxadmin README shows, exactly as it is written there: comments, null fields,
// empty lists, the unquoted n key of the policy rules, and the certificates of
// the org given as the paths of their PEM files, relative to the directory of
// the definition. The org's MSP then holds exactly the certificates of those
// files.
func TestAppAddREADMEDefinition(t *testing.T) {
	t.Parallel()

	msp := nodeTestFabricMSPConfig(t, newAppTestOrgGroup(t))
	require.NotEmpty(t, msp.GetAdmins())
	require.GreaterOrEqual(t, len(msp.GetKnownCerts()), 2)
	known := msp.GetKnownCerts()[:2]
	dir := t.TempDir()
	for path, cert := range map[string][]byte{
		"crypto/peer2/ca/ca-cert.pem":                     msp.GetRootCerts()[0],
		"crypto/peer2/users/Admin/msp/signcerts/cert.pem": msp.GetAdmins()[0],
		"crypto/peer2/tlsca/tlsca-cert.pem":               msp.GetTlsRootCerts()[0],
		"crypto/peer2/users/User1/msp/signcerts/cert.pem": known[0],
		"crypto/peer2/users/User2/msp/signcerts/cert.pem": known[1],
	} {
		writeDefinitionFile(t, dir, path, cert)
	}

	blockPath := writeNodeTestBlock(t, newAppTestBlock(t))
	orgPath := writeAppTestDefinitionIn(t, dir, appTestREADMEDefinition)
	require.NoError(t, modify.New().AppAdd(orgPath, blockPath))

	application := nodeTestConfigOf(t, readNodeTestFile(t, blockPath)).GetChannelGroup().
		GetGroups()[channelconfig.ApplicationGroupKey]
	added := application.GetGroups()[appTestNewOrg]
	require.NotNil(t, added)
	require.Len(t, added.GetPolicies(), 4)
	addedMSP := nodeTestFabricMSPConfig(t, added)
	require.Equal(t, appTestNewOrg, addedMSP.GetName())
	require.Equal(t, [][]byte{msp.GetRootCerts()[0]}, addedMSP.GetRootCerts())
	require.Equal(t, [][]byte{msp.GetAdmins()[0]}, addedMSP.GetAdmins())
	require.Equal(t, [][]byte{msp.GetTlsRootCerts()[0]}, addedMSP.GetTlsRootCerts())
	require.Equal(t, known, addedMSP.GetKnownCerts())
	require.Nil(t, addedMSP.GetFabricNodeOus())
}

// TestAppAddNodeOUs adds an org whose MSP sets node OUs, enabled or not: the
// client OU pins the org's CA, given by the path of its file, and the other OUs
// pin no CA, which the definition gives as an empty certificate, as `fxadmin
// decode` prints it. The MSP reads the node OUs, and accepts an OU that pins
// no CA, whether they are enabled or not.
func TestAppAddNodeOUs(t *testing.T) {
	t.Parallel()

	baseOrg := newAppTestOrgGroup(t)
	caCert := nodeTestFabricMSPConfig(t, baseOrg).GetRootCerts()[0]

	for _, tc := range []struct {
		name   string
		enable bool
	}{
		{name: "node OUs enabled", enable: true},
		{name: "node OUs disabled", enable: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fabricConfig := nodeTestFabricMSPConfig(t, baseOrg)
			fabricConfig.FabricNodeOus = &mspproto.FabricNodeOUs{
				Enable: tc.enable,
				ClientOuIdentifier: &mspproto.FabricOUIdentifier{
					Certificate: caCert, OrganizationalUnitIdentifier: appTestClientOU,
				},
				PeerOuIdentifier:    &mspproto.FabricOUIdentifier{OrganizationalUnitIdentifier: "peer"},
				AdminOuIdentifier:   &mspproto.FabricOUIdentifier{OrganizationalUnitIdentifier: "admin"},
				OrdererOuIdentifier: &mspproto.FabricOUIdentifier{OrganizationalUnitIdentifier: "orderer"},
			}
			org := withAppTestFabricMSPConfig(t, baseOrg, fabricConfig)

			// The client OU's CA is given by the path of its file; the other OUs
			// keep the empty certificate the rendered group has.
			definition := parseDefinition(t, appTestDefinition(t, appTestNewOrg, org, appTestFormatYAML))
			renderedMSP, ok := mspConfigMapOf(childMap(t, definition, appTestConfigGroupKey))
			require.True(t, ok)
			clientOU := childMap(t, childMap(t, renderedMSP, "fabric_node_ous"), "client_ou_identifier")
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			require.NoError(t, os.WriteFile(caPath, caCert, 0o600))
			clientOU["certificate"] = caPath

			blockPath := writeNodeTestBlock(t, newAppTestBlock(t))
			orgPath := writeAppTestDefinition(t, marshalDefinition(t, definition))
			require.NoError(t, modify.New().AppAdd(orgPath, blockPath))

			application := nodeTestConfigOf(t, readNodeTestFile(t, blockPath)).GetChannelGroup().
				GetGroups()[channelconfig.ApplicationGroupKey]
			test.RequireProtoEqual(t, org, application.GetGroups()[appTestNewOrg])
		})
	}
}

// TestAppAddCopyOfAnOrg adds an application org of the block again, under
// another name. The channel config accepts two orgs with the same MSP ID when
// their MSPs are identical, and so does the command.
func TestAppAddCopyOfAnOrg(t *testing.T) {
	t.Parallel()

	baseBlock := newAppTestBlock(t)
	existing := nodeTestConfigOf(t, baseBlock).GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey].
		GetGroups()[appTestExistingOrg]
	require.NotNil(t, existing)

	blockPath := writeNodeTestBlock(t, baseBlock)
	orgPath := writeAppTestDefinition(t, appTestDefinition(t, appTestOtherName, existing, appTestFormatYAML))
	require.NoError(t, modify.New().AppAdd(orgPath, blockPath))

	application := nodeTestConfigOf(t, readNodeTestFile(t, blockPath)).GetChannelGroup().
		GetGroups()[channelconfig.ApplicationGroupKey]
	require.Len(t, application.GetGroups(), 2)
	test.RequireProtoEqual(t, existing, application.GetGroups()[appTestExistingOrg])
	test.RequireProtoEqual(t, existing, application.GetGroups()[appTestOtherName])
}

// TestAppAddRejects covers definitions and conflicts that must fail, and
// asserts that a failed add leaves the block file unchanged.
func TestAppAddRejects(t *testing.T) {
	t.Parallel()

	baseBlock := newAppTestBlock(t)
	org := newAppTestOrgGroup(t)
	orgMap := childMap(t, parseDefinition(t, appTestDefinition(t, appTestNewOrg, org, appTestFormatYAML)),
		appTestConfigGroupKey)
	withoutMSP := proto.CloneOf(org)
	delete(withoutMSP.Values, channelconfig.MSPKey)
	unpinnedOU := nodeTestFabricMSPConfig(t, org)
	unpinnedOU.OrganizationalUnitIdentifiers = []*mspproto.FabricOUIdentifier{
		{OrganizationalUnitIdentifier: appTestClientOU},
	}

	for _, tc := range []struct {
		name       string
		block      []byte
		definition string
		wantErr    string
	}{
		{
			name: "an org name already in the Application group", block: baseBlock,
			definition: appTestDefinition(t, appTestExistingOrg, org, appTestFormatYAML),
			wantErr:    `application org "peer-org-1" already exists`,
		},
		{
			// Two orgs may share an MSP ID only when their MSPs are identical; see
			// TestAppAddCopyOfAnOrg.
			name: "an org with the MSP ID of an application org but another MSP", block: baseBlock,
			definition: appTestDefinition(t, appTestNewOrg, withAppTestMSPName(t, org, appTestExistingOrg),
				appTestFormatYAML),
			wantErr: "Attempted to define two different versions of MSP",
		},
		{
			name: "no name", block: baseBlock,
			definition: marshalDefinition(t, map[string]any{appTestConfigGroupKey: orgMap}),
			wantErr:    "has no name",
		},
		{
			name: "a name that is not a string", block: baseBlock,
			definition: marshalDefinition(t, map[string]any{appTestNameKey: 5, appTestConfigGroupKey: orgMap}),
			wantErr:    "has no name",
		},
		{
			name: "no config group", block: baseBlock,
			definition: marshalDefinition(t, map[string]any{appTestNameKey: appTestNewOrg}),
			wantErr:    "has no config_group",
		},
		{
			// The old form of a definition: a Name key next to the group's own keys.
			name: "an unknown key", block: baseBlock,
			definition: marshalDefinition(t, map[string]any{"Name": appTestNewOrg, appTestConfigGroupKey: orgMap}),
			wantErr:    `has an unknown key "Name": want "name" and "config_group"`,
		},
		{
			name: "not YAML", block: baseBlock,
			definition: "name: [peer2",
			wantErr:    "failed to parse organization definition",
		},
		{
			name: "a config group key that is not a field of a config group", block: baseBlock,
			definition: marshalDefinition(t, map[string]any{
				appTestNameKey: appTestNewOrg, appTestConfigGroupKey: map[string]any{"not_a_field": 1},
			}),
			wantErr: "failed to decode the config_group of organization definition",
		},
		{
			// Unlike a node OU, an OU identifier must pin a CA.
			name: "an OU identifier with no certificate", block: baseBlock,
			definition: appTestDefinition(t, appTestNewOrg, withAppTestFabricMSPConfig(t, org, unpinnedOU),
				appTestFormatYAML),
			wantErr: "failed getting certificate for",
		},
		{
			name: "an org group without an MSP", block: baseBlock,
			definition: appTestDefinition(t, appTestNewOrg, withoutMSP, appTestFormatYAML),
			wantErr:    "the edited config is not a valid channel config",
		},
		{
			name: "a block with no Application group", block: withoutAppTestApplication(t, baseBlock),
			definition: appTestDefinition(t, appTestNewOrg, org, appTestFormatYAML),
			wantErr:    "the config has no Application group",
		},
		{
			name: "a block file that is not a config block", block: []byte("not a block"),
			definition: appTestDefinition(t, appTestNewOrg, org, appTestFormatYAML),
			wantErr:    "unmarshal config block",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, tc.block)
			orgPath := writeAppTestDefinition(t, tc.definition)
			err := modify.New().AppAdd(orgPath, blockPath)
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, tc.block)
		})
	}
}

// TestAppAddRejectsCertificateFiles covers certificate and CRL files of the
// org's MSP that must fail the checks the other modify commands make on
// certificate files, and asserts that a failed add leaves the block file
// unchanged.
func TestAppAddRejectsCertificateFiles(t *testing.T) {
	t.Parallel()

	baseBlock := newAppTestBlock(t)
	org := newAppTestOrgGroup(t)
	orgMSP := nodeTestFabricMSPConfig(t, org)
	caCert, identityCert := orgMSP.GetRootCerts()[0], orgMSP.GetAdmins()[0]
	certDir := t.TempDir()
	caPath := filepath.Join(certDir, "ca.pem")
	identityPath := filepath.Join(certDir, "identity.pem")
	notPEMPath := filepath.Join(certDir, "not-pem.pem")
	caAndKeyPath := filepath.Join(certDir, "ca-and-key.pem")
	for path, content := range map[string][]byte{
		caPath:       caCert,
		identityPath: identityCert,
		notPEMPath:   []byte("not a certificate"),
		caAndKeyPath: slices.Concat(caCert, []byte(partyTestPrivateKey)),
	} {
		require.NoError(t, os.WriteFile(path, content, 0o600))
	}

	for _, tc := range []struct {
		name string
		// field is the MSP config field the values are given in, in place of
		// its paths.
		field   string
		values  []string
		wantErr string
	}{
		{
			name: "a certificate given inline, not as the path of its file", field: appTestRootCertsField,
			values:  []string{base64.StdEncoding.EncodeToString(caCert)},
			wantErr: "root_certs: failed to read certificate",
		},
		{
			name: "a root certificate file that is not PEM", field: appTestRootCertsField, values: []string{notPEMPath},
			wantErr: `not-pem.pem" is not a PEM-encoded certificate`,
		},
		{
			name: "a certificate followed by a private key in its file", field: appTestRootCertsField,
			values:  []string{caAndKeyPath},
			wantErr: `ca-and-key.pem" holds more than one PEM block`,
		},
		{
			name: "an identity certificate as a root certificate", field: appTestRootCertsField,
			values:  []string{identityPath},
			wantErr: `identity.pem" is not a CA certificate`,
		},
		{
			name: "an identity certificate as a TLS root certificate", field: "tls_root_certs",
			values:  []string{identityPath},
			wantErr: `tls_root_certs: "` + identityPath + `" is not a CA certificate`,
		},
		{
			name: "a CA certificate as an admin certificate", field: "admins", values: []string{caPath},
			wantErr: `admins: "` + caPath + `" is a CA certificate, not the certificate of an identity`,
		},
		{
			name: "a CA certificate as a known certificate", field: "known_certs", values: []string{caPath},
			wantErr: `known_certs: "` + caPath + `" is a CA certificate, not the certificate of an identity`,
		},
		{
			name: "the same root certificate twice", field: appTestRootCertsField, values: []string{caPath, caPath},
			wantErr: `ca.pem" hold the same certificate`,
		},
		{
			name: "a certificate as a CRL", field: "revocation_list", values: []string{caPath},
			wantErr: `ca.pem" is not a PEM-encoded CRL`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blockPath := writeNodeTestBlock(t, baseBlock)
			orgPath := writeAppTestDefinition(t, appTestDefinitionWithFiles(t, org, tc.field, tc.values...))
			err := modify.New().AppAdd(orgPath, blockPath)
			require.ErrorContains(t, err, tc.wantErr)
			requireArmaBlockUnchanged(t, blockPath, baseBlock)
		})
	}
}

// newAppTestBlock returns a marshaled ARMA config block of an orderer org,
// nodeTestOrg, and of an application org, appTestExistingOrg.
func newAppTestBlock(t *testing.T) []byte {
	t.Helper()
	return newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{
		Organizations: []cryptogen.OrganizationParameters{
			removeTestOrg(nodeTestOrg, nodeTestParty),
			appTestPeerOrg(appTestExistingOrg),
		},
	})
}

// newAppTestOrgGroup returns the config group of the application org
// appTestNewOrg, as a config block generated for it stores the group: its
// policies and its MSP, with the certificates of its own crypto material.
func newAppTestOrgGroup(t *testing.T) *cb.ConfigGroup {
	t.Helper()
	block := newPartiesTestBlock(t, cryptogen.ConfigBlockParameters{
		Organizations: []cryptogen.OrganizationParameters{
			removeTestOrg(nodeTestOrg, nodeTestParty),
			appTestPeerOrg(appTestNewOrg),
		},
	})
	application := nodeTestConfigOf(t, block).GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
	org := application.GetGroups()[appTestNewOrg]
	require.NotNil(t, org)
	return org
}

// appTestPeerOrg returns the parameters of an application org of two peers.
func appTestPeerOrg(name string) cryptogen.OrganizationParameters {
	return cryptogen.OrganizationParameters{
		Name:   name,
		Domain: name + ".com",
		PeerNodes: []cryptogen.Node{
			{CommonName: appTestPeer0, Hostname: appTestPeer0 + "." + name},
			{CommonName: appTestPeer1, Hostname: appTestPeer1 + "." + name},
		},
	}
}

// withoutAppTestApplication returns the marshaled block without its
// Application group.
func withoutAppTestApplication(t *testing.T, marshaledBlock []byte) []byte {
	t.Helper()
	configBlock, err := helpers.UnmarshalAndDecodeConfigBlock(marshaledBlock)
	require.NoError(t, err)
	delete(configBlock.Config().GetChannelGroup().GetGroups(), channelconfig.ApplicationGroupKey)
	require.NoError(t, configBlock.Encode())
	return protoutil.MarshalOrPanic(configBlock.Block)
}

// withAppTestFabricMSPConfig returns a copy of the org whose MSP holds
// fabricConfig as its Fabric MSP config.
func withAppTestFabricMSPConfig(
	t *testing.T, org *cb.ConfigGroup, fabricConfig *msppb.FabricMSPConfig,
) *cb.ConfigGroup {
	t.Helper()
	withConfig := proto.CloneOf(org)
	value := withConfig.GetValues()[channelconfig.MSPKey]
	mspConfig := &mspproto.MSPConfig{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), mspConfig))
	mspConfig.Config = protoutil.MarshalOrPanic(fabricConfig)
	value.Value = protoutil.MarshalOrPanic(mspConfig)
	return withConfig
}

// withAppTestMSPName returns a copy of the org whose Fabric MSP is named mspID.
func withAppTestMSPName(t *testing.T, org *cb.ConfigGroup, mspID string) *cb.ConfigGroup {
	t.Helper()
	renamed := proto.CloneOf(org)
	setPartyTestMSPName(t, renamed, mspID)
	return renamed
}

// appTestDefinition renders the organization definition of an org: its name
// and its config group, in the form `fxadmin decode` prints the group, as YAML
// or JSON. Each certificate of the group's MSP is written to a file in a fresh
// directory and given by the file's absolute path, so that the definition can
// be written in any directory.
func appTestDefinition(t *testing.T, name string, org *cb.ConfigGroup, format string) string {
	t.Helper()
	group := protolatorMapOf(t, &peerext.DynamicApplicationOrgGroup{ConfigGroup: org})
	if mspConfig, ok := mspConfigMapOf(group); ok {
		files := &certificateFiles{t: t, dir: t.TempDir(), absolute: true}
		files.replaceMSPWithPaths(mspConfig)
	}
	definition := map[string]any{appTestNameKey: name, appTestConfigGroupKey: group}
	if format == appTestFormatJSON {
		content, err := json.Marshal(definition)
		require.NoError(t, err)
		return string(content)
	}
	return marshalDefinition(t, definition)
}

// appTestDefinitionWithFiles renders the organization definition of the org
// as appTestNewOrg, with the field of its MSP config set to the given values in
// place of the paths of the field's files.
func appTestDefinitionWithFiles(t *testing.T, org *cb.ConfigGroup, field string, values ...string) string {
	t.Helper()
	definition := parseDefinition(t, appTestDefinition(t, appTestNewOrg, org, appTestFormatYAML))
	mspConfig, ok := mspConfigMapOf(childMap(t, definition, appTestConfigGroupKey))
	require.True(t, ok)
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	mspConfig[field] = items
	return marshalDefinition(t, definition)
}

// writeAppTestDefinition writes the definition as peer2.yaml in a fresh
// directory and returns its path.
func writeAppTestDefinition(t *testing.T, definition string) string {
	t.Helper()
	return writeAppTestDefinitionIn(t, t.TempDir(), definition)
}

// writeAppTestDefinitionIn writes the definition as peer2.yaml in dir and
// returns its path.
func writeAppTestDefinitionIn(t *testing.T, dir, definition string) string {
	t.Helper()
	path := filepath.Join(dir, appTestNewOrg+".yaml")
	require.NoError(t, os.WriteFile(path, []byte(definition), 0o600))
	return path
}

// appTestREADMEDefinition is the organization definition of appTestNewOrg,
// exactly as the fxadmin README writes it. Its certificates are the paths,
// relative to the directory of the definition, of the files of the MSP's root
// certificate, its admin certificate, its TLS root certificate, and two known
// certificates.
const appTestREADMEDefinition = `# peer2.yaml
name: peer2                          # the org's key under Application

config_group:                        # → Application/groups/<name>
  version: "0"
  mod_policy: Admins
  groups: {}

  policies:                          # Readers, Writers, Admins, Endorsement
    Readers:
      version: "0"
      mod_policy: Admins
      policy:
        type: 1                      # 1 = SIGNATURE
        value:                       # OR('peer2.member')
          version: 0
          identities:
            - principal_classification: ROLE
              principal:
                msp_identifier: peer2
                role: MEMBER
          rule:
            n_out_of:
              n: 1
              rules:
                - signed_by: 0

    Writers:
      version: "0"
      mod_policy: Admins
      policy:
        type: 1
        value:                       # OR('peer2.member')
          version: 0
          identities:
            - principal_classification: ROLE
              principal:
                msp_identifier: peer2
                role: MEMBER
          rule:
            n_out_of:
              n: 1
              rules:
                - signed_by: 0

    Admins:
      version: "0"
      mod_policy: Admins
      policy:
        type: 1
        value:                       # OR('peer2.admin')
          version: 0
          identities:
            - principal_classification: ROLE
              principal:
                msp_identifier: peer2
                role: ADMIN
          rule:
            n_out_of:
              n: 1
              rules:
                - signed_by: 0

    Endorsement:
      version: "0"
      mod_policy: Admins
      policy:
        type: 1
        value:                       # OR('peer2.member')
          version: 0
          identities:
            - principal_classification: ROLE
              principal:
                msp_identifier: peer2
                role: MEMBER
          rule:
            n_out_of:
              n: 1
              rules:
                - signed_by: 0

  values:
    MSP:
      version: "0"
      mod_policy: Admins
      value:
        type: 0                      # 0 = FABRIC
        config:                      # FabricMSPConfig
          name: peer2                # MSP ID; the msp_identifier of the policies
          root_certs:
            - crypto/peer2/ca/ca-cert.pem
          intermediate_certs: []
          admins:
            - crypto/peer2/users/Admin/msp/signcerts/cert.pem
          revocation_list: []
          signing_identity: null
          organizational_unit_identifiers: []
          crypto_config:
            signature_hash_family: SHA2
            identity_identifier_hash_function: SHA256
          tls_root_certs:
            - crypto/peer2/tlsca/tlsca-cert.pem
          tls_intermediate_certs: []
          fabric_node_ous: null
          known_certs:
            - crypto/peer2/users/User1/msp/signcerts/cert.pem
            - crypto/peer2/users/User2/msp/signcerts/cert.pem
`
