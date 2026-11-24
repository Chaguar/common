/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/api/ordererpb"
	"github.com/Chaguar/common/api/types"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/msp"
	"github.com/Chaguar/common/protolator"
	"github.com/Chaguar/common/protolator/protoext/ordererext"
	"github.com/Chaguar/common/tools/fxadmin/core/helpers"
)

// Keys of a party definition: the party's entry of the shared config, the
// party's orderer org, and, inside the org, the org's name.
const (
	partyDefPartyKey   = "Party"
	partyDefOrgKey     = "Org"
	partyDefOrgNameKey = "Name"
)

// partyDefinition is a decoded party definition: the party's shared config
// entry, and its orderer org's name and config group.
type partyDefinition struct {
	party   *ordererpb.PartyConfig
	orgName string
	org     *cb.ConfigGroup
}

// PartyAdd implements `fxadmin modify party add`. The party definition at
// partyPath holds the party's entry of the ARMA shared config (Party) and the
// config group of its new orderer org (Org), each mirroring its form in the
// config block, except that every certificate and CRL is given as the path of
// its PEM file. They are added to the config block at blockPath, which is
// rewritten in place. The org group carries the org's Endpoints value, the
// router's broadcast and the assembler's deliver addresses, which is added as
// given. The command also updates the elements of the block that must agree
// with the new party: the shared config's MaxPartyID, the party's consenter in
// the Orderers value, and the Orderer group's BlockValidation policy over all
// the consenters.
func (*Handler) PartyAdd(partyPath, blockPath string) error {
	logger.Debugf("modify party add: party=%s block=%s", partyPath, blockPath)

	def, err := loadPartyDefinition(partyPath)
	if err != nil {
		return err
	}
	block, err := readAndDecodeConfigBlock(blockPath)
	if err != nil {
		return err
	}
	orderer := block.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	if orderer == nil {
		return errors.Newf("the config has no %s group", channelconfig.OrdererGroupKey)
	}
	if err := addParty(orderer, def); err != nil {
		return err
	}

	if err := validateEncodeAndWriteConfigBlock(block, blockPath); err != nil {
		return err
	}
	logger.Infof("added party %d with orderer org %s to %s", def.party.GetPartyID(), def.orgName, blockPath)
	return nil
}

// addParty adds the party and its org to the Orderer group, in each of the
// places the block holds a party:
//   - the shared config (the ConsensusType value's metadata): the party is
//     appended to PartiesConfig, and MaxPartyID is set to its PartyID;
//   - the orderer org: its group is added under the org's name, with its MSP,
//     its policies, and its Endpoints value, which lists the router's broadcast
//     and the assembler's deliver addresses;
//   - the consenter mapping (the Orderers value): the party's consenter is
//     appended, with the endpoint and certificates of its ConsenterConfig and
//     the MSP ID of its org;
//   - the BlockValidation policy: it is recomputed over all the consenters'
//     signing certificates.
func addParty(orderer *cb.ConfigGroup, def *partyDefinition) error {
	if _, exists := orderer.GetGroups()[def.orgName]; exists {
		return errors.Newf("orderer org %q already exists", def.orgName)
	}
	if err := validatePartyHosts(def.party); err != nil {
		return err
	}
	if err := validateOrgEndpoints(def.org); err != nil {
		return fmt.Errorf("invalid orderer org %q: %w", def.orgName, err)
	}
	mspID, err := orgMSPID(def.org)
	if err != nil {
		return fmt.Errorf("invalid orderer org %q: %w", def.orgName, err)
	}
	consenter, err := consenterOf(def.party, mspID)
	if err != nil {
		return err
	}

	if err = addToSharedConfig(orderer, def.party); err != nil {
		return err
	}
	consenters, err := addConsenter(orderer, consenter)
	if err != nil {
		return err
	}
	if orderer.Groups == nil {
		orderer.Groups = make(map[string]*cb.ConfigGroup)
	}
	orderer.Groups[def.orgName] = def.org
	return recomputeBlockValidation(orderer, consenters)
}

// addToSharedConfig appends the party to the ARMA shared config, the consensus
// metadata of the Orderer group's ConsensusType value, and sets MaxPartyID to
// the party's PartyID. The orderer requires that PartyID to be the previous
// MaxPartyID + 1, and checks it when the config update is submitted.
func addToSharedConfig(orderer *cb.ConfigGroup, party *ordererpb.PartyConfig) error {
	consensusType, err := decodeConsensusType(orderer)
	if err != nil {
		return err
	}
	shared := consensusType.sharedConfig
	shared.PartiesConfig = append(shared.PartiesConfig, party)
	shared.MaxPartyID = party.GetPartyID()
	return consensusType.encode()
}

// consenterOf returns the party's consenter as the Orderers value lists it: the
// endpoint and certificates of the party's consenter node, under the MSP ID of
// the party's org. The orderer requires them to match the party's
// ConsenterConfig, so they are taken from it.
func consenterOf(party *ordererpb.PartyConfig, mspID string) (*cb.Consenter, error) {
	node := party.GetConsenterConfig().GetNodeConfig()
	if node == nil {
		return nil, errors.Newf("party %d has no ConsenterConfig", party.GetPartyID())
	}
	return &cb.Consenter{
		Id:            party.GetPartyID(),
		Host:          node.GetHost(),
		Port:          node.GetPort(),
		MspId:         mspID,
		Identity:      node.GetSignCert(),
		ClientTlsCert: node.GetClientTlsCert(),
		ServerTlsCert: node.GetServerTlsCert(),
	}, nil
}

// addConsenter appends the consenter to the consenter mapping of the Orderer
// group's Orderers value and returns the new mapping.
func addConsenter(orderer *cb.ConfigGroup, consenter *cb.Consenter) ([]*cb.Consenter, error) {
	orderers, err := decodeOrderers(orderer)
	if err != nil {
		return nil, err
	}
	orderers.orderers.ConsenterMapping = append(orderers.orderers.ConsenterMapping, consenter)
	if err := orderers.encode(); err != nil {
		return nil, err
	}
	return orderers.orderers.GetConsenterMapping(), nil
}

// PartyRemove implements `fxadmin modify party remove`. It removes the party
// from the config block at blockPath, which is rewritten in place, and its
// orderer org with it, unless the org also runs another party. The command
// also updates the elements of the block that must agree with the remaining
// parties: the Orderers value, the Endpoints value of a kept org, and the
// Orderer group's BlockValidation policy over the remaining consenters.
func (*Handler) PartyRemove(partyID uint32, blockPath string) error {
	logger.Debugf("modify party remove: partyID=%d block=%s", partyID, blockPath)

	block, err := readAndDecodeConfigBlock(blockPath)
	if err != nil {
		return err
	}
	orderer := block.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	if orderer == nil {
		return errors.Newf("the config has no %s group", channelconfig.OrdererGroupKey)
	}
	orgName, orgKept, err := removeParty(orderer, partyID)
	if err != nil {
		return err
	}

	if err := validateEncodeAndWriteConfigBlock(block, blockPath); err != nil {
		return err
	}
	if orgKept {
		logger.Infof("removed party %d from %s, and kept its orderer org %s, which runs other parties",
			partyID, blockPath, orgName)
		return nil
	}
	logger.Infof("removed party %d with orderer org %s from %s", partyID, orgName, blockPath)
	return nil
}

// removeParty removes the party from the Orderer group, in each of the places
// the block holds a party, and returns the name of the party's orderer org and
// whether the org is kept:
//   - the shared config (the ConsensusType value's metadata): the party is
//     removed from PartiesConfig, and MaxPartyID is kept;
//   - the consenter mapping (the Orderers value): the party's consenter is
//     removed;
//   - the orderer org: a party belongs to one org, the org whose MSP ID is that
//     of the party's consenter, as the orderer associates them. The org, and
//     with it its Endpoints value, is removed. An org can run several parties,
//     so if the consenter of another party has the same MSP ID, the org is
//     kept, and only the party's endpoints are removed from its Endpoints
//     value. An org lists only the endpoints of its own parties, so the
//     Endpoints values of other orgs are not changed;
//   - the BlockValidation policy: it is recomputed over the remaining
//     consenters' signing certificates.
func removeParty(orderer *cb.ConfigGroup, partyID uint32) (orgName string, orgKept bool, err error) {
	if err = removeFromSharedConfig(orderer, partyID); err != nil {
		return "", false, err
	}
	consenter, consenters, err := removeConsenter(orderer, partyID)
	if err != nil {
		return "", false, err
	}
	orgName, err = ordererOrgOf(orderer, consenter.GetMspId())
	if err != nil {
		return "", false, fmt.Errorf("the orderer org of party %d: %w", partyID, err)
	}

	orgKept = slices.ContainsFunc(consenters, func(c *cb.Consenter) bool {
		return c.GetMspId() == consenter.GetMspId()
	})
	if !orgKept {
		delete(orderer.Groups, orgName)
	} else if err = removeOrgPartyEndpoints(orderer.GetGroups()[orgName], partyID); err != nil {
		return "", false, fmt.Errorf("orderer org %q: %w", orgName, err)
	}
	return orgName, orgKept, recomputeBlockValidation(orderer, consenters)
}

// removeFromSharedConfig removes the party from the ARMA shared config, the
// consensus metadata of the Orderer group's ConsensusType value. MaxPartyID is
// kept: the orderer allows it to change only when a party is added, so that a
// removed party's PartyID is never reused. The only party is not removed, as
// that would leave the ordering service with no party.
func removeFromSharedConfig(orderer *cb.ConfigGroup, partyID uint32) error {
	consensusType, err := decodeConsensusType(orderer)
	if err != nil {
		return err
	}
	shared := consensusType.sharedConfig
	i := slices.IndexFunc(shared.GetPartiesConfig(), func(p *ordererpb.PartyConfig) bool {
		return p.GetPartyID() == partyID
	})
	if i < 0 {
		return errors.Newf("the shared config has no party %d", partyID)
	}
	if len(shared.GetPartiesConfig()) == 1 {
		return errors.Newf("party %d is the only party of the shared config, and cannot be removed", partyID)
	}
	shared.PartiesConfig = slices.Delete(shared.PartiesConfig, i, i+1)
	return consensusType.encode()
}

// removeConsenter removes the party's consenter from the consenter mapping of
// the Orderer group's Orderers value, and returns the removed consenter and the
// remaining mapping.
func removeConsenter(orderer *cb.ConfigGroup, partyID uint32) (*cb.Consenter, []*cb.Consenter, error) {
	orderers, err := decodeOrderers(orderer)
	if err != nil {
		return nil, nil, err
	}
	mapping := orderers.orderers.GetConsenterMapping()
	i := slices.IndexFunc(mapping, func(c *cb.Consenter) bool {
		return c.GetId() == partyID
	})
	if i < 0 {
		return nil, nil, errors.Newf("the consenter mapping has no consenter of party %d", partyID)
	}
	consenter := mapping[i]
	orderers.orderers.ConsenterMapping = slices.Delete(mapping, i, i+1)
	if err := orderers.encode(); err != nil {
		return nil, nil, err
	}
	return consenter, orderers.orderers.GetConsenterMapping(), nil
}

// ordererOrgOf returns the name of the orderer org whose MSP ID is mspID. It
// errors if no org, or more than one, has that MSP ID, as the org a consenter
// of that MSP ID is associated with would not be known.
func ordererOrgOf(orderer *cb.ConfigGroup, mspID string) (string, error) {
	var names []string
	for _, name := range slices.Sorted(maps.Keys(orderer.GetGroups())) {
		orgMSP, err := orgMSPID(orderer.GetGroups()[name])
		if err != nil {
			return "", fmt.Errorf("orderer org %q: %w", name, err)
		}
		if orgMSP == mspID {
			names = append(names, name)
		}
	}
	switch len(names) {
	case 0:
		return "", errors.Newf("no orderer org has MSP ID %q", mspID)
	case 1:
		return names[0], nil
	default:
		return "", errors.Newf("orderer orgs %q all have MSP ID %q", names, mspID)
	}
}

// removeOrgPartyEndpoints removes the party's endpoints, the addresses with its
// ID, from the org's Endpoints value.
func removeOrgPartyEndpoints(org *cb.ConfigGroup, partyID uint32) error {
	value, addresses, err := decodeOrgEndpoints(org)
	if err != nil || value == nil {
		return err
	}
	kept := make([]string, 0, len(addresses.GetAddresses()))
	for _, address := range addresses.GetAddresses() {
		// A malformed address might be the party's, so keeping it could leave an
		// endpoint of the removed party.
		endpoint, parseErr := types.ParseOrdererEndpoint(address)
		if parseErr != nil {
			return fmt.Errorf("failed to parse endpoint %q: %w", address, parseErr)
		}
		if endpoint.ID != partyID {
			kept = append(kept, address)
		}
	}
	addresses.Addresses = kept
	content, err := helpers.DeterministicMarshal.Marshal(addresses)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the Endpoints value")
	}
	value.Value = content
	return nil
}

// validatePartyHosts checks that the host of each of the party's nodes is an IP
// address or a host name, as `modify party node --host` checks a new host. The
// host of a node that is not given is not checked: the party without a
// consenter, for example, is rejected later with its own error.
// TODO: the orderer does not check the hosts of a party's nodes yet. Remove
// this check once the orderer does, and revisit it when the validation checks
// are integrated into fxadmin.
func validatePartyHosts(party *ordererpb.PartyConfig) error {
	type node struct {
		name string
		host string
	}
	nodes := make([]node, 0, len(party.GetBatchersConfig())+3)
	if router := party.GetRouterConfig().GetNodeConfig(); router != nil {
		nodes = append(nodes, node{name: "router", host: router.GetHost()})
	}
	for _, batcher := range party.GetBatchersConfig() {
		if config := batcher.GetNodeConfig(); config != nil {
			name := fmt.Sprintf("batcher of shard %d", batcher.GetShardId())
			nodes = append(nodes, node{name: name, host: config.GetHost()})
		}
	}
	if consenter := party.GetConsenterConfig().GetNodeConfig(); consenter != nil {
		nodes = append(nodes, node{name: "consenter", host: consenter.GetHost()})
	}
	if assembler := party.GetAssemblerConfig().GetNodeConfig(); assembler != nil {
		nodes = append(nodes, node{name: "assembler", host: assembler.GetHost()})
	}
	for _, n := range nodes {
		if err := validateHost(n.host); err != nil {
			return fmt.Errorf("the %s of party %d: %w", n.name, party.GetPartyID(), err)
		}
	}
	return nil
}

// validateOrgEndpoints checks that each address in the org's Endpoints value
// parses as an orderer endpoint and that its host is an IP address or a host
// name. An org with no Endpoints value is left to the orderer, which requires a
// broadcast and a deliver endpoint.
// TODO: the orderer does not check the hosts of an org's endpoints yet. Remove
// this check once the orderer does, and revisit it when the validation checks
// are integrated into fxadmin.
func validateOrgEndpoints(org *cb.ConfigGroup) error {
	_, addresses, err := decodeOrgEndpoints(org)
	if err != nil {
		return err
	}
	for _, address := range addresses.GetAddresses() {
		endpoint, err := types.ParseOrdererEndpoint(address)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint %q: %w", address, err)
		}
		if err := validateHost(endpoint.Host); err != nil {
			return fmt.Errorf("endpoint %q: %w", address, err)
		}
	}
	return nil
}

// orgMSPID returns the MSP ID of an org group: the name of its Fabric MSP.
func orgMSPID(org *cb.ConfigGroup) (string, error) {
	orgMSP, err := decodeOrgMSP(org)
	if err != nil {
		return "", err
	}
	if orgMSP.fabricConfig.GetName() == "" {
		return "", errors.New("the Fabric MSP has no name")
	}
	return orgMSP.fabricConfig.GetName(), nil
}

// decodedOrgMSP is an org's MSP config value with its two encoded layers
// decoded: the MSP config it holds, and the Fabric MSP config that is the MSP
// config's content. It keeps every layer, so that encode can write a changed
// Fabric MSP config back into the config value.
type decodedOrgMSP struct {
	configValue  *cb.ConfigValue
	mspConfig    *mspproto.MSPConfig
	fabricConfig *msppb.FabricMSPConfig
}

// decodeOrgMSP decodes the org's MSP config value down to its Fabric MSP config.
// It errors if the MSP is not a Fabric (X.509) MSP, such as an idemix MSP.
func decodeOrgMSP(org *cb.ConfigGroup) (*decodedOrgMSP, error) {
	value := org.GetValues()[channelconfig.MSPKey]
	if value == nil {
		return nil, errors.Newf("no %s value", channelconfig.MSPKey)
	}
	mspConfig := &mspproto.MSPConfig{}
	if err := proto.Unmarshal(value.GetValue(), mspConfig); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal the MSP value")
	}
	// The config of another MSP type, such as idemix, does not fail to decode
	// as a Fabric MSP config: protobuf keeps the fields it does not match as
	// unknown fields. So the type is checked first.
	if mspType := msp.ProviderType(mspConfig.GetType()); mspType != msp.FABRIC {
		name := msp.ProviderTypeToString(mspType)
		if name == "" {
			name = "unknown"
		}
		return nil, errors.Newf("the MSP is not a Fabric (X.509) MSP: its type is %d (%s)", mspType, name)
	}
	fabricConfig := &msppb.FabricMSPConfig{}
	if err := proto.Unmarshal(mspConfig.GetConfig(), fabricConfig); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal the Fabric MSP config")
	}
	return &decodedOrgMSP{configValue: value, mspConfig: mspConfig, fabricConfig: fabricConfig}, nil
}

// encode writes the Fabric MSP config, with any change made to it, back through
// the MSP config into the config value.
func (d *decodedOrgMSP) encode() error {
	content, err := helpers.DeterministicMarshal.Marshal(d.fabricConfig)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the Fabric MSP config")
	}
	d.mspConfig.Config = content
	value, err := helpers.DeterministicMarshal.Marshal(d.mspConfig)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the MSP value")
	}
	d.configValue.Value = value
	return nil
}

// loadPartyDefinition reads the party definition YAML at path. Its Party is the
// party's PartiesConfig entry and its Org the org's config group plus a Name
// key, each mirroring its form in the config block, except that every
// certificate and CRL is given as the path of its PEM file instead of its
// content. A relative path is relative to the directory of the definition. The
// files are read in, and the two sections are then decoded as is.
func loadPartyDefinition(path string) (*partyDefinition, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read party definition %q", path)
	}
	definition := map[string]any{}
	if err = yaml.Unmarshal(content, &definition); err != nil {
		return nil, errors.Wrapf(err, "failed to parse party definition %q", path)
	}
	party, ok := definition[partyDefPartyKey].(map[string]any)
	if !ok {
		return nil, errors.Newf("party definition %q has no %s", path, partyDefPartyKey)
	}
	org, ok := definition[partyDefOrgKey].(map[string]any)
	if !ok {
		return nil, errors.Newf("party definition %q has no %s", path, partyDefOrgKey)
	}
	orgName, ok := org[partyDefOrgNameKey].(string)
	if !ok || orgName == "" {
		return nil, errors.Newf("the %s of party definition %q has no %s", partyDefOrgKey, path, partyDefOrgNameKey)
	}
	delete(org, partyDefOrgNameKey)
	if err := readCertificateFiles(definition, filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("party definition %q: %w", path, err)
	}

	def := &partyDefinition{party: &ordererpb.PartyConfig{}, orgName: orgName, org: &cb.ConfigGroup{}}
	if err := decodeProtolatorValue(party, def.party); err != nil {
		return nil, fmt.Errorf("failed to decode the %s of party definition %q: %w", partyDefPartyKey, path, err)
	}
	if err := decodeProtolatorValue(org, &ordererext.DynamicOrdererOrgGroup{ConfigGroup: def.org}); err != nil {
		return nil, fmt.Errorf("failed to decode the %s of party definition %q: %w", partyDefOrgKey, path, err)
	}
	return def, nil
}

// decodeProtolatorValue decodes a value parsed from YAML into msg. protolator
// reads JSON, so the value is re-encoded as JSON first.
func decodeProtolatorValue(value any, msg proto.Message) error {
	content, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "failed to encode as JSON")
	}
	if err := protolator.DeepUnmarshalJSON(bytes.NewReader(content), msg); err != nil {
		return errors.Wrap(err, "failed to decode")
	}
	return nil
}
