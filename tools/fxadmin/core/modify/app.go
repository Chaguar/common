/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"go.yaml.in/yaml/v3"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/protolator/protoext/peerext"
)

// Keys of an organization definition: the org's name, its key under the
// Application group, and its config group, in the form it has in the config
// block.
const (
	orgDefNameKey        = "name"
	orgDefConfigGroupKey = "config_group"
)

// AppAdd implements `fxadmin modify app add`. The organization definition at
// orgPath holds the org's name, its key under the Application group, and its
// config group, in the form it has in the config block: its policies and its
// MSP, with every certificate and CRL given as the path of its PEM file. The
// group is added as is, with each file read in place of its path, under that
// name, to the Application group of the config block at blockPath, which is
// rewritten in place; nothing is filled in. An org whose name is already in the
// Application group is rejected.
func (*Handler) AppAdd(orgPath, blockPath string) error {
	logger.Debugf("modify app add: org=%s block=%s", orgPath, blockPath)

	name, org, err := loadAppOrgDefinition(orgPath)
	if err != nil {
		return err
	}
	block, err := readAndDecodeConfigBlock(blockPath)
	if err != nil {
		return err
	}
	application := block.Config().GetChannelGroup().GetGroups()[channelconfig.ApplicationGroupKey]
	if application == nil {
		return errors.Newf("the config has no %s group", channelconfig.ApplicationGroupKey)
	}
	if _, exists := application.GetGroups()[name]; exists {
		return errors.Newf("application org %q already exists", name)
	}
	if application.Groups == nil {
		application.Groups = make(map[string]*cb.ConfigGroup)
	}
	application.Groups[name] = org

	if err := validateEncodeAndWriteConfigBlock(block, blockPath); err != nil {
		return err
	}
	logger.Infof("added application org %s to %s", name, blockPath)
	return nil
}

// AppRemove implements `fxadmin modify app remove`. It removes the whole config
// group of an application org from the config block at blockPath, which is
// rewritten in place: the org's MSP, its policies and every other value and
// group it holds. The org is given by its key under the Application group,
// which can differ from its MSP ID. Nothing else changes:
//   - the only application org is not removed. With no org, the implicit meta
//     policies of the Application group would be satisfied by anyone;
//   - what the rest of the config still refers to the org by, an ACL or a
//     signature policy (see appOrgReferences), is kept,
//     and a warning lists it, for the admins to update it.
func (*Handler) AppRemove(org, blockPath string) error {
	logger.Debugf("modify app remove: org=%s block=%s", org, blockPath)

	block, err := readAndDecodeConfigBlock(blockPath)
	if err != nil {
		return err
	}
	channel := block.Config().GetChannelGroup()
	application := channel.GetGroups()[channelconfig.ApplicationGroupKey]
	if application == nil {
		return errors.Newf("the config has no %s group", channelconfig.ApplicationGroupKey)
	}
	removed, exists := application.GetGroups()[org]
	if !exists {
		return missingOrgError(channelconfig.ApplicationGroupKey, application, org)
	}
	if len(application.GetGroups()) == 1 {
		return errors.Newf("application org %q is the only org of the %s group, and cannot be removed: "+
			"with no org, the group's policies would be satisfied by anyone", org, channelconfig.ApplicationGroupKey)
	}
	mspID, err := mspIDOf(removed)
	if err != nil {
		return fmt.Errorf("failed to read the MSP ID of application org %q: %w", org, err)
	}
	delete(application.Groups, org)
	refs, err := appOrgReferences(channel, org, mspID)
	if err != nil {
		return err
	}

	if err := validateEncodeAndWriteConfigBlock(block, blockPath); err != nil {
		return err
	}
	logger.Infof("removed application org %s from %s", org, blockPath)
	if len(refs) > 0 {
		logger.Warnf("the config still refers to the removed application org %s: %s. The org can no "+
			"longer satisfy these policies, and these ACLs deny every request: update them in a config update. "+
			"A policy that guards changes, such as Admins, and needs the org locks what it guards",
			org, strings.Join(refs, ", "))
	}
	return nil
}

// loadAppOrgDefinition reads the organization definition YAML at path and
// returns the org's name and config group. The definition has exactly two
// keys: the name, and the config group, which is decoded as is once its
// certificate and CRL files are read.
func loadAppOrgDefinition(path string) (string, *cb.ConfigGroup, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errors.Wrapf(err, "failed to read organization definition %q", path)
	}
	definition := map[string]any{}
	if err = yaml.Unmarshal(content, &definition); err != nil {
		return "", nil, errors.Wrapf(err, "failed to parse organization definition %q", path)
	}
	unknown := make([]string, 0, len(definition))
	for _, key := range slices.Sorted(maps.Keys(definition)) {
		if key != orgDefNameKey && key != orgDefConfigGroupKey {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		return "", nil, errors.Newf("organization definition %q has unknown keys %q: want %q and %q",
			path, unknown, orgDefNameKey, orgDefConfigGroupKey)
	}
	name, err := appOrgDefinitionName(definition, path)
	if err != nil {
		return "", nil, err
	}
	group, err := appOrgDefinitionGroup(definition, path)
	if err != nil {
		return "", nil, err
	}
	if err := readCertificateFiles(group, filepath.Dir(path)); err != nil {
		return "", nil, fmt.Errorf("organization definition %q: %w", path, err)
	}

	org := &cb.ConfigGroup{}
	if err := decodeProtolatorValue(group, &peerext.DynamicApplicationOrgGroup{ConfigGroup: org}); err != nil {
		return "", nil, fmt.Errorf("failed to decode the %s of organization definition %q: %w",
			orgDefConfigGroupKey, path, err)
	}
	return name, org, nil
}

// appOrgDefinitionName returns the name of the parsed organization definition
// at path, which must be a non-empty string. A name that is not set, or is
// empty, is missing; a name of another type is rejected as such.
func appOrgDefinitionName(definition map[string]any, path string) (string, error) {
	switch name := definition[orgDefNameKey].(type) {
	case string:
		if name != "" {
			return name, nil
		}
	case nil:
	default:
		return "", errors.Newf("the %s of organization definition %q must be a string, got %T",
			orgDefNameKey, path, name)
	}
	return "", errors.Newf("organization definition %q has no %s", path, orgDefNameKey)
}

// appOrgDefinitionGroup returns the config group of the parsed organization
// definition at path, which must be a map. A config group that is not set is
// missing; one of another type is rejected as such.
func appOrgDefinitionGroup(definition map[string]any, path string) (map[string]any, error) {
	switch group := definition[orgDefConfigGroupKey].(type) {
	case map[string]any:
		return group, nil
	case nil:
		return nil, errors.Newf("organization definition %q has no %s", path, orgDefConfigGroupKey)
	default:
		return nil, errors.Newf("the %s of organization definition %q must be a map, got %T",
			orgDefConfigGroupKey, path, group)
	}
}
