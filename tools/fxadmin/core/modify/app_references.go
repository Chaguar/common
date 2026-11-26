/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/common/channelconfig"
)

// appOrgReferences returns what the channel config still refers to the removed
// application org by, the org named org with the MSP ID mspID, whose group
// channel no longer holds. The bundle check accepts such a reference, but it no
// longer works:
//   - an ACL of the Application group whose policy is one of the org's
//     policies, such as /Channel/Application/<org>/Readers, denies every
//     request;
//   - a signature policy that names the org's MSP ID can no longer be satisfied
//     by the org. Another org of the channel that keeps that MSP ID still
//     satisfies it, so such a policy is not returned.
func appOrgReferences(channel *cb.ConfigGroup, org, mspID string) ([]string, error) {
	refs, err := aclReferences(channel.GetGroups()[channelconfig.ApplicationGroupKey], org)
	if err != nil {
		return nil, err
	}
	kept, err := mspIDKept(channel, mspID)
	if err != nil || kept {
		return refs, err
	}
	policyRefs, err := policyReferences(channel, "/"+channelconfig.ChannelGroupKey, mspID)
	if err != nil {
		return nil, err
	}
	return append(refs, policyRefs...), nil
}

// aclReferences returns the ACLs of the Application group whose policy is one
// of the org's policies. A relative policy reference is relative to the
// Application group, as the channel config resolves it.
func aclReferences(application *cb.ConfigGroup, org string) ([]string, error) {
	value := application.GetValues()[channelconfig.ACLsKey]
	if value == nil {
		return nil, nil
	}
	acls := &pb.ACLs{}
	if err := proto.Unmarshal(value.GetValue(), acls); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal the %s value of the %s group",
			channelconfig.ACLsKey, channelconfig.ApplicationGroupKey)
	}
	applicationPath := "/" + channelconfig.ChannelGroupKey + "/" + channelconfig.ApplicationGroupKey + "/"
	refs := make([]string, 0, len(acls.GetAcls()))
	for _, api := range slices.Sorted(maps.Keys(acls.GetAcls())) {
		policyRef := acls.GetAcls()[api].GetPolicyRef()
		path := policyRef
		if !strings.HasPrefix(path, "/") {
			path = applicationPath + path
		}
		if strings.HasPrefix(path, applicationPath+org+"/") {
			refs = append(refs, fmt.Sprintf("ACL %q (policy %q)", api, policyRef))
		}
	}
	return refs, nil
}

// mspIDKept reports whether an org of the Application or of the Orderer group
// of channel has the MSP ID mspID.
func mspIDKept(channel *cb.ConfigGroup, mspID string) (bool, error) {
	for _, groupKey := range []string{channelconfig.ApplicationGroupKey, channelconfig.OrdererGroupKey} {
		orgs := channel.GetGroups()[groupKey].GetGroups()
		for _, name := range slices.Sorted(maps.Keys(orgs)) {
			orgMSPID, err := mspIDOf(orgs[name])
			if err != nil {
				return false, fmt.Errorf("failed to read the MSP ID of %s org %q: %w", groupKey, name, err)
			}
			if orgMSPID == mspID {
				return true, nil
			}
		}
	}
	return false, nil
}

// policyReferences returns the paths of the signature policies of the group at
// path, and of its subgroups, that name the MSP ID mspID.
func policyReferences(group *cb.ConfigGroup, path, mspID string) ([]string, error) {
	var refs []string
	for _, name := range slices.Sorted(maps.Keys(group.GetPolicies())) {
		names, err := signaturePolicyNamesMSPID(group.GetPolicies()[name].GetPolicy(), mspID)
		if err != nil {
			return nil, fmt.Errorf("policy %s/%s: %w", path, name, err)
		}
		if names {
			refs = append(refs, fmt.Sprintf("policy %q", path+"/"+name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(group.GetGroups())) {
		groupRefs, err := policyReferences(group.GetGroups()[name], path+"/"+name, mspID)
		if err != nil {
			return nil, err
		}
		refs = append(refs, groupRefs...)
	}
	return refs, nil
}

// signaturePolicyNamesMSPID reports whether the policy is a signature policy
// with a principal of the MSP ID mspID.
func signaturePolicyNamesMSPID(policy *cb.Policy, mspID string) (bool, error) {
	if policy.GetType() != int32(cb.Policy_SIGNATURE) {
		return false, nil
	}
	envelope := &cb.SignaturePolicyEnvelope{}
	if err := proto.Unmarshal(policy.GetValue(), envelope); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal the signature policy")
	}
	return principalsNameMSPID(envelope.GetIdentities(), mspID)
}

// principalsNameMSPID reports whether one of the principals is of the MSP ID
// mspID.
func principalsNameMSPID(principals []*mspproto.MSPPrincipal, mspID string) (bool, error) {
	for _, principal := range principals {
		names, err := principalNamesMSPID(principal, mspID)
		if err != nil || names {
			return names, err
		}
	}
	return false, nil
}

// principalNamesMSPID reports whether the principal is of the MSP ID mspID: a
// role, an OU or an identity of that MSP, or a combination of principals one
// of which is. An anonymity principal names no MSP.
func principalNamesMSPID(principal *mspproto.MSPPrincipal, mspID string) (bool, error) {
	switch principal.GetPrincipalClassification() {
	case mspproto.MSPPrincipal_ROLE:
		role := &mspproto.MSPRole{}
		if err := proto.Unmarshal(principal.GetPrincipal(), role); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal a role principal")
		}
		return role.GetMspIdentifier() == mspID, nil
	case mspproto.MSPPrincipal_ORGANIZATION_UNIT:
		ou := &mspproto.OrganizationUnit{}
		if err := proto.Unmarshal(principal.GetPrincipal(), ou); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal an OU principal")
		}
		return ou.GetMspIdentifier() == mspID, nil
	case mspproto.MSPPrincipal_IDENTITY:
		identity := &msppb.Identity{}
		if err := proto.Unmarshal(principal.GetPrincipal(), identity); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal an identity principal")
		}
		return identity.GetMspId() == mspID, nil
	case mspproto.MSPPrincipal_COMBINED:
		combined := &mspproto.CombinedPrincipal{}
		if err := proto.Unmarshal(principal.GetPrincipal(), combined); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal a combined principal")
		}
		return principalsNameMSPID(combined.GetPrincipals(), mspID)
	default:
		return false, nil
	}
}
