/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"testing"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/protoutil"
)

const (
	// refTestOrg is the removed application org, its name and MSP ID, and
	// refTestKeptOrg the application org that remains.
	refTestOrg     = "peer2"
	refTestKeptOrg = "peer-org-1"
	// refTestAPI is the API of the ACL the tests set.
	refTestAPI = "/committerpb.QueryService/GetRows"
	// refTestPolicy is the name of the policy the tests set.
	refTestPolicy = "Endorsement"
)

// TestAppOrgReferences covers what the channel config can still refer to a
// removed application org by, which `modify app remove` warns about.
func TestAppOrgReferences(t *testing.T) {
	t.Parallel()

	application := []string{channelconfig.ApplicationGroupKey}
	keptOrgPolicy := []string{channelconfig.ApplicationGroupKey, refTestKeptOrg}
	wantACL := `ACL "/committerpb.QueryService/GetRows" (policy "/Channel/Application/peer2/Readers")`
	wantAppPolicy := `policy "/Channel/Application/Endorsement"`

	for _, tc := range []struct {
		name    string
		channel *cb.ConfigGroup
		want    []string
	}{
		{name: "nothing refers to the org", channel: newRefTestChannel()},
		{
			name:    "an ACL to a policy of the org",
			channel: withRefTestACL(t, newRefTestChannel(), "/Channel/Application/peer2/Readers"),
			want:    []string{wantACL},
		},
		{
			name:    "an ACL to a policy of the org by a relative path",
			channel: withRefTestACL(t, newRefTestChannel(), "peer2/Writers"),
			want:    []string{`ACL "/committerpb.QueryService/GetRows" (policy "peer2/Writers")`},
		},
		{
			name:    "an ACL to a policy of another org",
			channel: withRefTestACL(t, newRefTestChannel(), "/Channel/Application/peer-org-1/Readers"),
		},
		{
			// The org's name is only a prefix of the other org's name.
			name:    "an ACL to a policy of an org whose name starts with the org's name",
			channel: withRefTestACL(t, newRefTestChannel(), "/Channel/Application/peer2x/Readers"),
		},
		{
			name: "an Application policy with a role of the org",
			channel: withRefTestPolicy(newRefTestChannel(), application,
				refTestSignaturePolicy(refTestRole(refTestKeptOrg), refTestRole(refTestOrg))),
			want: []string{wantAppPolicy},
		},
		{
			name:    "a channel policy with a role of the org",
			channel: withRefTestPolicy(newRefTestChannel(), nil, refTestSignaturePolicy(refTestRole(refTestOrg))),
			want:    []string{`policy "/Channel/Endorsement"`},
		},
		{
			name: "a policy of another org with a role of the org",
			channel: withRefTestPolicy(newRefTestChannel(), keptOrgPolicy,
				refTestSignaturePolicy(refTestRole(refTestOrg))),
			want: []string{`policy "/Channel/Application/peer-org-1/Endorsement"`},
		},
		{
			name: "a policy with an OU of the org",
			channel: withRefTestPolicy(newRefTestChannel(), application,
				refTestSignaturePolicy(refTestPrincipal(mspproto.MSPPrincipal_ORGANIZATION_UNIT,
					&mspproto.OrganizationUnit{MspIdentifier: refTestOrg, OrganizationalUnitIdentifier: "client"}))),
			want: []string{wantAppPolicy},
		},
		{
			name: "a policy with an identity of the org",
			channel: withRefTestPolicy(newRefTestChannel(), application,
				refTestSignaturePolicy(refTestPrincipal(mspproto.MSPPrincipal_IDENTITY,
					&msppb.Identity{MspId: refTestOrg}))),
			want: []string{wantAppPolicy},
		},
		{
			name: "a policy with a combined principal that includes the org",
			channel: withRefTestPolicy(newRefTestChannel(), application,
				refTestSignaturePolicy(refTestPrincipal(mspproto.MSPPrincipal_COMBINED,
					&mspproto.CombinedPrincipal{Principals: []*mspproto.MSPPrincipal{
						refTestRole(refTestKeptOrg), refTestRole(refTestOrg),
					}}))),
			want: []string{wantAppPolicy},
		},
		{
			name: "a policy of other orgs only",
			channel: withRefTestPolicy(newRefTestChannel(), application,
				refTestSignaturePolicy(refTestRole(refTestKeptOrg))),
		},
		{
			// Another org keeps the MSP ID, so the policy still works; the ACL
			// refers to the removed org's own policy, and so does not.
			name: "an MSP ID that another org keeps",
			channel: withRefTestACL(t, withRefTestPolicy(withRefTestAppOrg(newRefTestChannel(), "peer3", refTestOrg),
				application, refTestSignaturePolicy(refTestRole(refTestOrg))),
				"/Channel/Application/peer2/Readers"),
			want: []string{wantACL},
		},
		{
			name: "an ACL and policies together, in order",
			channel: withRefTestACL(t, withRefTestPolicy(withRefTestPolicy(newRefTestChannel(), nil,
				refTestSignaturePolicy(refTestRole(refTestOrg))), application,
				refTestSignaturePolicy(refTestRole(refTestOrg))), "/Channel/Application/peer2/Readers"),
			want: []string{wantACL, `policy "/Channel/Endorsement"`, wantAppPolicy},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			refs, err := appOrgReferences(tc.channel, refTestOrg, refTestOrg)
			require.NoError(t, err)
			if len(tc.want) == 0 {
				require.Empty(t, refs)
				return
			}
			require.Equal(t, tc.want, refs)
		})
	}
}

// TestAppOrgReferencesRejectsMalformedPolicy asserts that a signature policy
// that cannot be read is an error, not a policy that names no org.
func TestAppOrgReferencesRejectsMalformedPolicy(t *testing.T) {
	t.Parallel()

	malformed := &cb.ConfigPolicy{Policy: &cb.Policy{Type: int32(cb.Policy_SIGNATURE), Value: []byte("not a policy")}}
	channel := withRefTestPolicy(newRefTestChannel(), []string{channelconfig.ApplicationGroupKey}, malformed)
	_, err := appOrgReferences(channel, refTestOrg, refTestOrg)
	require.ErrorContains(t, err, "policy /Channel/Application/Endorsement: failed to unmarshal the signature policy")
}

// newRefTestChannel returns a channel group whose removed org, refTestOrg, is
// already gone: an Application group of one org, refTestKeptOrg, with an ACL
// to an Application policy, and an Orderer group of one org. Every policy is
// an implicit meta policy.
func newRefTestChannel() *cb.ConfigGroup {
	implicitMeta := &cb.ConfigPolicy{Policy: &cb.Policy{
		Type:  int32(cb.Policy_IMPLICIT_META),
		Value: protoutil.MarshalOrPanic(&cb.ImplicitMetaPolicy{SubPolicy: refTestPolicy}),
	}}
	acls := &pb.ACLs{Acls: map[string]*pb.APIResource{
		"/committerpb.QueryService/BeginView": {PolicyRef: "/Channel/Application/Readers"},
	}}
	return &cb.ConfigGroup{
		Policies: map[string]*cb.ConfigPolicy{refTestPolicy: implicitMeta},
		Groups: map[string]*cb.ConfigGroup{
			channelconfig.ApplicationGroupKey: {
				Values: map[string]*cb.ConfigValue{
					channelconfig.ACLsKey: {Value: protoutil.MarshalOrPanic(acls)},
				},
				Policies: map[string]*cb.ConfigPolicy{refTestPolicy: implicitMeta},
				Groups:   map[string]*cb.ConfigGroup{refTestKeptOrg: refTestOrgGroup(refTestKeptOrg)},
			},
			channelconfig.OrdererGroupKey: {
				Groups: map[string]*cb.ConfigGroup{"orderer-org-1": refTestOrgGroup("orderer-org-1")},
			},
		},
	}
}

// withRefTestACL returns the channel with the ACL of refTestAPI set to the
// policy reference policyRef.
func withRefTestACL(t *testing.T, channel *cb.ConfigGroup, policyRef string) *cb.ConfigGroup {
	t.Helper()
	value := channel.GetGroups()[channelconfig.ApplicationGroupKey].GetValues()[channelconfig.ACLsKey]
	acls := &pb.ACLs{}
	require.NoError(t, proto.Unmarshal(value.GetValue(), acls))
	acls.Acls[refTestAPI] = &pb.APIResource{PolicyRef: policyRef}
	value.Value = protoutil.MarshalOrPanic(acls)
	return channel
}

// withRefTestPolicy returns the channel with the policy refTestPolicy of the
// group at path, from the channel group, set to policy.
func withRefTestPolicy(channel *cb.ConfigGroup, path []string, policy *cb.ConfigPolicy) *cb.ConfigGroup {
	group := channel
	for _, key := range path {
		group = group.GetGroups()[key]
	}
	if group.Policies == nil {
		group.Policies = map[string]*cb.ConfigPolicy{}
	}
	group.Policies[refTestPolicy] = policy
	return channel
}

// withRefTestAppOrg returns the channel with an application org named name of
// the MSP ID mspID.
func withRefTestAppOrg(channel *cb.ConfigGroup, name, mspID string) *cb.ConfigGroup {
	channel.GetGroups()[channelconfig.ApplicationGroupKey].Groups[name] = refTestOrgGroup(mspID)
	return channel
}

// refTestOrgGroup returns the group of an org whose Fabric MSP has the MSP ID
// mspID.
func refTestOrgGroup(mspID string) *cb.ConfigGroup {
	mspConfig := &mspproto.MSPConfig{Config: protoutil.MarshalOrPanic(&mspproto.FabricMSPConfig{Name: mspID})}
	return &cb.ConfigGroup{Values: map[string]*cb.ConfigValue{
		channelconfig.MSPKey: {Value: protoutil.MarshalOrPanic(mspConfig)},
	}}
}

// refTestSignaturePolicy returns a signature policy of the principals.
func refTestSignaturePolicy(principals ...*mspproto.MSPPrincipal) *cb.ConfigPolicy {
	envelope := &cb.SignaturePolicyEnvelope{Identities: principals}
	return &cb.ConfigPolicy{Policy: &cb.Policy{
		Type:  int32(cb.Policy_SIGNATURE),
		Value: protoutil.MarshalOrPanic(envelope),
	}}
}

// refTestRole returns a principal of the members of the MSP mspID.
func refTestRole(mspID string) *mspproto.MSPPrincipal {
	return refTestPrincipal(mspproto.MSPPrincipal_ROLE,
		&mspproto.MSPRole{MspIdentifier: mspID, Role: mspproto.MSPRole_MEMBER})
}

// refTestPrincipal returns a principal of the classification, with the
// principal message marshaled.
func refTestPrincipal(
	classification mspproto.MSPPrincipal_Classification, principal proto.Message,
) *mspproto.MSPPrincipal {
	return &mspproto.MSPPrincipal{
		PrincipalClassification: classification,
		Principal:               protoutil.MarshalOrPanic(principal),
	}
}
