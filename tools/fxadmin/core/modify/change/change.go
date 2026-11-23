/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package change defines the `fxadmin modify party` requests.
package change

// Node is a `modify party node` request. It selects one node of a party
// (Role, plus Shard for a batcher) and carries the fields to change; an empty
// field is left unchanged.
type Node struct {
	Party     uint32
	Role      string
	Shard     uint32
	Host      string
	Port      uint32
	TLSCert   string
	SignCert  string
	BlockPath string
}

// The operations of a known-certs request, as the `modify app|orderer
// known-certs` sub-verbs name them. The CLI and the handler both use them, so
// that they agree on the names.
const (
	KnownCertsOpAdd    = "add"
	KnownCertsOpRemove = "remove"
	KnownCertsOpSet    = "set"
)

// KnownCerts is a `modify app|orderer known-certs add|remove|set` request over
// the known certificates of an org's MSP. Group is the config group of the org,
// channelconfig.ApplicationGroupKey or channelconfig.OrdererGroupKey, and Org
// the org's name in that group. Op is the sub-verb, one of the KnownCertsOp
// constants.
type KnownCerts struct {
	Op        string
	Group     string
	Org       string
	Certs     []string
	BlockPath string
}

// The operations of a CA request, as the `modify party ca` sub-verbs name them.
// The CLI and the handler both use them, so that they agree on the names.
const (
	CAOpAdd     = "add"
	CAOpRemove  = "remove"
	CAOpSet     = "set"
	CAOpNodeOUs = "node-ous"
)

// CA is a `modify party ca add|remove|set|node-ous` request. add, remove and
// set change a party's CA (SignCerts) and TLS-CA (TLSCerts) certificate lists;
// node-ous points the node OUs of the party's org MSP at a CA (SignCerts, a
// single one). Op is the sub-verb, one of the CAOp constants. An empty field is
// left unchanged.
type CA struct {
	Op        string
	Party     uint32
	SignCerts []string
	TLSCerts  []string
	BlockPath string
}
