/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	mspproto "github.com/hyperledger/fabric-protos-go-apiv2/msp"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/api/ordererpb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/tools/fxadmin/core/modify/change"
)

// givenCertificate is a certificate given to a modify command, such as `party
// ca` or `known-certs`: the path of the file it was read from, for messages,
// and the certificate, PEM-encoded as the block stores it.
type givenCertificate struct {
	path string
	pem  []byte
}

// caChange is a `modify party ca` request with its certificate files read: the
// operation, the party, and the certificates for its CA list and its TLS CA
// list. An empty list of certificates leaves the party's list unchanged.
type caChange struct {
	op        string
	party     uint32
	signCerts []givenCertificate
	tlsCerts  []givenCertificate
}

// caList is one of the CA lists of an orderer org's parties, in each place of
// the block that holds it: the shared config entry of each of the org's
// parties, and the org's Fabric MSP. name names the list, for messages.
type caList struct {
	name    string
	parties []partyCAList
	msp     *[][]byte
}

// partyCAList is the CA list of one party's shared config entry.
type partyCAList struct {
	party uint32
	certs *[][]byte
}

// PartyCA implements `fxadmin modify party ca add|remove|set|node-ous`. add,
// remove and set change a party's CA list, its TLS CA list, or both, in each
// place of the block that holds the list: the party's entry of the ARMA shared
// config (CACerts and TLSCACerts), and the Fabric MSP of the party's orderer
// org (root_certs and tls_root_certs). The party's org is the org whose MSP ID
// is that of the party's consenter, as the orderer associates them. An org can
// run several parties, which all trust the org's MSP, so the change is applied
// to each of the org's parties. Setting a list replaces it as a whole.
//
// node-ous is the only operation that changes the CA the org MSP's node OUs
// pin: it points them at a CA of the party's CA list, and leaves the lists
// unchanged. A CA rotation moves the node OUs to the new CA in the same config
// update as the party's node certificates, while both CAs are trusted. add,
// remove and set leave the node OUs as they are, so remove and set refuse to
// drop the CA they pin.
//
// The config block at the request's BlockPath is rewritten in place.
//
// TODO: intermediate CAs are not supported yet
// (https://github.com/Chaguar/orderer/issues/619). A certificate is always
// added to the MSP's root certificates, and the MSP's intermediate certificates
// are left as they are.
func (*Handler) PartyCA(ch change.CA) error {
	logger.Debugf("modify party ca %s: party=%d sign-certs=%v tls-certs=%v block=%s",
		ch.Op, ch.Party, ch.SignCerts, ch.TLSCerts, ch.BlockPath)

	cc, err := readCAChange(ch)
	if err != nil {
		return err
	}
	block, err := readAndDecodeConfigBlock(ch.BlockPath)
	if err != nil {
		return err
	}
	orderer := block.Config().GetChannelGroup().GetGroups()[channelconfig.OrdererGroupKey]
	if orderer == nil {
		return errors.Newf("the config has no %s group", channelconfig.OrdererGroupKey)
	}
	org, err := changePartyCAs(orderer, cc)
	if err != nil {
		return err
	}

	if err := validateEncodeAndWriteConfigBlock(block, ch.BlockPath); err != nil {
		return err
	}
	logger.Infof("applied ca %s to parties %v of orderer org %s in %s", cc.op, org.parties, org.name, ch.BlockPath)
	return nil
}

// readCAChange checks the request's operation and that it gives at least one
// certificate, and reads its certificate files.
func readCAChange(ch change.CA) (*caChange, error) {
	if !slices.Contains([]string{change.CAOpAdd, change.CAOpRemove, change.CAOpSet, change.CAOpNodeOUs}, ch.Op) {
		return nil, errors.Newf("unknown operation %q: want %q, %q, %q or %q",
			ch.Op, change.CAOpAdd, change.CAOpRemove, change.CAOpSet, change.CAOpNodeOUs)
	}
	if len(ch.SignCerts) == 0 && len(ch.TLSCerts) == 0 {
		return nil, errors.New("nothing to change: no CA or TLS CA certificate is given")
	}
	// A node OU pins a single signing CA.
	if ch.Op == change.CAOpNodeOUs && (len(ch.SignCerts) != 1 || len(ch.TLSCerts) != 0) {
		return nil, errors.Newf("%s takes exactly one CA certificate, and no TLS CA certificate", change.CAOpNodeOUs)
	}
	signCerts, err := readCACertificates(ch.SignCerts)
	if err != nil {
		return nil, fmt.Errorf("invalid CA certificates: %w", err)
	}
	tlsCerts, err := readCACertificates(ch.TLSCerts)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS CA certificates: %w", err)
	}
	return &caChange{op: ch.Op, party: ch.Party, signCerts: signCerts, tlsCerts: tlsCerts}, nil
}

// readCACertificates reads the certificate files at paths. Each must hold a
// PEM-encoded X.509 CA certificate, and no certificate may be given twice.
func readCACertificates(paths []string) ([]givenCertificate, error) {
	return readGivenCertificates(paths, requireCACertificate)
}

// readGivenCertificates reads the certificate files at paths. Each must hold a
// single PEM block, a PEM-encoded X.509 certificate that passes check, and no
// certificate may be given twice.
func readGivenCertificates(
	paths []string, check func(path string, cert *x509.Certificate) error,
) ([]givenCertificate, error) {
	certs := make([]givenCertificate, 0, len(paths))
	for _, path := range paths {
		cert, content, err := parseCertificateFile(path)
		if err != nil {
			return nil, err
		}
		if err := requireOnePEMBlock(path); err != nil {
			return nil, err
		}
		if err := check(path, cert); err != nil {
			return nil, err
		}
		for _, given := range certs {
			if sameCertificate(given.pem, content) {
				return nil, errors.Newf("%q and %q hold the same certificate", given.path, path)
			}
		}
		certs = append(certs, givenCertificate{path: path, pem: content})
	}
	return certs, nil
}

// requireCACertificate checks that the certificate at path is a CA certificate.
func requireCACertificate(path string, cert *x509.Certificate) error {
	if !cert.IsCA {
		return errors.Newf("%q is not a CA certificate", path)
	}
	return nil
}

// requireOnePEMBlock checks that the file at path holds a single PEM block. A
// file of several, such as a CA chain, a bundle of the old and the new CA, or a
// bundle of known certificates, is rejected rather than read in part: only its
// first certificate would be kept, and the others dropped without notice.
func requireOnePEMBlock(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return errors.Wrapf(err, "failed to read certificate %q", path)
	}
	_, rest := pem.Decode(content)
	if next, _ := pem.Decode(rest); next != nil {
		return errors.Newf("%q holds more than one PEM block; give each certificate in a file of its own", path)
	}
	return nil
}

// ordererOrgParties is an orderer org and the parties it runs: the parties
// whose consenters have the org's MSP ID.
type ordererOrgParties struct {
	name    string
	parties []uint32
}

// changePartyCAs applies the change to the CA lists of the party and of the
// other parties of its org, in their shared config entries and in the org's
// Fabric MSP, and returns the org and its parties.
func changePartyCAs(orderer *cb.ConfigGroup, cc *caChange) (*ordererOrgParties, error) {
	consensusType, err := decodeConsensusType(orderer)
	if err != nil {
		return nil, err
	}
	if _, err = partyConfigOf(consensusType.sharedConfig, cc.party); err != nil {
		return nil, err
	}
	org, err := ordererOrgPartiesOf(orderer, cc.party)
	if err != nil {
		return nil, err
	}
	parties := make([]*ordererpb.PartyConfig, 0, len(org.parties))
	for _, id := range org.parties {
		party, partyErr := partyConfigOf(consensusType.sharedConfig, id)
		if partyErr != nil {
			return nil, fmt.Errorf("party %d of orderer org %q: %w", id, org.name, partyErr)
		}
		parties = append(parties, party)
	}
	orgMSP, err := decodeOrgMSP(orderer.GetGroups()[org.name])
	if err != nil {
		return nil, fmt.Errorf("orderer org %q: %w", org.name, err)
	}
	fabricConfig := orgMSP.fabricConfig

	caCerts := caList{name: "CA", msp: &fabricConfig.RootCerts}
	tlsCACerts := caList{name: "TLS CA", msp: &fabricConfig.TlsRootCerts}
	for _, party := range parties {
		caCerts.parties = append(caCerts.parties, partyCAList{party: party.GetPartyID(), certs: &party.CACerts})
		tlsCACerts.parties = append(tlsCACerts.parties,
			partyCAList{party: party.GetPartyID(), certs: &party.TLSCACerts})
	}
	if err := applyCAChange(cc, caCerts, tlsCACerts, fabricConfig); err != nil {
		return nil, fmt.Errorf("orderer org %q: %w", org.name, err)
	}

	if err := consensusType.encode(); err != nil {
		return nil, err
	}
	if err := orgMSP.encode(); err != nil {
		return nil, fmt.Errorf("orderer org %q: %w", org.name, err)
	}
	return org, nil
}

// applyCAChange applies the change's operation to the CA lists or to the org
// MSP's node OUs:
//   - node-ous points the node OUs at the given CA and leaves the lists as they
//     are;
//   - add, remove and set change the lists and leave the node OUs as they are,
//     so they may not drop the CA the node OUs pin.
func applyCAChange(cc *caChange, caCerts, tlsCACerts caList, fabricConfig *msppb.FabricMSPConfig) error {
	if cc.op == change.CAOpNodeOUs {
		return moveNodeOUs(caCerts, fabricConfig, cc.signCerts[0])
	}
	if err := changeCAList(cc.op, caCerts, cc.signCerts); err != nil {
		return err
	}
	if err := changeCAList(cc.op, tlsCACerts, cc.tlsCerts); err != nil {
		return err
	}
	// Only a change of the signing-CA list can drop the CA the node OUs pin.
	if len(cc.signCerts) == 0 {
		return nil
	}
	return validateNodeOUPins(fabricConfig)
}

// validateNodeOUPins checks that each CA the MSP's node OUs pin is one of the
// MSP's root or intermediate certificates, as the MSP requires. add, remove and
// set change the root certificates but not the node OUs, so a change that drops
// the pinned CA is rejected with what to do instead: move the node OUs with
// node-ous first.
func validateNodeOUPins(fabricConfig *msppb.FabricMSPConfig) error {
	for _, identifier := range nodeOUIdentifiers(fabricConfig) {
		pinned := identifier.GetCertificate()
		if len(pinned) > 0 && !mspHoldsCA(fabricConfig, pinned) {
			return errors.Newf("the node OUs pin the CA %q, which is not in the CA list; "+
				"first point them at a CA of the list, with `fxadmin modify party ca node-ous`",
				certificateSubject(pinned))
		}
	}
	return nil
}

// mspHoldsCA reports whether the CA is one of the MSP's root or intermediate
// certificates, the CAs a node OU may pin.
func mspHoldsCA(fabricConfig *msppb.FabricMSPConfig, cert []byte) bool {
	return containsCertificate(fabricConfig.GetRootCerts(), cert) ||
		containsCertificate(fabricConfig.GetIntermediateCerts(), cert)
}

// moveNodeOUs points the node OUs of the org MSP at the CA. The MSP requires
// the CA a node OU pins to be one of its root or intermediate certificates, so
// the CA must be in each party's CA list and in the MSP, and the MSP must have
// node OUs that pin a CA. The MSP checks the pins even when its node OUs are
// not enabled, so the pins are moved then too, with a warning that they do not
// classify identities.
func moveNodeOUs(list caList, fabricConfig *msppb.FabricMSPConfig, cert givenCertificate) error {
	for _, party := range list.parties {
		if !containsCertificate(*party.certs, cert.pem) {
			return errors.Newf("the %s list of party %d does not hold the certificate of %q",
				list.name, party.party, cert.path)
		}
	}
	if !mspHoldsCA(fabricConfig, cert.pem) {
		return errors.Newf("the root and intermediate certificates of the MSP do not hold the certificate of %q",
			cert.path)
	}
	if retargetNodeOUs(fabricConfig, cert.pem) == 0 {
		return errors.New("the MSP has no node OUs that pin a CA")
	}
	if !fabricConfig.GetFabricNodeOus().GetEnable() {
		logger.Warnf("the node OUs of the MSP are not enabled: their pins are moved, "+
			"but they do not classify identities until node OUs are enabled; certificate %q", cert.path)
	}
	return nil
}

// ordererOrgPartiesOf returns the party's orderer org, the org whose MSP ID is
// that of the party's consenter in the Orderers consenter mapping, and the
// parties the org runs, in the order of the mapping.
func ordererOrgPartiesOf(orderer *cb.ConfigGroup, partyID uint32) (*ordererOrgParties, error) {
	orderers, err := decodeOrderers(orderer)
	if err != nil {
		return nil, err
	}
	consenters := orderers.orderers.GetConsenterMapping()
	i := slices.IndexFunc(consenters, func(c *cb.Consenter) bool {
		return c.GetId() == partyID
	})
	if i < 0 {
		return nil, errors.Newf("the consenter mapping has no consenter of party %d", partyID)
	}
	mspID := consenters[i].GetMspId()
	name, err := ordererOrgOf(orderer, mspID)
	if err != nil {
		return nil, fmt.Errorf("the orderer org of party %d: %w", partyID, err)
	}
	org := &ordererOrgParties{name: name}
	for _, consenter := range consenters {
		if consenter.GetMspId() == mspID {
			org.parties = append(org.parties, consenter.GetId())
		}
	}
	return org, nil
}

// changeCAList applies the operation to each place of a CA list. Each party's
// list is checked against the request; the org's MSP list follows them:
//   - add appends each certificate a list does not hold yet, and skips, with a
//     message, each a party's list already holds;
//   - remove drops each certificate, which each party's list must hold, and
//     refuses to leave a party's list empty;
//   - set replaces each list as a whole: whichever CAs the list holds, one or
//     more, it then holds exactly the certificates, in the order given.
//
// No certificates leave the lists unchanged.
func changeCAList(op string, list caList, certs []givenCertificate) error {
	if len(certs) == 0 {
		return nil
	}
	switch op {
	case change.CAOpAdd:
		addCertificates(list, certs)
		return nil
	case change.CAOpRemove:
		return removeCertificates(list, certs)
	case change.CAOpSet:
		pems := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			pems = append(pems, cert.pem)
		}
		for _, party := range list.parties {
			*party.certs = slices.Clone(pems)
		}
		*list.msp = pems
		return nil
	default:
		return errors.Newf("unknown operation %q", op)
	}
}

// addCertificates appends to each place of the list each certificate that
// place does not hold yet. A certificate a party's list already holds is
// reported, as the request leaves it as it was.
func addCertificates(list caList, certs []givenCertificate) {
	for _, cert := range certs {
		for _, party := range list.parties {
			if containsCertificate(*party.certs, cert.pem) {
				logger.Infof("the %s list of party %d already holds the certificate of %q; it is not added again",
					list.name, party.party, cert.path)
				continue
			}
			*party.certs = append(*party.certs, cert.pem)
		}
		if !containsCertificate(*list.msp, cert.pem) {
			*list.msp = append(*list.msp, cert.pem)
		}
	}
}

// removeCertificates removes the certificates from each place of the list.
// Each must be in each party's list, and no party's list may be left empty.
func removeCertificates(list caList, certs []givenCertificate) error {
	for _, party := range list.parties {
		for _, cert := range certs {
			if !containsCertificate(*party.certs, cert.pem) {
				return errors.Newf("the %s list of party %d does not hold the certificate of %q",
					list.name, party.party, cert.path)
			}
		}
		*party.certs = withoutCertificates(*party.certs, certs)
		if len(*party.certs) == 0 {
			return errors.Newf("the %s list of party %d cannot be left empty", list.name, party.party)
		}
	}
	*list.msp = withoutCertificates(*list.msp, certs)
	return nil
}

// withoutCertificates returns the list without the certificates.
func withoutCertificates(list [][]byte, certs []givenCertificate) [][]byte {
	return slices.DeleteFunc(list, func(held []byte) bool {
		return slices.ContainsFunc(certs, func(cert givenCertificate) bool {
			return sameCertificate(held, cert.pem)
		})
	})
}

// retargetNodeOUs sets the CA that each node OU identifier of the MSP pins to
// cert, as the orderer's CA rotation does, and returns how many it set. A node
// OU identifier pins a single CA, which the MSP requires to be one of its root
// certificates. An identifier that pins no CA, and an MSP without node OUs, are
// left unchanged.
func retargetNodeOUs(fabricConfig *msppb.FabricMSPConfig, cert []byte) int {
	retargeted := 0
	for _, identifier := range nodeOUIdentifiers(fabricConfig) {
		if len(identifier.GetCertificate()) > 0 {
			identifier.Certificate = cert
			retargeted++
		}
	}
	return retargeted
}

// nodeOUIdentifiers returns the node OU identifiers of the MSP: client, peer,
// admin and orderer. An identifier the MSP does not have is nil.
func nodeOUIdentifiers(fabricConfig *msppb.FabricMSPConfig) []*mspproto.FabricOUIdentifier {
	nodeOUs := fabricConfig.GetFabricNodeOus()
	return []*mspproto.FabricOUIdentifier{
		nodeOUs.GetClientOuIdentifier(),
		nodeOUs.GetPeerOuIdentifier(),
		nodeOUs.GetAdminOuIdentifier(),
		nodeOUs.GetOrdererOuIdentifier(),
	}
}

// certificateSubject returns the subject of a PEM-encoded certificate, to name
// it in messages, or a placeholder if it does not parse.
func certificateSubject(content []byte) string {
	block, _ := pem.Decode(content)
	if block == nil {
		return "<not a PEM certificate>"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "<unparsable certificate>"
	}
	return cert.Subject.String()
}

// containsCertificate reports whether the list holds the certificate.
func containsCertificate(list [][]byte, cert []byte) bool {
	return slices.ContainsFunc(list, func(held []byte) bool {
		return sameCertificate(held, cert)
	})
}

// sameCertificate reports whether two PEM-encoded certificates are the same
// certificate. A certificate is compared by its DER encoding, so that how the
// block happens to format its PEM, such as its line breaks or headers, does not
// matter. Content that is not PEM is compared as is.
func sameCertificate(a, b []byte) bool {
	blockA, _ := pem.Decode(a)
	blockB, _ := pem.Decode(b)
	if blockA == nil || blockB == nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(blockA.Bytes, blockB.Bytes)
}
