/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/cockroachdb/errors"

	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/tools/fxadmin/core/modify/change"
)

// The operations of `modify app|orderer known-certs`, as its sub-verbs name
// them.
const (
	knownCertsAdd    = "add"
	knownCertsRemove = "remove"
	knownCertsSet    = "set"
)

// KnownCerts implements `fxadmin modify app|orderer known-certs add|remove|set`.
// It changes the known certificates (known_certs) of the Fabric MSP of one org:
// the org named Org in the request's Group, Application or Orderer. A client
// can sign with the ID of a known certificate instead of the certificate, and
// the MSP resolves that ID only through its known certificates.
//
// The application orgs and the orderer orgs are assumed to be different orgs,
// each with its own MSP, so only the org's MSP in its own group changes. The
// channel config rejects an org that is in both groups, with two different
// versions of its MSP.
//
// The config block at the request's BlockPath is rewritten in place.
func (*Handler) KnownCerts(ch change.KnownCerts) error {
	logger.Debugf("modify %s known-certs %s: org=%s certs=%v block=%s",
		ch.Group, ch.Op, ch.Org, ch.Certs, ch.BlockPath)

	certs, err := readKnownCertsChange(ch)
	if err != nil {
		return err
	}
	block, err := readAndDecodeConfigBlock(ch.BlockPath)
	if err != nil {
		return err
	}
	group := block.Config().GetChannelGroup().GetGroups()[ch.Group]
	if group == nil {
		return errors.Newf("the config has no %s group", ch.Group)
	}
	org := group.GetGroups()[ch.Org]
	if org == nil {
		return errors.Newf("the %s group has no org %q; give the org's name in the group, not its MSP ID",
			ch.Group, ch.Org)
	}
	orgMSP, err := decodeOrgMSP(org)
	if err != nil {
		return fmt.Errorf("%s org %q: %w", ch.Group, ch.Org, err)
	}
	if err := changeKnownCerts(ch.Op, &orgMSP.fabricConfig.KnownCerts, certs); err != nil {
		return fmt.Errorf("%s org %q: %w", ch.Group, ch.Org, err)
	}
	if err := orgMSP.encode(); err != nil {
		return fmt.Errorf("%s org %q: %w", ch.Group, ch.Org, err)
	}

	if err := validateEncodeAndWriteConfigBlock(block, ch.BlockPath); err != nil {
		return err
	}
	logger.Infof("applied known-certs %s to %s org %s in %s", ch.Op, ch.Group, ch.Org, ch.BlockPath)
	return nil
}

// readKnownCertsChange checks the request's operation and group, and reads its
// certificate files. Each must hold a PEM-encoded X.509 certificate of an
// identity, not of a CA, as the MSP accepts no CA certificate as an identity.
func readKnownCertsChange(ch change.KnownCerts) ([]givenCertificate, error) {
	if !slices.Contains([]string{knownCertsAdd, knownCertsRemove, knownCertsSet}, ch.Op) {
		return nil, errors.Newf("unknown operation %q: want %q, %q or %q",
			ch.Op, knownCertsAdd, knownCertsRemove, knownCertsSet)
	}
	if ch.Group != channelconfig.ApplicationGroupKey && ch.Group != channelconfig.OrdererGroupKey {
		return nil, errors.Newf("unknown group %q: want %q or %q",
			ch.Group, channelconfig.ApplicationGroupKey, channelconfig.OrdererGroupKey)
	}
	if len(ch.Certs) == 0 {
		return nil, errors.New("nothing to change: no known certificate is given")
	}
	certs, err := readGivenCertificates(ch.Certs, rejectCACertificate)
	if err != nil {
		return nil, fmt.Errorf("invalid known certificates: %w", err)
	}
	return certs, nil
}

// rejectCACertificate checks that the certificate at path is not a CA
// certificate.
func rejectCACertificate(path string, cert *x509.Certificate) error {
	if cert.IsCA {
		return errors.Newf("%q is a CA certificate; a known certificate must be an identity certificate", path)
	}
	return nil
}

// changeKnownCerts applies the operation to the known certificates:
//   - add appends each certificate the list does not hold yet, and skips, with
//     a message, each it already holds;
//   - remove drops each certificate, which the list must hold. The list may be
//     left empty;
//   - set replaces the list as a whole with the certificates, in the order
//     given.
func changeKnownCerts(op string, known *[][]byte, certs []givenCertificate) error {
	switch op {
	case knownCertsAdd:
		for _, cert := range certs {
			if containsCertificate(*known, cert.pem) {
				logger.Infof("the known certificates already hold the certificate of %q; it is not added again",
					cert.path)
				continue
			}
			*known = append(*known, cert.pem)
		}
		return nil
	case knownCertsRemove:
		for _, cert := range certs {
			if !containsCertificate(*known, cert.pem) {
				return errors.Newf("the known certificates do not hold the certificate of %q", cert.path)
			}
		}
		*known = withoutCertificates(*known, certs)
		return nil
	case knownCertsSet:
		pems := make([][]byte, 0, len(certs))
		for _, cert := range certs {
			pems = append(pems, cert.pem)
		}
		*known = pems
		return nil
	default:
		return errors.Newf("unknown operation %q", op)
	}
}
