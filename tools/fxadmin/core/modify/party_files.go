/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modify

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
)

// crlField is the field of an MSP config, in a party definition or an
// organization definition, that holds CRLs.
const crlField = "revocation_list"

// certificateFields are the fields of a party definition, and of an
// organization definition, that hold certificates: a single one, or a list of
// them. Each is mapped to the check its certificates must pass, the one the
// other modify commands make for that kind of certificate: a CA field holds CA
// certificates, as `modify party ca` requires, and an identity field holds
// certificates of identities, not of CAs, as `modify app|orderer known-certs`
// requires. A node's own certificates have no check, as `modify party node`
// makes none.
var certificateFields = map[string]func(path string, cert *x509.Certificate) error{
	// Party, and the node_config of each of its nodes.
	"CACerts": requireCACertificate, "TLSCACerts": requireCACertificate,
	"client_tls_cert": nil, "server_tls_cert": nil, "sign_cert": nil,
	// Org's MSP config, and its OU identifiers.
	"root_certs": requireCACertificate, "intermediate_certs": requireCACertificate,
	"tls_root_certs": requireCACertificate, "tls_intermediate_certs": requireCACertificate,
	"certificate": requireCACertificate,
	"admins":      rejectCACertificate, "known_certs": rejectCACertificate,
}

// readCertificateFiles replaces, in a parsed section of a party definition or
// of an organization definition, the path of each certificate and CRL file with
// the file's content, base64-encoded as the block stores it. For example:
//
//	RouterConfig: {node_config: {server_tls_cert: router-tls.pem}}
//
// becomes
//
//	RouterConfig: {node_config: {server_tls_cert: LS0tLS1CRUdJTi...}}
//
// A path may be absolute, or relative to dir, the directory of the definition.
// Each file must hold a single PEM block: a certificate that passes the check
// of its field, or a CRL in the field of CRLs. A list may not hold the same
// certificate or CRL twice.
func readCertificateFiles(section any, dir string) error {
	switch section := section.(type) {
	case map[string]any:
		return readMapCertificateFiles(section, dir)
	case []any:
		return readListCertificateFiles(section, dir)
	default:
		// A plain value, such as a host or a port, holds no certificate.
		return nil
	}
}

// readMapCertificateFiles reads the certificate and CRL files of a map: the
// paths of its certificate and CRL fields, and those of the maps and lists it
// holds.
func readMapCertificateFiles(section map[string]any, dir string) error {
	for key, value := range section {
		var err error
		switch check, isCertificateField := certificateFields[key]; {
		case isCertificateField:
			section[key], err = readCertificatePaths(value, dir, check)
		case key == crlField:
			section[key], err = readCRLPaths(value, dir)
		default:
			err = readCertificateFiles(value, dir)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

// readListCertificateFiles reads the certificate and CRL files of each item of
// a list.
func readListCertificateFiles(section []any, dir string) error {
	for i, item := range section {
		if err := readCertificateFiles(item, dir); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

// readCertificatePaths reads the files of a certificate field: a path, or a
// list of paths. Each file must hold a single PEM block, a PEM-encoded X.509
// certificate that passes check, when check is set, and no certificate may be
// given twice.
func readCertificatePaths(value any, dir string, check func(string, *x509.Certificate) error) (any, error) {
	paths, err := pathsOf(value, dir)
	if err != nil || paths == nil {
		return nil, err
	}
	certs, err := readGivenCertificates(paths, check)
	if err != nil {
		return nil, err
	}
	contents := make([][]byte, len(certs))
	for i, cert := range certs {
		contents[i] = cert.pem
	}
	return encodedLike(value, contents), nil
}

// readCRLPaths reads the files of a CRL field: a path, or a list of paths. Each
// file must hold a single PEM block, a PEM-encoded X.509 CRL, and no CRL may be
// given twice.
func readCRLPaths(value any, dir string) (any, error) {
	paths, err := pathsOf(value, dir)
	if err != nil || paths == nil {
		return nil, err
	}
	crls := make([][]byte, 0, len(paths))
	for _, path := range paths {
		crl, err := readCRLFile(path)
		if err != nil {
			return nil, err
		}
		for i, given := range crls {
			if sameCertificate(given, crl) {
				return nil, errors.Newf("%q and %q hold the same CRL", paths[i], path)
			}
		}
		crls = append(crls, crl)
	}
	return encodedLike(value, crls), nil
}

// readCRLFile reads the PEM-encoded X.509 CRL of the file at path, which must
// be the file's single PEM block, and returns it PEM-encoded.
func readCRLFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read CRL %q", path)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "X509 CRL" {
		return nil, errors.Newf("%q is not a PEM-encoded CRL", path)
	}
	if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		return nil, errors.Wrapf(err, "failed to parse CRL %q", path)
	}
	if err := requireOnePEMBlock(path); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}

// pathsOf returns the paths of a certificate or CRL field, a path or a list of
// paths, with each relative path joined to dir. A field that is not set has no
// paths, and neither has a field set to an empty string, the form `fxadmin
// decode` gives a certificate that is not set, such as the certificate of an OU
// identifier that pins no CA.
func pathsOf(value any, dir string) ([]string, error) {
	switch value := value.(type) {
	case nil:
		return nil, nil
	case string:
		if value == "" {
			return nil, nil
		}
		return []string{resolvePath(value, dir)}, nil
	case []any:
		paths := make([]string, len(value))
		for i, item := range value {
			path, ok := item.(string)
			if !ok {
				return nil, errors.Newf("[%d]: want a file path, got %T", i, item)
			}
			paths[i] = resolvePath(path, dir)
		}
		return paths, nil
	default:
		return nil, errors.Newf("want a file path or a list of file paths, got %T", value)
	}
}

// resolvePath returns path as is when it is absolute, and joined to dir when
// it is relative.
func resolvePath(path, dir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// encodedLike returns the contents of a field's files base64-encoded, as the
// block stores them, in the shape of the field's value: a list for a list of
// paths, and the single content for a path.
func encodedLike(value any, contents [][]byte) any {
	if _, isList := value.([]any); !isList {
		return base64.StdEncoding.EncodeToString(contents[0])
	}
	encoded := make([]any, len(contents))
	for i, content := range contents {
		encoded[i] = base64.StdEncoding.EncodeToString(content)
	}
	return encoded
}
