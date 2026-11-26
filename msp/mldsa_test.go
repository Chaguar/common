/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/sw"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/Chaguar/common/api/msppb"
)

const (
	testECDSA  = "ecdsa"
	testMLDSA  = "mldsa"
	testMSPID  = "MLDSAMSP"
	gateErrMsg = "ML-DSA public keys require MSP version 3.1 or later"

	pemTypeCertificate = "CERTIFICATE"
)

func TestMLDSAVersionGate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		caAlg    string
		leafAlg  string
		version  MSPVersion
		setupErr string
		idErr    string
	}{
		{name: "v3.0 rejects ML-DSA CA", caAlg: testMLDSA, leafAlg: testECDSA, version: MSPv3_0, setupErr: gateErrMsg},
		{
			name: "v3.0 rejects ML-DSA identity", caAlg: testECDSA, leafAlg: testMLDSA, version: MSPv3_0,
			idErr: gateErrMsg,
		},
		{name: "v3.0 accepts ECDSA", caAlg: testECDSA, leafAlg: testECDSA, version: MSPv3_0},
		{name: "v3.1 accepts ML-DSA CA", caAlg: testMLDSA, leafAlg: testECDSA, version: MSPv3_1},
		{name: "v3.1 accepts ML-DSA identity", caAlg: testECDSA, leafAlg: testMLDSA, version: MSPv3_1},
		{name: "v3.1 accepts ML-DSA chain", caAlg: testMLDSA, leafAlg: testMLDSA, version: MSPv3_1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, tc.caAlg, tc.leafAlg)
			mspInst := newTestMSP(t, tc.version)

			err := mspInst.Setup(toMSPConfig(t, pki.fabricConfig()))
			if tc.setupErr != "" {
				require.ErrorContains(t, err, tc.setupErr)
				return
			}
			require.NoError(t, err)

			id, err := mspInst.DeserializeIdentity(msppb.NewIdentity(testMSPID, pki.leafPEM))
			if tc.idErr != "" {
				require.ErrorContains(t, err, tc.idErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, mspInst.Validate(id))
		})
	}
}

func TestMLDSASigningIdentity(t *testing.T) {
	t.Parallel()
	for _, caAlg := range []string{testECDSA, testMLDSA} {
		t.Run(caAlg+" CA", func(t *testing.T) {
			t.Parallel()
			pki := newTestPKI(t, caAlg, testMLDSA)
			mspInst := newTestMSP(t, MSPv3_1)
			// The private key comes from the KeyMaterial field.
			conf := pki.fabricConfig()
			conf.SigningIdentity = pki.signingIdentity(t)
			require.NoError(t, mspInst.Setup(toMSPConfig(t, conf)))

			signer, err := mspInst.GetDefaultSigningIdentity()
			require.NoError(t, err)
			msg := []byte("hello world")
			sig, err := signer.Sign(msg)
			require.NoError(t, err)

			// ML-DSA signs the full message, not its digest.
			require.NoError(t, mldsa.Verify(pki.leafKey.mldsa, msg, sig, nil))

			id, err := mspInst.DeserializeIdentity(msppb.NewIdentity(testMSPID, pki.leafPEM))
			require.NoError(t, err)
			require.NoError(t, id.Verify(msg, sig))
			require.ErrorContains(t, id.Verify([]byte("tampered"), sig), "The signature is invalid")
		})
	}
}

func TestSanitizeECDSASignedCertNonECDSAParent(t *testing.T) {
	t.Parallel()
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	cert := &x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256}
	parent := &x509.Certificate{PublicKey: sk.PublicKey()}
	_, err = sanitizeECDSASignedCert(cert, parent)
	require.ErrorContains(t, err, "ECDSA-signed certificate has a *mldsa.PublicKey parent public key")
}

type testPKI struct {
	caPEM    []byte
	adminPEM []byte
	leafPEM  []byte
	leafKey  *mldsaOrECDSAKey
}

// mldsaOrECDSAKey is a test key and, for ML-DSA, its public key.
type mldsaOrECDSAKey struct {
	signer crypto.Signer
	mldsa  *mldsa.PublicKey
}

type testIssuer struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newTestPKI creates a root CA, an ECDSA admin, and a leaf identity.
func newTestPKI(t *testing.T, caAlg, leafAlg string) *testPKI {
	t.Helper()
	caKey := newTestKey(t, caAlg)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca", Organization: []string{testMSPID}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.signer.Public(), caKey.signer)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	issuer := &testIssuer{cert: caCert, key: caKey.signer}
	leafKey := newTestKey(t, leafAlg)
	return &testPKI{
		caPEM:    pemCert(caDER),
		adminPEM: newTestLeaf(t, issuer, newTestKey(t, testECDSA).signer, "admin"),
		leafPEM:  newTestLeaf(t, issuer, leafKey.signer, "leaf"),
		leafKey:  leafKey,
	}
}

func (p *testPKI) fabricConfig() *msppb.FabricMSPConfig {
	return &msppb.FabricMSPConfig{
		Name:      testMSPID,
		RootCerts: [][]byte{p.caPEM},
		Admins:    [][]byte{p.adminPEM},
	}
}

func (p *testPKI) signingIdentity(t *testing.T) *m.SigningIdentityInfo {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.leafKey.signer)
	require.NoError(t, err)
	return &m.SigningIdentityInfo{
		PublicSigner: p.leafPEM,
		PrivateSigner: &m.KeyInfo{
			KeyIdentifier: "leaf",
			KeyMaterial:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		},
	}
}

func toMSPConfig(t *testing.T, conf *msppb.FabricMSPConfig) *m.MSPConfig {
	t.Helper()
	raw, err := proto.Marshal(conf)
	require.NoError(t, err)
	return &m.MSPConfig{Type: int32(FABRIC), Config: raw}
}

func newTestMSP(t *testing.T, version MSPVersion) MSP { //nolint:ireturn // the MSP constructor returns the interface.
	t.Helper()
	csp, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	require.NoError(t, err)
	mspInst, err := New(&BCCSPNewOpts{NewBaseOpts{Version: version}}, csp)
	require.NoError(t, err)
	return mspInst
}

func newTestKey(t *testing.T, alg string) *mldsaOrECDSAKey {
	t.Helper()
	if alg == testMLDSA {
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		require.NoError(t, err)
		return &mldsaOrECDSAKey{signer: key, mldsa: key.PublicKey()}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &mldsaOrECDSAKey{signer: key}
}

func newTestLeaf(t *testing.T, issuer *testIssuer, key crypto.Signer, cn string) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{testMSPID}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, key.Public(), issuer.key)
	require.NoError(t, err)
	return pemCert(der)
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}
