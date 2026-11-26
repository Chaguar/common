/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptogen

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Chaguar/common/api/msppb"
	"github.com/Chaguar/common/msp"
)

func TestMLDSALocalMSP(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		keyAlg string
		params mldsa.Parameters
	}{
		{keyAlg: MLDSA44, params: mldsa.MLDSA44()},
		{keyAlg: MLDSA65, params: mldsa.MLDSA65()},
		{keyAlg: MLDSA87, params: mldsa.MLDSA87()},
	} {
		t.Run(tc.keyAlg, func(t *testing.T) {
			t.Parallel()
			testDir := t.TempDir()
			tree := newMspTree(testDir)
			params := newMLDSAMSPParameters(t, testDir, tc.keyAlg)
			require.NoError(t, tree.generateLocalMSP(params))

			// The signing key is found in the BCCSP file keystore.
			localMsp, err := msp.LoadLocalMspDir(msp.DirLoadParameters{MspDir: tree.MSP})
			require.NoError(t, err)
			signer, err := localMsp.GetDefaultSigningIdentity()
			require.NoError(t, err)

			msg := []byte("hello world")
			sig, err := signer.Sign(msg)
			require.NoError(t, err)
			require.Len(t, sig, tc.params.SignatureSize())

			certPEM, err := signer.GetCertificatePEM()
			require.NoError(t, err)
			verifyingMsp, err := msp.LoadVerifyingMspDir(msp.DirLoadParameters{MspDir: tree.MSP})
			require.NoError(t, err)
			id, err := verifyingMsp.DeserializeIdentity(msppb.NewIdentity(signer.GetMSPIdentifier(), certPEM))
			require.NoError(t, err)
			require.NoError(t, id.Validate())
			require.NoError(t, id.Verify(msg, sig))
			require.Error(t, id.Verify([]byte("tampered"), sig))

			// The signature is over the full message.
			cert, err := loadCertificate(path.Join(tree.MSP, "signcerts"))
			require.NoError(t, err)
			require.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
			pub, ok := cert.PublicKey.(*mldsa.PublicKey)
			require.True(t, ok)
			require.NoError(t, mldsa.Verify(pub, msg, sig, nil))

			// The CA SKI is computed from the ML-DSA public key.
			caCert, err := loadCertificate(path.Join(tree.MSP, "cacerts"))
			require.NoError(t, err)
			caPub, ok := caCert.PublicKey.(*mldsa.PublicKey)
			require.True(t, ok)
			ski := sha256.Sum256(caPub.Bytes())
			require.Equal(t, ski[:], caCert.SubjectKeyId)
		})
	}
}

func TestMLDSAPrivateKey(t *testing.T) {
	t.Parallel()
	testDir := t.TempDir()

	priv, err := generatePrivateKey(testDir, MLDSA65)
	require.NoError(t, err)
	loaded, err := loadPrivateKey(testDir)
	require.NoError(t, err)
	mldsaKey, ok := loaded.(*mldsa.PrivateKey)
	require.True(t, ok)
	require.True(t, mldsaKey.Equal(priv))

	require.Equal(t, mldsaKey, newSignerFromPrivateKey(priv))
	require.Equal(t, mldsaKey.PublicKey(), getPublicKey(priv))
}

func newMLDSAMSPParameters(t *testing.T, rootDir, keyAlg string) nodeParameters {
	t.Helper()
	signCA := defaultCA(t, mspTestCAName, path.Join(rootDir, "ca"))
	tlsCA := defaultCA(t, mspTestCAName, path.Join(rootDir, "tlsca"))
	for _, ca := range []*caParams{signCA, tlsCA} {
		ca.KeyAlgorithm = keyAlg
		require.NoError(t, buildCA(path.Join(rootDir, ca.Name), ca))
	}
	return nodeParameters{
		Name:      mspTestName,
		OU:        PeerOU,
		KeyAlg:    keyAlg,
		SignCa:    signCA,
		TLSCa:     tlsCA,
		EnableOUs: true,
	}
}
