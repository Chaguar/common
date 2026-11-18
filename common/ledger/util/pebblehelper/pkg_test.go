/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pebblehelper

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type testDBProviderEnv struct {
	provider *Provider
}

func newTestProviderEnv(t *testing.T, path string) *testDBProviderEnv {
	t.Helper()
	provider, err := NewProvider(&Conf{DBPath: path})
	require.NoError(t, err)
	t.Cleanup(provider.Close)
	return &testDBProviderEnv{provider: provider}
}

func (env *testDBProviderEnv) cleanup() {
	env.provider.Close()
}
