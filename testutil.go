package wampprotocli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func NoErrorLen(t *testing.T, err error, object interface{}, len int) {
	require.NoError(t, err)
	require.Len(t, object, len)
}

func NoErrorEqual(t *testing.T, err error, expected interface{}, actual interface{}) {
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
