package auth

import (
	"testing"
	"time"

	"github.com/fahmifan/authme"
	"github.com/stretchr/testify/require"
)

func TestSession_CreateAccessToken(t *testing.T) {
	now := time.Now()
	guid := "guid"

	sess, err := CreateSession(authme.User{}, now, guid)
	require.NoError(t, err)
	require.NotEmpty(t, sess.Token)
	require.NotZero(t, sess.TokenExpiredAt)

	token, expiredAt, err := sess.CreateAccessToken([]byte("secret"), now)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Greater(t, expiredAt, now)
}

func TestSession_Refresh(t *testing.T) {
	now := time.Now()
	guid := "guid"

	sess, err := CreateSession(authme.User{}, now, guid)
	require.NoError(t, err)
	require.NotZero(t, sess)

	refreshed, err := sess.Refresh(time.Now())
	require.NoError(t, err)
	require.NotZero(t, refreshed)
	require.NotEmpty(t, refreshed.Token)
	require.NotEqual(t, sess.Token, refreshed.Token)
	require.Greater(t, refreshed.TokenExpiredAt, now)
}
