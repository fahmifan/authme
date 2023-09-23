package auth_test

import (
	"testing"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestSession_CreateAccessToken(t *testing.T) {
	now := time.Now()
	guid := "guid"

	sess, err := auth.CreateSession(authme.User{}, now, guid)
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

	t.Run("ok refresh token", func(t *testing.T) {
		sess, err := auth.CreateSession(authme.User{}, now, guid)
		require.NoError(t, err)
		require.NotZero(t, sess)

		refreshed, err := sess.Refresh(now)
		require.NoError(t, err)
		require.NotZero(t, refreshed)
		require.NotEmpty(t, refreshed.Token)
		require.NotEqual(t, sess.Token, refreshed.Token)
		require.Greater(t, refreshed.TokenExpiredAt, now)
	})

	t.Run("should failed if token already expired", func(t *testing.T) {
		sess, err := auth.CreateSession(authme.User{}, now, guid)
		require.NoError(t, err)
		require.NotZero(t, sess)

		// expired it now
		sess.TokenExpiredAt = now.Add(-1 * time.Hour)

		_, err = sess.Refresh(now)
		require.Error(t, err)
		require.ErrorIs(t, err, auth.ErrSessionExpired)
	})

}

func TestVerifyAccessToken(t *testing.T) {
	user := authme.User{}
	guid := "guid123"
	now := time.Now()
	secret := []byte("secret")

	session, err := auth.CreateSession(user, now, guid)
	require.NoError(t, err)

	t.Run("failed, wrong secret", func(t *testing.T) {
		accessToken, expiredAt, err := session.CreateAccessToken(secret, now)
		require.NoError(t, err)
		require.NotZero(t, expiredAt)
		require.NotEmpty(t, accessToken)

		_, err = auth.VerifyAccessToken([]byte("wrong secret"), accessToken)
		require.Error(t, err)
	})

	t.Run("failed, invalid access token", func(t *testing.T) {
		_, err = auth.VerifyAccessToken(secret, "access token is invalid")
		require.Error(t, err)
	})

	t.Run("access token expired", func(t *testing.T) {
		user := authme.User{}
		guid := "guid123"
		now := time.Now().Add(-24 * time.Hour)
		secret := []byte("secret")

		session, err := auth.CreateSession(user, now, guid)
		require.NoError(t, err)

		accessToken, expiredAt, err := session.CreateAccessToken(secret, now)
		require.NoError(t, err)
		require.NotZero(t, expiredAt)

		_, err = auth.VerifyAccessToken(secret, accessToken)
		require.Error(t, err)
		require.ErrorIs(t, err, jwt.ErrTokenExpired)
	})

	t.Run("ok", func(t *testing.T) {
		accessToken, expiredAt, err := session.CreateAccessToken(secret, now)
		require.NoError(t, err)
		require.NotZero(t, expiredAt)
		require.NotEmpty(t, accessToken)

		authUser, err := auth.VerifyAccessToken(secret, accessToken)
		require.NoError(t, err)
		require.Equal(t, user.GUID, authUser.GUID)
		require.Equal(t, user.PID, authUser.PID)
	})
}
