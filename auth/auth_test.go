package auth_test

import (
	"testing"
	"time"

	"github.com/fahmifan/authme"
	"github.com/stretchr/testify/require"
)

func TestCanAuth(t *testing.T) {
	t.Run(`can't auth because count is max & lock is not expired`, func(t *testing.T) {
		now := time.Now()
		rc := authme.RetryCount{
			Count:        3,
			MaxCount:     3,
			LastRetryAt:  now,
			LockDuration: time.Hour,
		}

		can := rc.CanAuth(now)
		require.False(t, can)
	})

	t.Run(`can auth when count is not maxed`, func(t *testing.T) {
		now := time.Now()
		rc := authme.RetryCount{
			Count:        0,
			MaxCount:     3,
			LastRetryAt:  now,
			LockDuration: time.Hour,
		}

		can := rc.CanAuth(now)
		require.True(t, can)
	})

	t.Run(`can auth when count is maxed but lock is expired`, func(t *testing.T) {
		now := time.Now()
		rc := authme.RetryCount{
			Count:        3,
			MaxCount:     3,
			LastRetryAt:  now.Add(-(time.Hour + time.Minute)),
			LockDuration: time.Hour,
		}

		can := rc.CanAuth(now)
		require.True(t, can)
	})
}
