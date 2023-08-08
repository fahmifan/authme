package authme

import (
	"context"
	"time"
)

type RetryCountReader interface {
	// Read reads retry count for user.
	Read(ctx context.Context, user User) (RetryCount, error)
}

type ReatryCountWriter interface {
	// Write writes retry count for user.
	Write(ctx context.Context, user User, rc RetryCount) error
}

type RetryCountReadWriter interface {
	RetryCountReader
	ReatryCountWriter
}

type RetryCount struct {
	ID           string
	Count        int
	MaxCount     int
	LastRetryAt  time.Time
	LockDuration time.Duration
}

// CanAuth returns true if user can do authentication.
func (rc RetryCount) CanAuth(now time.Time) bool {
	isLocked := rc.Count >= rc.MaxCount
	if !isLocked {
		return true
	}

	isLockExpired := now.After(rc.LastRetryAt.Add(rc.LockDuration))

	return isLocked && isLockExpired
}

func (rc RetryCount) Reset() RetryCount {
	rc.Count = 0
	return rc
}

func (rc RetryCount) Inc() RetryCount {
	if rc.Count >= rc.MaxCount {
		return rc
	}

	rc.Count++
	return rc
}
