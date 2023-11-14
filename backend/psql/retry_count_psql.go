package psql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/psql/sqlcs"
	"github.com/google/uuid"
)

const MaxRetryCount = 3
const LockDuration = 1 * time.Minute

var _ authme.RetryCountReadWriter = RetryCountReadWriter{}

type RetryCountReadWriter struct {
}

func NewRetryCountReadWriter() RetryCountReadWriter {
	return RetryCountReadWriter{}
}

func (rw RetryCountReadWriter) GetOrCreate(ctx context.Context, tx authme.DBTX, user authme.User) (authme.RetryCount, error) {
	query := sqlcs.New(tx)
	userGUID, err := uuid.Parse(user.GUID)
	if err != nil {
		return authme.RetryCount{}, fmt.Errorf("RetryCountReadWriter: GetOrCreate: parse guid: %w", err)
	}

	xretry, err := query.FindUserRetryCountByUserID(ctx, userGUID)
	switch {
	case err == nil:
		return RetryCountFromSQL(xretry), nil
	case isNotFoundErr(err):
		guid := uuid.New()
		xretry, err = query.InsertUserRetryCount(ctx, sqlcs.InsertUserRetryCountParams{
			ID:         guid,
			UserID:     userGUID,
			RetryCount: 0,
			CreatedAt:  time.Now(),
		})
		if err != nil {
			return authme.RetryCount{}, fmt.Errorf("RetryCountReadWriter: GetOrCreate: insert: %w", err)
		}

		return RetryCountFromSQL(xretry), nil
	default:
		return authme.RetryCount{}, fmt.Errorf("RetryCountReadWriter: GetOrCreate: find: %w", err)
	}
}

func (rw RetryCountReadWriter) Update(ctx context.Context, tx authme.DBTX, retryCount authme.RetryCount) (authme.RetryCount, error) {
	query := sqlcs.New(tx)
	guid, err := uuid.Parse(retryCount.ID)
	if err != nil {
		return authme.RetryCount{}, fmt.Errorf("RetryCountReadWriter: Update: parse guid: %w", err)
	}

	xretry, err := query.UpdateUserRetryCount(ctx, sqlcs.UpdateUserRetryCountParams{
		LastRetryAt: sql.NullTime{Time: retryCount.LastRetryAt, Valid: true},
		ID:          guid,
		RetryCount:  MaxRetryCount,
	})
	if err != nil {
		return authme.RetryCount{}, fmt.Errorf("RetryCountReadWriter: Update: update: %w", err)
	}

	return RetryCountFromSQL(xretry), nil
}

func RetryCountFromSQL(xretry sqlcs.UserRetryCount) authme.RetryCount {
	return authme.RetryCount{
		ID:           xretry.ID.String(),
		Count:        int(xretry.RetryCount),
		LastRetryAt:  xretry.LastRetryAt.Time,
		MaxCount:     MaxRetryCount,
		LockDuration: LockDuration,
	}
}
