package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/sqlite/sqlcs"
	"github.com/google/uuid"
)

var _ authme.UserReader = UserReadWriter{}
var _ authme.UserWriter = UserReadWriter{}

func UserFromSQL(xuser sqlcs.User) authme.User {
	return authme.User{
		GUID:         xuser.ID,
		PID:          xuser.Email,
		Email:        xuser.Email,
		Name:         xuser.Name,
		VerifyToken:  xuser.VerifyToken,
		Status:       authme.UserStatus(xuser.Status),
		PasswordHash: xuser.PasswordHash,
	}
}

type UserReadWriter struct {
}

func NewUserReadWriter() UserReadWriter {
	return UserReadWriter{}
}

func (rw UserReadWriter) FindByPID(ctx context.Context, tx authme.DBTX, pid string) (authme.User, error) {
	xuser, err := sqlcs.New(tx).FindUserByEmail(ctx, pid)
	if err != nil {
		if isNotFoundErr(err) {
			return authme.User{}, authme.ErrNotFound
		}

		return authme.User{}, fmt.Errorf("sqlite: FindUserByEmail: %w", err)
	}

	return UserFromSQL(xuser), nil
}

func (rw UserReadWriter) Create(ctx context.Context, tx authme.DBTX, user authme.User) (_ authme.User, err error) {
	now := time.Now()

	guid := user.GUID
	if user.GUID == "" {
		guid = uuid.New().String()
	}

	_, err = sqlcs.New(tx).InsertUser(ctx, sqlcs.InsertUserParams{
		ID:           guid,
		Email:        user.PID,
		PasswordHash: user.PasswordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
		Name:         user.Name,
		Status:       string(user.Status),
		VerifyToken:  user.VerifyToken,
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("sqlite: Write: insert user: %w", err)
	}

	return user, nil
}

func (rw UserReadWriter) Update(ctx context.Context, tx authme.DBTX, user authme.User) (_ authme.User, err error) {
	_, err = sqlcs.New(tx).UpdateUser(ctx, sqlcs.UpdateUserParams{
		ID:           user.GUID,
		Email:        user.PID,
		Name:         user.Name,
		Status:       string(user.Status),
		PasswordHash: user.PasswordHash,
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("sqlite: Write: update user: %w", err)
	}

	return user, nil
}

func isNotFoundErr(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
