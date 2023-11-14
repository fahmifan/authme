package psql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fahmifan/authme"
	"github.com/fahmifan/authme/backend/psql/sqlcs"
	"github.com/google/uuid"
)

var _ authme.UserReader = UserReadWriter{}
var _ authme.UserWriter = UserReadWriter{}

func UserFromSQL(xuser sqlcs.User) authme.User {
	return authme.User{
		GUID:         xuser.ID.String(),
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

func (psql UserReadWriter) FindByPID(ctx context.Context, tx authme.DBTX, pid string) (authme.User, error) {
	xuser, err := sqlcs.New(tx).FindUserByEmail(ctx, pid)
	if err != nil {
		if isNotFoundErr(err) {
			return authme.User{}, authme.ErrNotFound
		}

		return authme.User{}, fmt.Errorf("PSQL: FindUserByEmail: %w", err)
	}

	return UserFromSQL(xuser), nil
}

func (psql UserReadWriter) Create(ctx context.Context, tx authme.DBTX, user authme.User) (_ authme.User, err error) {
	var guid uuid.UUID
	if user.GUID == "" {
		guid = uuid.New()
	} else {
		guid, err = uuid.Parse(user.GUID)
		if err != nil {
			return authme.User{}, fmt.Errorf("PSQL: Write: parse guid: %w", err)
		}
	}

	_, err = sqlcs.New(tx).InsertUser(ctx, sqlcs.InsertUserParams{
		ID:           guid,
		Email:        user.PID,
		PasswordHash: user.PasswordHash,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Name:         user.Name,
		Status:       string(user.Status),
		VerifyToken:  user.VerifyToken,
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("PSQL: Write: insert user: %w", err)
	}

	return user, nil
}

func (psql UserReadWriter) Update(ctx context.Context, tx authme.DBTX, user authme.User) (_ authme.User, err error) {
	_, err = sqlcs.New(tx).UpdateUser(ctx, sqlcs.UpdateUserParams{
		ID:           uuid.MustParse(user.GUID),
		Email:        user.PID,
		Name:         user.Name,
		Status:       string(user.Status),
		PasswordHash: user.PasswordHash,
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("PSQL: Write: update user: %w", err)
	}

	return user, nil
}

func isNotFoundErr(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
