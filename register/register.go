package register

import (
	"context"
	"errors"
	"fmt"

	"github.com/fahmifan/authme"
)

// Register is a use case for registering a new user.
type Register struct {
	userRW authme.UserReadWriter
	hasher authme.PasswordHasher
}

func NewRegister(
	userRW authme.UserReadWriter,
	hasher authme.PasswordHasher,
) Register {
	return Register{
		userRW: userRW,
		hasher: hasher,
	}
}

type RegisterRequest struct {
	PID           string
	PlainPassword string
}

// Register registers a new user.
func (reg Register) Register(ctx context.Context, req RegisterRequest) (authme.User, error) {
	_, err := reg.userRW.FindByPID(ctx, req.PID)
	if err != nil && !isErrNotFound(err) {
		return authme.User{}, fmt.Errorf("read user: %w", err)
	}
	if !isErrNotFound(err) {
		return authme.User{}, fmt.Errorf("user already exists")
	}

	hashedPassword, err := reg.hasher.HashPassword(req.PlainPassword)
	if err != nil {
		return authme.User{}, fmt.Errorf("hash password: %w", err)
	}

	regUser := authme.User{
		PID:          req.PID,
		PasswordHash: hashedPassword,
	}
	err = reg.userRW.Create(ctx, regUser)
	if err != nil {
		return authme.User{}, fmt.Errorf("save user: %w", err)
	}

	return regUser, nil
}

func isErrNotFound(err error) bool {
	return errors.Is(err, authme.ErrNotFound)
}
