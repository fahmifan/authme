package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
)

type UserReader interface {
	FindByPID(ctx context.Context, dbtx authme.DBTX, pid string) (authme.User, error)
}

type Auther struct {
	userReader     UserReader
	passwordHasher authme.PasswordHasher
	retryCountRW   authme.RetryCountReadWriter
}

type NewAuthArg struct {
	UserReader     UserReader
	PasswordHasher authme.PasswordHasher
	RetryCountRW   authme.RetryCountReadWriter
}

func NewAuth(arg NewAuthArg) Auther {
	return Auther{
		userReader:     arg.UserReader,
		passwordHasher: arg.PasswordHasher,
		retryCountRW:   arg.RetryCountRW,
	}
}

type AuthRequest struct {
	PID           string
	PlainPassword string
}

func (auther *Auther) Auth(ctx context.Context, tx authme.DBTX, req AuthRequest) (user authme.User, err error) {
	if req.PID == "" {
		return authme.User{}, fmt.Errorf("pid is required")
	}
	if req.PlainPassword == "" {
		return authme.User{}, fmt.Errorf("password is required")
	}

	user, err = auther.userReader.FindByPID(ctx, tx, req.PID)
	if err != nil {
		return authme.User{}, fmt.Errorf("read user: %w", err)
	}

	rc, err := auther.retryCountRW.GetOrCreate(ctx, tx, user)
	if err != nil {
		return authme.User{}, fmt.Errorf("retry count: %w", err)
	}

	if !rc.CanAuth(time.Now()) {
		return authme.User{}, fmt.Errorf("auth is locked")
	}

	err = auther.passwordHasher.Compare(user.PasswordHash, req.PlainPassword)
	if err != nil {
		return authme.User{}, fmt.Errorf("compare password: %w", err)
	}

	rc = rc.Inc()

	_, err = auther.retryCountRW.Update(ctx, tx, rc)
	if err != nil {
		return authme.User{}, fmt.Errorf("reset retry count: %w", err)
	}

	return user, nil
}

func makeLockKey(pid string) string {
	return fmt.Sprintf("auth:%s", pid)
}
