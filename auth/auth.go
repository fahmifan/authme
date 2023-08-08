package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
)

type Auther struct {
	userReader     authme.UserReader
	passwordHasher authme.PasswordHasher
	retryCountRW   authme.RetryCountReadWriter
	locker         authme.Locker
}

func NewAuth(
	userReader authme.UserReader,
	passwordHasher authme.PasswordHasher,
	retryCountRW authme.RetryCountReadWriter,
	locker authme.Locker,
) Auther {
	return Auther{
		userReader:     userReader,
		passwordHasher: passwordHasher,
		retryCountRW:   retryCountRW,
		locker:         locker,
	}
}

type AuthRequest struct {
	PID           string
	PlainPassword string
}

func (auther *Auther) Auth(ctx context.Context, req AuthRequest) (user authme.User, err error) {
	err = auther.locker.Lock(ctx, makeLockKey(req.PID), func(ctx context.Context) (err error) {
		user, err = auther.userReader.FindByPID(ctx, req.PID)
		if err != nil {
			return fmt.Errorf("read user: %w", err)
		}

		rc, err := auther.retryCountRW.Read(ctx, user)
		if err != nil {
			return fmt.Errorf("retry count: %w", err)
		}

		if !rc.CanAuth(time.Now()) {
			return fmt.Errorf("auth is locked")
		}

		err = auther.passwordHasher.Compare(user.PasswordHash, req.PlainPassword)
		if err != nil {
			return fmt.Errorf("compare password: %w", err)
		}

		rc = rc.Inc()

		err = auther.retryCountRW.Write(ctx, user, rc)
		if err != nil {
			return fmt.Errorf("reset retry count: %w", err)
		}

		return nil
	})
	if err != nil {
		return authme.User{}, fmt.Errorf("lock: %w", err)
	}

	return user, nil
}

func makeLockKey(pid string) string {
	return fmt.Sprintf("auth:%s", pid)
}
