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

type NewAuthArg struct {
	UserReader     authme.UserReader
	PasswordHasher authme.PasswordHasher
	RetryCountRW   authme.RetryCountReadWriter
	Locker         authme.Locker
}

func NewAuth(arg NewAuthArg) Auther {
	return Auther{
		userReader:     arg.UserReader,
		passwordHasher: arg.PasswordHasher,
		retryCountRW:   arg.RetryCountRW,
		locker:         arg.Locker,
	}
}

type AuthRequest struct {
	PID           string
	PlainPassword string
}

func (auther *Auther) Auth(ctx context.Context, req AuthRequest) (user authme.User, err error) {
	if req.PID == "" {
		return authme.User{}, fmt.Errorf("pid is required")
	}
	if req.PlainPassword == "" {
		return authme.User{}, fmt.Errorf("password is required")
	}

	err = auther.locker.Lock(ctx, makeLockKey(req.PID), func(ctx context.Context) (err error) {
		user, err = auther.userReader.FindByPID(ctx, req.PID)
		if err != nil {
			return fmt.Errorf("read user: %w", err)
		}

		rc, err := auther.retryCountRW.GetOrCreate(ctx, user)
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

		_, err = auther.retryCountRW.Update(ctx, rc)
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

type SessionAuther struct {
	auther         Auther
	sessionRW      SessionReadWriter
	guideGenerator authme.GUIDGenerator
}

type NewSessionAutherArg struct {
	Auther        Auther
	SessionRW     SessionReadWriter
	GUIDGenerator authme.GUIDGenerator
}

func NewSessionAuther(arg NewSessionAutherArg) SessionAuther {
	return SessionAuther{
		auther:         arg.Auther,
		sessionRW:      arg.SessionRW,
		guideGenerator: arg.GUIDGenerator,
	}
}

type SessionAuthResponse struct {
	Token  string `json:"token"`
	MaxAge int    `json:"max_age"`
}

func (sessionAuther SessionAuther) Auth(ctx context.Context, req AuthRequest) (SessionAuthResponse, error) {
	user, err := sessionAuther.auther.Auth(ctx, req)
	if err != nil {
		return SessionAuthResponse{}, fmt.Errorf("auth: %w", err)
	}

	now := time.Now()

	newGUID := sessionAuther.guideGenerator.Generate()
	session, err := CreateSession(user, now, newGUID)
	if err != nil {
		return SessionAuthResponse{}, fmt.Errorf("create session: %w", err)
	}

	session, err = sessionAuther.sessionRW.Create(ctx, session)
	if err != nil {
		return SessionAuthResponse{}, fmt.Errorf("create session: %w", err)
	}

	return SessionAuthResponse{
		Token:  session.Token,
		MaxAge: session.MaxAge(now),
	}, nil
}

func makeLockKey(pid string) string {
	return fmt.Sprintf("auth:%s", pid)
}
