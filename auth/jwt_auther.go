package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
	"github.com/golang-jwt/jwt/v5"
)

type JWTCalim struct {
	UserGUID string `json:"user_guid"`
	UserPID  string `json:"user_pid"`
	jwt.RegisteredClaims
}

type JWTAuther struct {
	auther        Auther
	secret        []byte
	sessionRW     SessionReadWriter
	guidGenerator authme.GUIDGenerator
}

type NewJWTAutherArg struct {
	Auther        Auther
	Secret        []byte
	SessionRW     SessionReadWriter
	GUIDGenerator authme.GUIDGenerator
}

func NewJWTAuther(arg NewJWTAutherArg) JWTAuther {
	return JWTAuther{
		auther:        arg.Auther,
		secret:        arg.Secret,
		sessionRW:     arg.SessionRW,
		guidGenerator: arg.GUIDGenerator,
	}
}

type JWTAuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiredAt    int64  `json:"expired_at"`
}

func (auther JWTAuther) Auth(ctx context.Context, tx *sql.DB, req AuthRequest) (JWTAuthResponse, error) {
	res := JWTAuthResponse{}

	err := authme.Transaction(ctx, tx, func(ctx context.Context, tx authme.DBTX) error {
		user, err := auther.auther.Auth(ctx, tx, req)
		if err != nil {
			return fmt.Errorf("JWTAuther: auther.Auth: %w", err)
		}

		now := time.Now()
		guid := auther.guidGenerator.Generate()

		session, err := CreateSession(user, now, guid)
		if err != nil {
			return fmt.Errorf("JWTAuther: CreateSession: %w", err)
		}

		accessToken, expiredAt, err := session.CreateAccessToken(auther.secret, now)
		if err != nil {
			return fmt.Errorf("JWTAuther: CreateAccessToken: %w", err)
		}

		session, err = auther.sessionRW.Create(ctx, tx, session)
		if err != nil {
			return fmt.Errorf("JWTAuther: sessionRW.Create: %w", err)
		}

		res = JWTAuthResponse{
			AccessToken:  accessToken,
			RefreshToken: session.Token,
			ExpiredAt:    expiredAt.Truncate(time.Second).Unix(),
		}

		return nil
	})
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("JWTAuther: transaction: %w", err)
	}

	return res, nil
}

func (auther JWTAuther) RefreshToken(ctx context.Context, tx *sql.DB, refreshToken string) (JWTAuthResponse, error) {
	res := JWTAuthResponse{}

	err := authme.Transaction(ctx, tx, func(ctx context.Context, tx authme.DBTX) error {
		session, err := auther.sessionRW.FindByToken(ctx, tx, refreshToken)
		if err != nil {
			return fmt.Errorf("JWTAuther: find session: %w", err)
		}

		now := time.Now()

		accessToken, expiredAt, err := session.CreateAccessToken(auther.secret, now)
		if err != nil {
			return fmt.Errorf("JWTAuther: create access token: %w", err)
		}

		session, err = session.Refresh(now)
		if err != nil {
			return fmt.Errorf("JWTAuther: refresh session: %w", err)
		}

		session, err = auther.sessionRW.Update(ctx, tx, session)
		if err != nil {
			return fmt.Errorf("JWTAuther: create session: %w", err)
		}

		res = JWTAuthResponse{
			AccessToken:  accessToken,
			RefreshToken: session.Token,
			ExpiredAt:    expiredAt.Truncate(time.Second).Unix(),
		}

		return nil
	})
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("JWTAuther: transaction: %w", err)
	}

	return res, nil
}
