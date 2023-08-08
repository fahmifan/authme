package auth

import (
	"context"
	"fmt"
	"time"
)

type JWTAuther struct {
	auther    *Auther
	secret    []byte
	sessionRW SessionReadWriter
}

func NewJWTAuther(auther *Auther) JWTAuther {
	return JWTAuther{auther: auther}
}

type JWTAuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiredAt    int64  `json:"expired_at"`
}

func (auther JWTAuther) Auth(ctx context.Context, req AuthRequest) (JWTAuthResponse, error) {
	user, err := auther.auther.Auth(ctx, req)
	if err != nil {
		return JWTAuthResponse{}, err
	}

	now := time.Now()

	session, err := CreateSession(auther.secret, user, now)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("create session: %w", err)
	}

	accessToken, expiredAt, err := session.CreateAccessToken(now)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("create access token: %w", err)
	}

	session, err = auther.sessionRW.Create(ctx, session)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("create session: %w", err)
	}

	res := JWTAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: session.Token,
		ExpiredAt:    expiredAt.Truncate(time.Second).Unix(),
	}

	return res, nil
}

func (auther JWTAuther) RefreshToken(ctx context.Context, refreshToken string) (JWTAuthResponse, error) {
	session, err := auther.sessionRW.FindByToken(ctx, refreshToken)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("find session: %w", err)
	}

	now := time.Now()

	accessToken, expiredAt, err := session.CreateAccessToken(now)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("create access token: %w", err)
	}

	session, err = session.Refresh(now)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("refresh session: %w", err)
	}

	session, err = auther.sessionRW.Update(ctx, session)
	if err != nil {
		return JWTAuthResponse{}, fmt.Errorf("create session: %w", err)
	}

	res := JWTAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: session.Token,
		ExpiredAt:    expiredAt.Truncate(time.Second).Unix(),
	}

	return res, nil
}
