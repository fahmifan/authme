package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
	"github.com/golang-jwt/jwt/v5"
)

const sessionExpireDuration = 24 * time.Hour
const accessTokenExpireDuration = 1 * time.Hour

var (
	ErrorSessionNotFound = fmt.Errorf("session not found")
)

type SessionWriter interface {
	Create(ctx context.Context, session Session) (Session, error)
	Update(ctx context.Context, session Session) (Session, error)
}

type SessionReader interface {
	FindByToken(ctx context.Context, token string) (Session, error)
}

type SessionReadWriter interface {
	SessionWriter
	SessionReader
}

type Session struct {
	secret []byte

	User           authme.User
	Token          string
	TokenExpiredAt time.Time
}

func CreateSession(secret []byte, user authme.User, now time.Time) (Session, error) {
	sess := Session{
		User: user,
	}

	return sess.Refresh(now)
}

type JWTCalim struct {
	UserGUID string `json:"user_guid"`
	UserPID  string `json:"user_pid"`
	jwt.RegisteredClaims
}

func (sess Session) CreateAccessToken(now time.Time) (token string, expiredAt time.Time, err error) {
	expiredAt = now.Add(accessTokenExpireDuration)

	jwtAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTCalim{
		UserGUID: sess.User.GUID,
		UserPID:  sess.User.PID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiredAt),
		},
	})

	accessToken, err := jwtAccessToken.SignedString(sess.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return accessToken, expiredAt, nil
}

func (sess Session) Refresh(now time.Time) (Session, error) {
	expiredAt := now.Add(sessionExpireDuration)

	sess.Token = GenerateRefreshToken()
	sess.TokenExpiredAt = expiredAt

	return sess, nil
}

const refreshTokenLength = 32

func GenerateRefreshToken() string {
	b := make([]byte, refreshTokenLength)
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return base32.StdEncoding.EncodeToString(b)
}
