package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/fahmifan/authme"
	"github.com/golang-jwt/jwt/v5"
)

const SessionExpireDuration = 24 * time.Hour
const AccessTokenExpireDuration = 1 * time.Hour

var (
	ErrorSessionNotFound = errors.New("session not found")
	ErrSessionExpired    = errors.New("session expired")
)

type SessionWriter interface {
	Create(ctx context.Context, tx authme.DBTX, session Session) (Session, error)
	Update(ctx context.Context, tx authme.DBTX, session Session) (Session, error)
}

type SessionReader interface {
	FindByToken(ctx context.Context, tx authme.DBTX, token string) (Session, error)
}

type SessionReadWriter interface {
	SessionWriter
	SessionReader
}

type UserSession struct {
	// GUID is global unique identifier can be UUID, Integer, etc.
	GUID string
	// PID is personal identifier can be email, username etc.
	PID    string
	Email  string
	Name   string
	Status authme.UserStatus
}

type Session struct {
	GUID           string
	User           UserSession
	Token          string
	TokenExpiredAt time.Time
}

func CreateSession(user authme.User, now time.Time, guid string) (Session, error) {
	sess := Session{
		GUID: guid,
		User: UserSession{
			GUID:   user.GUID,
			PID:    user.PID,
			Email:  user.Email,
			Name:   user.Name,
			Status: user.Status,
		},
	}

	return sess.Refresh(now)
}

func (sess Session) CreateAccessToken(secert []byte, now time.Time) (token string, expiredAt time.Time, err error) {
	expiredAt = now.Add(AccessTokenExpireDuration)

	jwtAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTCalim{
		UserGUID: sess.User.GUID,
		UserPID:  sess.User.PID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiredAt),
		},
	})

	accessToken, err := jwtAccessToken.SignedString(secert)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return accessToken, expiredAt, nil
}

func (sess Session) Refresh(now time.Time) (Session, error) {
	if sess.isTokenExpired() {
		return Session{}, ErrSessionExpired
	}

	expiredAt := now.Add(SessionExpireDuration)

	sess.Token = GenerateRefreshToken()
	sess.TokenExpiredAt = expiredAt

	return sess, nil
}

func (sess Session) isTokenExpired() bool {
	if sess.TokenExpiredAt.IsZero() {
		return false
	}

	return sess.TokenExpiredAt.Before(time.Now())
}

func (sess Session) MaxAge(now time.Time) int {
	return int(sess.TokenExpiredAt.Sub(now).Seconds())
}

func (sess Session) IsExpired(now time.Time) bool {
	return now.After(sess.TokenExpiredAt)
}

const refreshTokenLength = 32

func GenerateRefreshToken() string {
	b := make([]byte, refreshTokenLength)
	if _, err := rand.Read(b); err != nil {
		return ""
	}

	return base32.StdEncoding.EncodeToString(b)
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

func (sessionAuther SessionAuther) Auth(ctx context.Context, tx *sql.DB, req AuthRequest) (SessionAuthResponse, error) {
	session := Session{}
	now := time.Now()

	err := authme.Transaction(ctx, tx, func(ctx context.Context, tx authme.DBTX) error {
		user, err := sessionAuther.auther.Auth(ctx, tx, req)
		if err != nil {
			return fmt.Errorf("auth: %w", err)
		}

		newGUID := sessionAuther.guideGenerator.Generate()
		session, err = CreateSession(user, now, newGUID)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		session, err = sessionAuther.sessionRW.Create(ctx, tx, session)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		return nil
	})
	if err != nil {
		return SessionAuthResponse{}, fmt.Errorf("transaction: %w", err)
	}

	return SessionAuthResponse{
		Token:  session.Token,
		MaxAge: session.MaxAge(now),
	}, nil
}
