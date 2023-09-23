package authme

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

var (
	ErrNotFound = errors.New("not found")
)

type Locker interface {
	// Lock lock key and execute fn, if key already locked, fn will wait until key unlocked.
	Lock(ctx context.Context, key string, fn func(ctx context.Context) error) error
}

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func Transaction(ctx context.Context, db *sql.DB, fn func(ctx context.Context, tx DBTX) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	if fnErr := fn(ctx, tx); fnErr != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback tx: %w", rbErr)
		}
		return fnErr
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

type UserReader interface {
	FindByPID(ctx context.Context, tx DBTX, pid string) (User, error)
}

type UserWriter interface {
	Create(ctx context.Context, tx DBTX, user User) (User, error)
	Update(ctx context.Context, tx DBTX, user User) (User, error)
}

type UserReadWriter interface {
	UserReader
	UserWriter
}

type PasswordHasher interface {
	HashPassword(plainPassword string) (string, error)
	Compare(hashedPassword, plainPassword string) error
}

type MailerSendArg struct {
	Subject string
	From    string
	To      string
	Body    string
}

type Mailer interface {
	Send(ctx context.Context, arg MailerSendArg) (err error)
}

type GUIDGenerator interface {
	Generate() string
}

type UserStatus string

const (
	UserStatusVerified   UserStatus = "verified"
	UserStatusUnverified UserStatus = "unverified"
)

type User struct {
	// GUID is global unique identifier can be UUID, Integer, etc.
	GUID string `json:"guid"`
	// PID is personal identifier can be email, username etc.
	PID          string `json:"pid"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
	// VerifyToken to verify UserStatus
	VerifyToken string     `json:"verify_token"`
	Status      UserStatus `json:"status"`
}

type CreateUserRequest struct {
	PasswordHasher  PasswordHasher
	GUID            string
	PID             string
	Email           string
	Name            string
	VerifyToken     string
	PlainPassword   string
	ConfirmPassword string
}

func CreateUser(req CreateUserRequest) (User, error) {
	if req.VerifyToken == "" {
		return User{}, fmt.Errorf("verify token is empty")
	}
	if req.GUID == "" {
		return User{}, fmt.Errorf("guid is empty")
	}
	if req.PID == "" {
		return User{}, fmt.Errorf("pid is empty")
	}
	if len(strings.TrimSpace(req.PlainPassword)) < 8 {
		return User{}, fmt.Errorf("password is too short")
	}
	if !strings.EqualFold(req.PlainPassword, req.ConfirmPassword) {
		return User{}, fmt.Errorf("password and confirm password mismatch")
	}

	_, err := mail.ParseAddress(req.Email)
	if err != nil {
		return User{}, fmt.Errorf("invalid email address: %w", err)
	}

	hashedPassword, err := req.PasswordHasher.HashPassword(req.PlainPassword)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	return User{
		GUID:         req.GUID,
		PID:          req.PID,
		Email:        req.Email,
		Name:         req.Name,
		PasswordHash: hashedPassword,
		Status:       UserStatusUnverified,
		VerifyToken:  req.VerifyToken,
	}, nil
}

func (user User) VerifyStatus(verifyToken string) (User, error) {
	if user.Status == UserStatusVerified {
		return user, fmt.Errorf("user already verified")
	}

	if user.VerifyToken != verifyToken {
		return user, fmt.Errorf("verify token mismatch")
	}

	user.Status = UserStatusVerified
	return user, nil
}

// DefaultPasswordHasher default implementation of PasswordHasher using bcrypt.
type DefaultPasswordHasher struct {
}

func (br DefaultPasswordHasher) HashPassword(plainPassword string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate password hash: %w", err)
	}

	return string(hashed), nil
}

func (br DefaultPasswordHasher) Compare(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

// DefaultLocker locker default implementation using Go singleflight
type DefaultLocker struct {
	fligthGroup *singleflight.Group
}

func NewDefaultLocker() *DefaultLocker {
	return &DefaultLocker{fligthGroup: &singleflight.Group{}}
}

func (l *DefaultLocker) Lock(ctx context.Context, key string, fn func(ctx context.Context) error) error {
	const ttl = 10 * time.Second
	timer := time.AfterFunc(ttl, func() { l.fligthGroup.Forget(key) })
	defer timer.Stop()

	_, err, _ := l.fligthGroup.Do(key, func() (any, error) {
		return nil, fn(ctx)
	})
	l.fligthGroup.Forget(key)

	return err
}
