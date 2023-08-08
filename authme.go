package authme

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound = errors.New("not found")
)

type UserReader interface {
	FindByPID(ctx context.Context, pid string) (User, error)
}

type UserWriter interface {
	Create(ctx context.Context, user User) (User, error)
	Update(ctx context.Context, user User) (User, error)
}

type UserReadWriter interface {
	UserReader
	UserWriter
}

type PasswordHasher interface {
	HashPassword(plainPassword string) (string, error)
	Compare(hashedPassword, plainPassword string) error
}

type Locker interface {
	Lock(ctx context.Context, key string, fn func(ctx context.Context) error) error
}

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

type UserStatus string

const (
	UserStatusVerified   UserStatus = "verified"
	UserStatusUnverified UserStatus = "unverified"
)

type User struct {
	// GUID is global unique identifier can be UUID, Integer, etc.
	GUID string
	// PID is personal identifier can be email, username etc.
	PID          string
	Email        string
	Name         string
	PasswordHash string
	// VerifyToken is used to verify UserStatus
	VerifyToken string
	Status      UserStatus
}

type CreateUserRequest struct {
	PasswordHasher PasswordHasher
	GUID           string
	PID            string
	Email          string
	Name           string
	VerifyToken    string
	PlainPassword  string
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
	if req.Email == "" {
		return User{}, fmt.Errorf("email is empty")
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

type DefaultHasher struct {
}

func (br DefaultHasher) HashPassword(plainPassword string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate password hash: %w", err)
	}

	return string(hashed), nil
}

func (br DefaultHasher) Compare(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}
