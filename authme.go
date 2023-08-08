package authme

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	// GUID is global unique identifier can be UUID, Integer, etc.
	GUID string
	// PID is personal identifier can be email, username etc.
	PID          string
	PasswordHash string
}

var (
	ErrNotFound = errors.New("not found")
)

type UserReader interface {
	FindByPID(ctx context.Context, pid string) (User, error)
}

type UserWriter interface {
	Create(ctx context.Context, user User) error
}

type UserReadWriter interface {
	UserReader
	UserWriter
}

type PasswordHasher interface {
	HashPassword(plainPassword string) (string, error)
	Compare(hashedPassword, plainPassword string) error
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
