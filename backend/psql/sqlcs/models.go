// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0

package sqlcs

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
	Email        string
	Name         string
	PasswordHash string
	VerifyToken  string
	Status       string
	LastLoginAt  sql.NullTime
	Archived     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserRetryCount struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	RetryCount  int32
	LastRetryAt sql.NullTime
	CreatedAt   time.Time
}

type UserSession struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Token          string
	TokenExpiredAt time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
