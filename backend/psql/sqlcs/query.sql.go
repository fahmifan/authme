// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0
// source: query.sql

package sqlcs

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const findSessionByToken = `-- name: FindSessionByToken :one
SELECT id, user_id, token, token_expired_at, created_at, updated_at FROM user_sessions WHERE token = $1
`

func (q *Queries) FindSessionByToken(ctx context.Context, token string) (UserSession, error) {
	row := q.db.QueryRowContext(ctx, findSessionByToken, token)
	var i UserSession
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.TokenExpiredAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findUserByEmail = `-- name: FindUserByEmail :one
SELECT id, email, name, password_hash, verify_token, status, last_login_at, archived, created_at, updated_at FROM users WHERE email = $1
`

func (q *Queries) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Name,
		&i.PasswordHash,
		&i.VerifyToken,
		&i.Status,
		&i.LastLoginAt,
		&i.Archived,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findUserByID = `-- name: FindUserByID :one
SELECT id, email, name, password_hash, verify_token, status, last_login_at, archived, created_at, updated_at FROM users WHERE id = $1
`

func (q *Queries) FindUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserByID, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Name,
		&i.PasswordHash,
		&i.VerifyToken,
		&i.Status,
		&i.LastLoginAt,
		&i.Archived,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const insertSession = `-- name: InsertSession :one
INSERT INTO user_sessions (id, user_id, token, token_expired_at)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, token, token_expired_at, created_at, updated_at
`

type InsertSessionParams struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Token          string
	TokenExpiredAt time.Time
}

func (q *Queries) InsertSession(ctx context.Context, arg InsertSessionParams) (UserSession, error) {
	row := q.db.QueryRowContext(ctx, insertSession,
		arg.ID,
		arg.UserID,
		arg.Token,
		arg.TokenExpiredAt,
	)
	var i UserSession
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.TokenExpiredAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const insertUser = `-- name: InsertUser :one
INSERT INTO users (id, email, "name", "status",  password_hash, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, email, name, password_hash, verify_token, status, last_login_at, archived, created_at, updated_at
`

type InsertUserParams struct {
	ID           uuid.UUID
	Email        string
	Name         string
	Status       string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (q *Queries) InsertUser(ctx context.Context, arg InsertUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, insertUser,
		arg.ID,
		arg.Email,
		arg.Name,
		arg.Status,
		arg.PasswordHash,
		arg.CreatedAt,
		arg.UpdatedAt,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Name,
		&i.PasswordHash,
		&i.VerifyToken,
		&i.Status,
		&i.LastLoginAt,
		&i.Archived,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateSession = `-- name: UpdateSession :one
UPDATE user_sessions 
SET 
    token = $1, 
    token_expired_at = $2,
    updated_at = NOW()
WHERE id = $3 RETURNING id, user_id, token, token_expired_at, created_at, updated_at
`

type UpdateSessionParams struct {
	Token          string
	TokenExpiredAt time.Time
	ID             uuid.UUID
}

func (q *Queries) UpdateSession(ctx context.Context, arg UpdateSessionParams) (UserSession, error) {
	row := q.db.QueryRowContext(ctx, updateSession, arg.Token, arg.TokenExpiredAt, arg.ID)
	var i UserSession
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.TokenExpiredAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET 
    email = $1,
    "name" = $2,
    "status" = $3,
    password_hash = $4,
    updated_at = NOW()
WHERE id = $5 RETURNING id, email, name, password_hash, verify_token, status, last_login_at, archived, created_at, updated_at
`

type UpdateUserParams struct {
	Email        string
	Name         string
	Status       string
	PasswordHash string
	ID           uuid.UUID
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser,
		arg.Email,
		arg.Name,
		arg.Status,
		arg.PasswordHash,
		arg.ID,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.Name,
		&i.PasswordHash,
		&i.VerifyToken,
		&i.Status,
		&i.LastLoginAt,
		&i.Archived,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
