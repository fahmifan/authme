-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: FindUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: InsertUser :one
INSERT INTO users (id, email, password_hash, created_at, updated_at)
VALUES (@id, @email, @password_hash, @created_at, @updated_at)
RETURNING *;

-- name: FindSessionByToken :one
SELECT * FROM user_sessions WHERE token = $1;

-- name: InsertSession :one
INSERT INTO user_sessions (id, user_id, token, token_expired_at)
VALUES (@id, @user_id, @token, @token_expired_at)
RETURNING *;

-- name: UpdateSession :one
UPDATE user_sessions 
SET 
    token = @token, 
    token_expired_at = @token_expired_at,
    updated_at = NOW()
WHERE id = @id RETURNING *;