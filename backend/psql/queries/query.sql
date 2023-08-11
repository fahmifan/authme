-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: FindUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: InsertUser :one
INSERT INTO users (id, email, "name", "status",  password_hash, verify_token, created_at, updated_at)
VALUES (@id, @email, @name, @status, @password_hash, @verify_token, @created_at, @updated_at)
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET 
    email = @email,
    "name" = @name,
    "status" = @status,
    password_hash = @password_hash,
    updated_at = NOW()
WHERE id = @id RETURNING *;

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

-- name: FindUserRetryCountByUserID :one
SELECT * FROM user_retry_counts WHERE user_id = $1 LIMIT 1;

-- name: InsertUserRetryCount :one
INSERT INTO user_retry_counts (id, user_id, retry_count, last_retry_at)
VALUES (@id, @user_id, @retry_count, @last_retry_at)
RETURNING *;

-- name: UpdateUserRetryCount :one
UPDATE user_retry_counts
SET 
    retry_count = @retry_count,
    last_retry_at = @last_retry_at
WHERE id = @id 
RETURNING *;