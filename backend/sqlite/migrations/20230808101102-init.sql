
-- +migrate Up
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  "name" TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  verify_token TEXT NOT NULL,
  "status" TEXT NOT NULL,
  last_login_at TIMESTAMP,
  archived boolean NOT NULL DEFAULT false,

  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users (email);

CREATE TABLE IF NOT EXISTS user_retry_counts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id),
  retry_count INTEGER NOT NULL DEFAULT 0,
  last_retry_at TIMESTAMP,

  created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users (id),
  token TEXT NOT NULL, 
  token_expired_at TIMESTAMP NOT NULL,

  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS user_tokens_refresh_token_idx ON user_sessions (token);

-- +migrate Down
DROP INDEX IF EXISTS user_tokens_refresh_token_idx;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_retry_counts;
DROP INDEX IF EXISTS users_email_idx;
DROP TABLE IF EXISTS users;
