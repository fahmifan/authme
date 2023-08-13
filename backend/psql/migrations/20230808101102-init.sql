
-- +migrate Up
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  "name" VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  verify_token TEXT NOT NULL,
  "status" VARCHAR(64) NOT NULL,
  last_login_at TIMESTAMP,
  archived boolean NOT NULL DEFAULT false,

  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users (email);

CREATE TABLE IF NOT EXISTS user_retry_counts (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  retry_count INTEGER NOT NULL DEFAULT 0,
  last_retry_at TIMESTAMP DEFAULT NOW(),

  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  token TEXT NOT NULL, 
  token_expired_at TIMESTAMP NOT NULL,

  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS user_tokens_refresh_token_idx ON user_sessions (token);

-- +migrate Down
DROP INDEX IF EXISTS user_tokens_refresh_token_idx;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_retry_counts;
DROP INDEX IF EXISTS users_email_idx;
DROP TABLE IF EXISTS users;
