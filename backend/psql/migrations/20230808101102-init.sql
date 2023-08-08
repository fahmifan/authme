
-- +migrate Up
CREATE TABLE users (
  id uuid PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  last_login_at TIMESTAMP,
  archived boolean NOT NULL DEFAULT false,

  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX users_email_idx ON users (email);

CREATE TABLE user_login_retry_counts (
  user_id uuid PRIMARY KEY,
  retry_count INTEGER NOT NULL DEFAULT 0,
  last_retry_at TIMESTAMP NOT NULL DEFAULT NOW(),

  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE user_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id),
  token TEXT NOT NULL, 
  token_expired_at TIMESTAMP NOT NULL,

  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX user_tokens_refresh_token_idx ON user_tokens (refresh_token);

-- +migrate Down
