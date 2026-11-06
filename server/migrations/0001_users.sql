CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      TEXT NOT NULL,
    -- Never the password itself: an Argon2 hash that includes its own salt.
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive uniqueness: "Alice" and "alice" can't both exist.
CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));

-- One row per logged-in device. The client sends the token with every request.
CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
