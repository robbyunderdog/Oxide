-- Security hardening.
--
-- Pre-release reset (again): the client now derives keys with much stronger
-- Argon2 settings and pads encrypted messages, so existing accounts can't log
-- in and existing DMs can't be decrypted. Wipe them, as in 0003.
DELETE FROM messages;
DELETE FROM channels;
DELETE FROM guilds;
DELETE FROM users;

-- Sessions now store SHA-256(token) instead of the token itself, so reading
-- this table doesn't let anyone log in as anyone. They also expire.
DROP TABLE sessions;
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
