-- End-to-end encrypted DMs.
--
-- Pre-release reset: login now uses a client-derived auth key instead of the
-- raw password, and DMs must be ciphertext. Existing test accounts and their
-- plaintext DMs are incompatible, so wipe them.
DELETE FROM messages;
DELETE FROM channels;
DELETE FROM guilds;
DELETE FROM users;

-- Each user's X25519 public key (shared with others) and their private key
-- encrypted on the client with a key the server never sees.
ALTER TABLE users
    ADD COLUMN public_key BYTEA NOT NULL,
    ADD COLUMN encrypted_private_key BYTEA NOT NULL;

-- A message is either plaintext (guild channels, for now) or ciphertext
-- (DMs). The CHECK makes the database itself refuse a half-filled row.
ALTER TABLE messages
    ALTER COLUMN content DROP NOT NULL,
    ADD COLUMN nonce BYTEA,
    ADD COLUMN ciphertext BYTEA,
    ADD CONSTRAINT messages_body_is_plain_xor_encrypted CHECK (
        (content IS NOT NULL AND nonce IS NULL AND ciphertext IS NULL)
        OR (content IS NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL)
    );
