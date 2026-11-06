CREATE TABLE guilds (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invite_code TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Many-to-many: a user is in many guilds, a guild has many users.
CREATE TABLE guild_members (
    guild_id  UUID NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE channels (
    id         UUID PRIMARY KEY,
    -- NULL for DM channels.
    guild_id   UUID REFERENCES guilds(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    -- For DMs only: "<smaller user id>:<larger user id>". The UNIQUE
    -- constraint guarantees at most one DM channel per pair of users.
    dm_key     TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE dm_members (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE messages (
    id         UUID PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    author_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "Latest 50 messages in channel X" is our hottest query; this index makes
-- it fast no matter how many messages exist overall.
CREATE INDEX messages_channel_created_idx ON messages (channel_id, created_at DESC);
