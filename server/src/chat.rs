//! Messages: history, sending, and channel access control.
//! Works identically for guild channels and DM channels, except that DM
//! messages must arrive end-to-end encrypted.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use shared::{Message, MessageBody, SendMessageRequest, ServerEvent, User};
use uuid::Uuid;

use crate::{AppState, auth::AuthUser, error::AppError};

/// Longest plaintext message, in characters.
const MAX_CHARS: usize = 2000;
/// XChaCha20-Poly1305 nonce size.
const NONCE_LEN: usize = 24;
/// Upper bound for ciphertext: 2000 chars * up to 4 bytes (UTF-8) + 16-byte tag.
const MAX_CIPHERTEXT: usize = MAX_CHARS * 4 + 16;

/// `#[derive(FromRow)]` maps result columns to fields *by name*.
#[derive(sqlx::FromRow)]
struct MessageRow {
    id: Uuid,
    channel_id: Uuid,
    content: Option<String>,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    author_id: Uuid,
    author_name: String,
}

impl From<MessageRow> for Message {
    fn from(r: MessageRow) -> Self {
        // The database CHECK constraint guarantees exactly one of these shapes.
        let body = match (r.content, r.nonce, r.ciphertext) {
            (Some(content), _, _) => MessageBody::Plain { content },
            (None, nonce, ciphertext) => MessageBody::Encrypted {
                nonce: nonce.unwrap_or_default(),
                ciphertext: ciphertext.unwrap_or_default(),
            },
        };
        Message {
            id: r.id,
            channel_id: r.channel_id,
            author: User { id: r.author_id, username: r.author_name },
            body,
            created_at: r.created_at,
        }
    }
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Optional `?before=<RFC3339 timestamp>` for paging back through history.
    before: Option<DateTime<Utc>>,
}

/// `GET /channels/{id}/messages`: latest 50 (oldest first), or 50 before a time.
pub async fn history(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(channel_id): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<Message>>, AppError> {
    require_access(&state.db, channel_id, user.id).await?;

    let mut rows: Vec<MessageRow> = sqlx::query_as(
        "SELECT m.id, m.channel_id, m.content, m.nonce, m.ciphertext, m.created_at,
                u.id AS author_id, u.username AS author_name
         FROM messages m JOIN users u ON u.id = m.author_id
         WHERE m.channel_id = $1 AND ($2::timestamptz IS NULL OR m.created_at < $2)
         ORDER BY m.created_at DESC
         LIMIT 50",
    )
    .bind(channel_id)
    .bind(q.before)
    .fetch_all(&state.db)
    .await?;

    rows.reverse(); // we fetched newest-first to get the *latest* 50; display oldest-first
    Ok(Json(rows.into_iter().map(Message::from).collect()))
}

/// `POST /channels/{id}/messages`: store the message, then push it live to
/// everyone who can see the channel.
pub async fn send(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<Message>, AppError> {
    require_access(&state.db, channel_id, user.id).await?;

    let is_dm: bool = sqlx::query_scalar("SELECT guild_id IS NULL FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_one(&state.db)
        .await?;

    // Matching on (body kind, channel kind) makes every combination explicit,
    // and the compiler checks we've covered all four.
    let body = match (req.body, is_dm) {
        (MessageBody::Plain { content }, false) => {
            let content = content.trim().to_string();
            if content.is_empty() {
                return Err(AppError::BadRequest("message can't be empty".into()));
            }
            if content.chars().count() > MAX_CHARS {
                return Err(AppError::BadRequest(format!("message can be at most {MAX_CHARS} characters")));
            }
            MessageBody::Plain { content }
        }
        (MessageBody::Encrypted { nonce, ciphertext }, true) => {
            // We can't read it; we can only check its shape and size.
            if nonce.len() != NONCE_LEN || ciphertext.len() <= 16 || ciphertext.len() > MAX_CIPHERTEXT {
                return Err(AppError::BadRequest("malformed encrypted message".into()));
            }
            MessageBody::Encrypted { nonce, ciphertext }
        }
        (MessageBody::Plain { .. }, true) => {
            return Err(AppError::BadRequest("direct messages must be end-to-end encrypted".into()));
        }
        (MessageBody::Encrypted { .. }, false) => {
            return Err(AppError::BadRequest("server channels don't support encryption yet".into()));
        }
    };

    let (content, nonce, ciphertext) = match &body {
        MessageBody::Plain { content } => (Some(content.as_str()), None, None),
        MessageBody::Encrypted { nonce, ciphertext } => (None, Some(nonce.as_slice()), Some(ciphertext.as_slice())),
    };

    let message = Message { id: req.id, channel_id, author: user, body: body.clone(), created_at: Utc::now() };
    let result = sqlx::query(
        "INSERT INTO messages (id, channel_id, author_id, content, nonce, ciphertext, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(message.id)
    .bind(channel_id)
    .bind(message.author.id)
    .bind(content)
    .bind(nonce)
    .bind(ciphertext)
    .bind(message.created_at)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {}
        // The client picks message ids; reusing one is rejected.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict("duplicate message id".into()));
        }
        Err(e) => return Err(e.into()),
    }

    let recipients = channel_members(&state.db, channel_id).await?;
    state.hub.send_to(&recipients, &ServerEvent::MessageCreated { message: message.clone() });

    Ok(Json(message))
}

/// Everyone allowed to see a channel: guild members for guild channels,
/// the two participants for DM channels.
pub async fn channel_members(db: &sqlx::PgPool, channel_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT gm.user_id FROM channels c JOIN guild_members gm ON gm.guild_id = c.guild_id WHERE c.id = $1
         UNION
         SELECT user_id FROM dm_members WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_all(db)
    .await
}

/// The single permission check every channel endpoint goes through.
pub async fn require_access(db: &sqlx::PgPool, channel_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM channels c JOIN guild_members gm ON gm.guild_id = c.guild_id
            WHERE c.id = $1 AND gm.user_id = $2
            UNION ALL
            SELECT 1 FROM dm_members WHERE channel_id = $1 AND user_id = $2
         )",
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_one(db)
    .await?;
    if allowed { Ok(()) } else { Err(AppError::Forbidden("you don't have access to this channel")) }
}
