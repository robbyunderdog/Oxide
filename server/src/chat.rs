//! Messages: history, sending, and channel access control.
//! Works identically for guild channels and DM channels.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use shared::{Message, SendMessageRequest, ServerEvent, User};
use uuid::Uuid;

use crate::{AppState, auth::AuthUser, error::AppError};

/// `#[derive(FromRow)]` maps result columns to fields *by name*, which is
/// clearer than a 6-element tuple. We then convert into the shared type.
#[derive(sqlx::FromRow)]
struct MessageRow {
    id: Uuid,
    channel_id: Uuid,
    content: String,
    created_at: DateTime<Utc>,
    author_id: Uuid,
    author_name: String,
}

impl From<MessageRow> for Message {
    fn from(r: MessageRow) -> Self {
        Message {
            id: r.id,
            channel_id: r.channel_id,
            author: User { id: r.author_id, username: r.author_name },
            content: r.content,
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
        "SELECT m.id, m.channel_id, m.content, m.created_at,
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
    let content = req.content.trim();
    if content.is_empty() {
        return Err(AppError::BadRequest("message can't be empty".into()));
    }
    if content.chars().count() > 2000 {
        return Err(AppError::BadRequest("message can be at most 2000 characters".into()));
    }
    require_access(&state.db, channel_id, user.id).await?;

    let message = Message {
        id: Uuid::new_v4(),
        channel_id,
        author: user, // `user` is *moved* into the message; we don't need it after this
        content: content.to_string(),
        created_at: Utc::now(),
    };
    sqlx::query(
        "INSERT INTO messages (id, channel_id, author_id, content, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(message.id)
    .bind(channel_id)
    .bind(message.author.id)
    .bind(&message.content)
    .bind(message.created_at)
    .execute(&state.db)
    .await?;

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
