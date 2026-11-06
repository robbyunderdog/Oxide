//! Direct messages. A DM is a channel with no guild and exactly two members,
//! so sending/reading messages reuses chat.rs unchanged.

use axum::{Json, extract::State};
use shared::{Channel, DmChannel, OpenDmRequest, ServerEvent, User};
use uuid::Uuid;

use crate::{AppState, auth::AuthUser, error::AppError};

/// `GET /dms`: the caller's DM conversations.
pub async fn list(
    State(state): State<AppState>,
    AuthUser(me): AuthUser,
) -> Result<Json<Vec<DmChannel>>, AppError> {
    // Join dm_members twice: once for "me", once for "the other person".
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT c.id, u.id, u.username
         FROM dm_members mine
         JOIN channels c ON c.id = mine.channel_id
         JOIN dm_members theirs ON theirs.channel_id = c.id AND theirs.user_id <> mine.user_id
         JOIN users u ON u.id = theirs.user_id
         WHERE mine.user_id = $1
         ORDER BY u.username",
    )
    .bind(me.id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(|(cid, uid, uname)| dm_view(cid, User { id: uid, username: uname })).collect()))
}

/// `POST /dms`: open (or re-open) a DM with a user by username.
pub async fn open(
    State(state): State<AppState>,
    AuthUser(me): AuthUser,
    Json(req): Json<OpenDmRequest>,
) -> Result<Json<DmChannel>, AppError> {
    let other: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, username FROM users WHERE lower(username) = lower($1)")
            .bind(req.username.trim())
            .fetch_optional(&state.db)
            .await?;
    let (other_id, other_name) = other.ok_or(AppError::NotFound("no user with that username"))?;
    if other_id == me.id {
        return Err(AppError::BadRequest("you can't DM yourself".into()));
    }

    // Order-independent key: alice->bob and bob->alice produce the same key.
    let (a, b) = if me.id < other_id { (me.id, other_id) } else { (other_id, me.id) };
    let dm_key = format!("{a}:{b}");

    let mut tx = state.db.begin().await?;
    // Try to create; if a DM for this pair already exists, the UNIQUE
    // constraint makes this a no-op and RETURNING yields no row.
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO channels (id, guild_id, name, dm_key) VALUES ($1, NULL, 'dm', $2)
         ON CONFLICT (dm_key) DO NOTHING RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&dm_key)
    .fetch_optional(&mut *tx)
    .await?;

    let channel_id = match created {
        Some(id) => {
            sqlx::query("INSERT INTO dm_members (channel_id, user_id) VALUES ($1, $2), ($1, $3)")
                .bind(id)
                .bind(me.id)
                .bind(other_id)
                .execute(&mut *tx)
                .await?;
            id
        }
        None => {
            sqlx::query_scalar("SELECT id FROM channels WHERE dm_key = $1")
                .bind(&dm_key)
                .fetch_one(&mut *tx)
                .await?
        }
    };
    tx.commit().await?;

    // If it's brand new, make it pop up in the other person's DM list live.
    if created.is_some() {
        state.hub.send_to(&[other_id], &ServerEvent::DmCreated { dm: dm_view(channel_id, me.clone()) });
    }

    Ok(Json(dm_view(channel_id, User { id: other_id, username: other_name })))
}

/// Builds the viewer-specific DM representation. The channel's display name
/// is the other person's username.
fn dm_view(channel_id: Uuid, other_user: User) -> DmChannel {
    DmChannel {
        channel: Channel { id: channel_id, guild_id: None, name: other_user.username.clone() },
        other_user,
    }
}
