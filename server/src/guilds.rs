//! Guilds ("servers"): create, join via invite code, list, and their channels.

use axum::{
    Json,
    extract::{Path, State},
};
use shared::{
    Channel, CreateChannelRequest, CreateGuildRequest, Guild, JoinGuildRequest, ServerEvent,
};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{AuthUser, random_hex},
    chat::channel_members,
    error::AppError,
};

/// The columns we SELECT for a guild, decoded positionally into a tuple.
type GuildRow = (Uuid, String, Uuid, String);

fn to_guild((id, name, owner_id, invite_code): GuildRow) -> Guild {
    Guild { id, name, owner_id, invite_code }
}

/// `GET /guilds`: every guild the caller is a member of.
pub async fn list(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Vec<Guild>>, AppError> {
    let rows: Vec<GuildRow> = sqlx::query_as(
        "SELECT g.id, g.name, g.owner_id, g.invite_code
         FROM guilds g JOIN guild_members m ON m.guild_id = g.id
         WHERE m.user_id = $1
         ORDER BY m.joined_at",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(to_guild).collect()))
}

/// `POST /guilds`: create a guild; the creator becomes owner and first member,
/// and it starts with a #general channel.
pub async fn create(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<CreateGuildRequest>,
) -> Result<Json<Guild>, AppError> {
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::BadRequest("server name must be 1-100 characters".into()));
    }

    let guild = Guild {
        id: Uuid::new_v4(),
        name: name.to_string(),
        owner_id: user.id,
        invite_code: random_hex(5),
    };

    // A transaction: all three inserts succeed together or none do, so we can
    // never end up with a guild that has no owner membership or no channel.
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO guilds (id, name, owner_id, invite_code) VALUES ($1, $2, $3, $4)")
        .bind(guild.id)
        .bind(&guild.name)
        .bind(guild.owner_id)
        .bind(&guild.invite_code)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO guild_members (guild_id, user_id) VALUES ($1, $2)")
        .bind(guild.id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO channels (id, guild_id, name) VALUES ($1, $2, 'general')")
        .bind(Uuid::new_v4())
        .bind(guild.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(guild))
}

/// `POST /guilds/join`: join a guild using its invite code.
pub async fn join(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(req): Json<JoinGuildRequest>,
) -> Result<Json<Guild>, AppError> {
    let row: Option<GuildRow> =
        sqlx::query_as("SELECT id, name, owner_id, invite_code FROM guilds WHERE invite_code = $1")
            .bind(req.invite_code.trim().to_lowercase())
            .fetch_optional(&state.db)
            .await?;
    let guild = row.map(to_guild).ok_or(AppError::NotFound("no server with that invite code"))?;

    // ON CONFLICT DO NOTHING: joining a guild you're already in is harmless.
    sqlx::query("INSERT INTO guild_members (guild_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(guild.id)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    Ok(Json(guild))
}

/// `GET /guilds/{id}/channels`
pub async fn channels(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(guild_id): Path<Uuid>,
) -> Result<Json<Vec<Channel>>, AppError> {
    require_member(&state.db, guild_id, user.id).await?;
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, name FROM channels WHERE guild_id = $1 ORDER BY created_at")
            .bind(guild_id)
            .fetch_all(&state.db)
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name)| Channel { id, guild_id: Some(guild_id), name })
            .collect(),
    ))
}

/// `POST /guilds/{id}/channels`: owner only.
pub async fn create_channel(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(guild_id): Path<Uuid>,
    Json(req): Json<CreateChannelRequest>,
) -> Result<Json<Channel>, AppError> {
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM guilds WHERE id = $1")
        .bind(guild_id)
        .fetch_optional(&state.db)
        .await?;
    match owner {
        None => return Err(AppError::NotFound("server not found")),
        Some(owner_id) if owner_id != user.id => {
            return Err(AppError::Forbidden("only the server owner can create channels"));
        }
        Some(_) => {}
    }

    // Discord-style channel names: lowercase, spaces become dashes.
    let name: String = req
        .name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::BadRequest("channel name must be 1-100 letters, digits, - or _".into()));
    }

    let channel = Channel { id: Uuid::new_v4(), guild_id: Some(guild_id), name };
    sqlx::query("INSERT INTO channels (id, guild_id, name) VALUES ($1, $2, $3)")
        .bind(channel.id)
        .bind(guild_id)
        .bind(&channel.name)
        .execute(&state.db)
        .await?;

    // Tell every member's open clients so the channel appears live.
    let members = channel_members(&state.db, channel.id).await?;
    state.hub.send_to(&members, &ServerEvent::ChannelCreated { channel: channel.clone() });

    Ok(Json(channel))
}

async fn require_member(db: &sqlx::PgPool, guild_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM guild_members WHERE guild_id = $1 AND user_id = $2)",
    )
    .bind(guild_id)
    .bind(user_id)
    .fetch_one(db)
    .await?;
    if is_member { Ok(()) } else { Err(AppError::Forbidden("you are not a member of this server")) }
}
