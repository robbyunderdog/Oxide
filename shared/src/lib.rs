//! Types shared between the client and server.
//!
//! Because both sides compile against this exact code, the compiler guarantees
//! they agree on the shape of every request and response.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------- Core data ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub username: String,
}

/// A "server" in Discord terms. Called Guild in code to avoid confusion
/// with the actual backend server program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Guild {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    /// Share this code with friends so they can join.
    pub invite_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Channel {
    pub id: Uuid,
    /// `None` means this is a DM channel rather than a guild channel.
    pub guild_id: Option<Uuid>,
    pub name: String,
}

/// A DM is just a channel with exactly two members.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DmChannel {
    pub channel: Channel,
    /// The person you're talking to (from the viewer's perspective).
    pub other_user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub author: User,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

// ---------- HTTP request/response bodies ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGuildRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinGuildRequest {
    pub invite_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenDmRequest {
    pub username: String,
}

/// Body of every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

// ---------- WebSocket events (server -> client only) ----------

/// Pushed from server to client over the WebSocket. Clients *send* things
/// via normal HTTP requests; the socket is purely for live updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")] // JSON looks like {"type":"MessageCreated", "message": {...}}
pub enum ServerEvent {
    MessageCreated { message: Message },
    ChannelCreated { channel: Channel },
    /// Someone opened a DM with you.
    DmCreated { dm: DmChannel },
}
