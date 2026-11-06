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
    /// Their X25519 public key: what you need to encrypt messages to them.
    #[serde(with = "b64")]
    pub other_public_key: Vec<u8>,
}

/// What a message contains. Guild channels are still plaintext for now;
/// DMs are always `Encrypted` (the server rejects anything else).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum MessageBody {
    Plain {
        content: String,
    },
    /// XChaCha20-Poly1305 output. The server stores and forwards these bytes
    /// but has no key to decrypt them.
    Encrypted {
        #[serde(with = "b64")]
        nonce: Vec<u8>,
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub author: User,
    pub body: MessageBody,
    pub created_at: DateTime<Utc>,
}

// ---------- HTTP request/response bodies ----------

/// The client never sends the password itself. It sends `auth_key`, which is
/// derived from the password but can't be used to recover the encryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub auth_key: String,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    /// The user's private key, encrypted on the client with a key the server
    /// never sees. Stored so you can log in from another computer.
    #[serde(with = "b64")]
    pub encrypted_private_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
    #[serde(with = "b64")]
    pub encrypted_private_key: Vec<u8>,
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
    /// Chosen by the client, because it's baked into the encryption (see the
    /// client's crypto.rs) so the server can't replay or relabel messages.
    pub id: Uuid,
    pub body: MessageBody,
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

/// `#[serde(with = "b64")]` support: bytes <-> base64 strings in JSON
/// (otherwise serde would write `[12, 255, 3, ...]`, about 4x larger).
mod b64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}
