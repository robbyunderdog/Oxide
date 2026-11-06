//! Accounts: registration, login, and identifying the caller from a token.

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString,
};
use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::{header::AUTHORIZATION, request::Parts},
};
use rand_core::{OsRng, RngCore};
use shared::{AuthResponse, LoginRequest, RegisterRequest, User};
use uuid::Uuid;

use crate::{AppState, error::AppError};

// ---------- Handlers ----------

/// X25519 public keys are always 32 bytes.
const PUBLIC_KEY_LEN: usize = 32;
/// 24-byte nonce + 32-byte encrypted key + 16-byte authentication tag.
const KEY_BACKUP_LEN: usize = 24 + 32 + 16;

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    validate_username(&req.username)?;
    validate_auth_key(&req.auth_key)?;
    // We can't check the keys are *correct* (we can't decrypt them, by design),
    // only that they have the right shape.
    if req.public_key.len() != PUBLIC_KEY_LEN || req.encrypted_private_key.len() != KEY_BACKUP_LEN {
        return Err(AppError::BadRequest("invalid key data".into()));
    }

    // The auth key is hashed *again* here. If the database leaked, the stored
    // hash still couldn't be replayed to log in.
    let password_hash = hash_password(req.auth_key).await?;
    let id = Uuid::new_v4();

    let result = sqlx::query(
        "INSERT INTO users (id, username, password_hash, public_key, encrypted_private_key)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&req.username)
    .bind(&password_hash)
    .bind(&req.public_key)
    .bind(&req.encrypted_private_key)
    .execute(&state.db)
    .await;

    // Pattern matching on the error lets us turn one specific database
    // failure (duplicate username) into a friendly 409 response.
    match result {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict("username is already taken".into()));
        }
        Err(e) => return Err(e.into()),
    }

    let token = create_session(&state, id).await?;
    Ok(Json(AuthResponse {
        token,
        user: User { id, username: req.username },
        public_key: req.public_key,
        encrypted_private_key: req.encrypted_private_key,
    }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let row: Option<(Uuid, String, String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, username, password_hash, public_key, encrypted_private_key
         FROM users WHERE lower(username) = lower($1)",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;

    // Same message whether the user doesn't exist or the password is wrong,
    // so attackers can't probe which usernames exist.
    const BAD_LOGIN: &str = "invalid username or password";

    let Some((id, username, password_hash, public_key, encrypted_private_key)) = row else {
        return Err(AppError::Unauthorized(BAD_LOGIN));
    };
    if !verify_password(req.auth_key, password_hash).await? {
        return Err(AppError::Unauthorized(BAD_LOGIN));
    }

    // Hand back the locked key backup. Only the client, which knows the
    // password, can unlock it.
    let token = create_session(&state, id).await?;
    Ok(Json(AuthResponse { token, user: User { id, username }, public_key, encrypted_private_key }))
}

/// `GET /me`. Simply declaring `AuthUser` as a parameter makes this route
/// require login: axum runs the extractor below before the handler.
pub async fn me(AuthUser(user): AuthUser) -> Json<User> {
    Json(user)
}

// ---------- The auth extractor ----------

/// The currently logged-in user. Any handler that takes this as an argument
/// can only be reached with a valid `Authorization: Bearer <token>` header.
pub struct AuthUser(pub User);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized("missing bearer token"))?;

        let user = user_for_token(&state.db, token)
            .await?
            .ok_or(AppError::Unauthorized("invalid or expired token"))?;
        Ok(AuthUser(user))
    }
}

/// Looks up which user a session token belongs to. Public so the WebSocket
/// handler can reuse it later.
pub async fn user_for_token(db: &sqlx::PgPool, token: &str) -> Result<Option<User>, sqlx::Error> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1",
    )
    .bind(token)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(id, username)| User { id, username }))
}

// ---------- Helpers ----------

fn validate_username(name: &str) -> Result<(), AppError> {
    let ok_len = (3..=32).contains(&name.chars().count());
    let ok_chars = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "username must be 3-32 characters: letters, digits, or _".into(),
        ))
    }
}

/// The client sends a 32-byte key as 64 hex characters, never the password.
fn validate_auth_key(key: &str) -> Result<(), AppError> {
    if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AppError::BadRequest("malformed auth key (is your client up to date?)".into()))
    }
}

/// Argon2 is deliberately slow (that's what makes brute-forcing expensive).
/// Running it directly in an async handler would block a tokio worker thread
/// and stall other connections, so we move it to a dedicated blocking thread.
async fn hash_password(password: String) -> Result<String, AppError> {
    let hash = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))
    })
    .await??; // first `?`: did the thread panic? second: did hashing fail?
    Ok(hash)
}

async fn verify_password(password: String, stored_hash: String) -> Result<bool, AppError> {
    let ok = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let parsed = PasswordHash::new(&stored_hash)
            .map_err(|e| anyhow::anyhow!("stored hash is malformed: {e}"))?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
    })
    .await??;
    Ok(ok)
}

/// `n_bytes` from the OS's secure RNG, hex-encoded (so 2 chars per byte).
pub fn random_hex(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 random bytes = 256 bits: an unguessable session token.
async fn create_session(state: &AppState, user_id: Uuid) -> Result<String, AppError> {
    let token = random_hex(32);

    sqlx::query("INSERT INTO sessions (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(token)
}
