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
use shared::{AuthRequest, AuthResponse, User};
use uuid::Uuid;

use crate::{AppState, error::AppError};

// ---------- Handlers ----------

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    validate_username(&req.username)?;
    if req.password.len() < 8 {
        return Err(AppError::BadRequest("password must be at least 8 characters".into()));
    }

    let password_hash = hash_password(req.password).await?;
    let id = Uuid::new_v4();

    let result = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&req.username)
        .bind(&password_hash)
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
    Ok(Json(AuthResponse { token, user: User { id, username: req.username } }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, username, password_hash FROM users WHERE lower(username) = lower($1)",
    )
    .bind(&req.username)
    .fetch_optional(&state.db)
    .await?;

    // Same message whether the user doesn't exist or the password is wrong,
    // so attackers can't probe which usernames exist.
    const BAD_LOGIN: &str = "invalid username or password";

    let Some((id, username, password_hash)) = row else {
        return Err(AppError::Unauthorized(BAD_LOGIN));
    };
    if !verify_password(req.password, password_hash).await? {
        return Err(AppError::Unauthorized(BAD_LOGIN));
    }

    let token = create_session(&state, id).await?;
    Ok(Json(AuthResponse { token, user: User { id, username } }))
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
