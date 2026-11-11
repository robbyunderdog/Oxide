mod auth;
mod chat;
mod dms;
mod error;
mod guilds;
mod limits;
mod realtime;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Semaphore;

/// Shared state handed to every request handler. `PgPool` is internally
/// reference-counted, so cloning `AppState` is cheap: every clone points
/// to the same pool of database connections.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    /// Registry of live WebSocket connections, for pushing events.
    pub hub: realtime::Hub,
    /// Caps login/register attempts per IP (see limits.rs).
    pub auth_limiter: Arc<limits::RateLimiter>,
    /// How many Argon2 hashes may run at once. Extra requests wait their turn
    /// instead of all grabbing CPU and memory at the same time.
    pub hash_slots: Arc<Semaphore>,
    /// Set TRUST_PROXY=1 when running behind a load balancer that sets
    /// X-Forwarded-For (most cloud hosts). Leave unset otherwise.
    pub trust_proxy: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env (if present) into environment variables. In the cloud we'll
    // set real environment variables instead, and this quietly does nothing.
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("server=debug,info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set (see .env)")?;
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("failed to connect to the database")?;

    // Applies any migrations in server/migrations/ that haven't run yet.
    // The SQL files are embedded into the binary at compile time.
    sqlx::migrate!().run(&db).await.context("failed to run migrations")?;
    tracing::info!("database ready, migrations applied");

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route("/guilds", get(guilds::list).post(guilds::create))
        .route("/guilds/join", post(guilds::join))
        .route("/guilds/{id}/channels", get(guilds::channels).post(guilds::create_channel))
        .route("/channels/{id}/messages", get(chat::history).post(chat::send))
        .route("/dms", get(dms::list).post(dms::open))
        .route("/ws", get(realtime::ws_handler))
        .with_state(AppState {
            db,
            hub: realtime::Hub::default(),
            // 10 attempts per 15 minutes is plenty for a person mistyping,
            // and makes online guessing hopelessly slow.
            auth_limiter: Arc::new(limits::RateLimiter::new(10, Duration::from_secs(15 * 60))),
            hash_slots: Arc::new(Semaphore::new(
                std::thread::available_parallelism().map_or(2, |n| n.get()),
            )),
            trust_proxy: std::env::var("TRUST_PROXY").is_ok_and(|v| v == "1"),
        });

    // 127.0.0.1 = only reachable from this PC (no firewall prompts, nothing
    // exposed). In the cloud we'll set BIND_ADDR=0.0.0.0:<port>.
    let addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on http://{addr}");
    // `with_connect_info` records each connection's IP address so the rate
    // limiter can read it (see `limits::ClientIp`).
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
