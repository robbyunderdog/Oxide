//! Real-time delivery over WebSockets.
//!
//! Each connected client gets a task (`handle_socket`) and an in-memory queue
//! (an mpsc channel). The `Hub` maps user id -> that user's queues, so code
//! anywhere in the server can say "send this event to users X, Y, Z".

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
};
use shared::ServerEvent;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{AppState, auth::AuthUser};

type EventTx = mpsc::UnboundedSender<ServerEvent>;

/// Cheap to clone: it's just an `Arc` (atomically reference-counted pointer)
/// to the one shared registry.
#[derive(Clone, Default)]
pub struct Hub {
    inner: Arc<HubInner>,
}

#[derive(Default)]
struct HubInner {
    /// user id -> (connection id -> queue). A user may be connected from
    /// several devices at once, hence the inner map.
    ///
    /// A plain std Mutex is fine here because we only hold it for
    /// microseconds and never across an `.await`.
    connections: Mutex<HashMap<Uuid, HashMap<u64, EventTx>>>,
    next_id: AtomicU64,
}

impl Hub {
    fn register(&self, user_id: Uuid, tx: EventTx) -> u64 {
        let conn_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.connections.lock().unwrap().entry(user_id).or_default().insert(conn_id, tx);
        conn_id
    }

    fn unregister(&self, user_id: Uuid, conn_id: u64) {
        let mut conns = self.inner.connections.lock().unwrap();
        if let Some(user_conns) = conns.get_mut(&user_id) {
            user_conns.remove(&conn_id);
            if user_conns.is_empty() {
                conns.remove(&user_id);
            }
        }
    }

    /// Queue an event for every open connection of each listed user.
    /// Offline users are simply skipped: they'll load history when they log in.
    pub fn send_to(&self, users: &[Uuid], event: &ServerEvent) {
        let conns = self.inner.connections.lock().unwrap();
        for user_id in users {
            if let Some(user_conns) = conns.get(user_id) {
                for tx in user_conns.values() {
                    // Err only means that connection is closing; ignore.
                    let _ = tx.send(event.clone());
                }
            }
        }
    }
}

/// `GET /ws`: requires the same `Authorization: Bearer` header as everything
/// else, so the `AuthUser` extractor is reused as-is.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, user.id))
}

async fn handle_socket(mut socket: WebSocket, state: AppState, user_id: Uuid) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn_id = state.hub.register(user_id, tx);
    tracing::debug!(%user_id, conn_id, "websocket connected");

    // Cloud hosts often drop connections that look idle; a ping every 30s
    // keeps the connection alive and detects dead clients.
    let mut ping = tokio::time::interval(Duration::from_secs(30));

    // `select!` waits on several things at once and runs whichever is ready
    // first. One task handles both directions of the socket.
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                let json = serde_json::to_string(&event).expect("ServerEvent always serializes");
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            _ = ping.tick() => {
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => match incoming {
                // Clients don't send us anything meaningful; we only watch for disconnects.
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }

    state.hub.unregister(user_id, conn_id);
    tracing::debug!(%user_id, conn_id, "websocket disconnected");
}
