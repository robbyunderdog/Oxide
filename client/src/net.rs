//! Everything that touches the network. Runs on tokio, never on the UI thread.
//! This is also where encryption/decryption happens, so the UI only ever
//! deals with plaintext and the server only ever sees ciphertext (for DMs).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use chrono::{DateTime, Utc};
use eframe::egui;
use futures_util::StreamExt;
use serde::{Serialize, de::DeserializeOwned};
use shared::{
    ApiError, AuthResponse, Channel, CreateChannelRequest, CreateGuildRequest, DmChannel, Guild,
    JoinGuildRequest, LoginRequest, Message, MessageBody, OpenDmRequest, RegisterRequest,
    SendMessageRequest, ServerEvent, User,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_tungstenite::tungstenite::{
    Message as WsMessage,
    client::IntoClientRequest,
    http::{HeaderValue, header::AUTHORIZATION},
};
use uuid::Uuid;

use crate::crypto::{self, ConversationKey, Identity};

/// Requests from the UI. Each one becomes an HTTP call.
pub enum Command {
    Auth { username: String, password: String, register: bool },
    LoadGuilds,
    CreateGuild(String),
    JoinGuild(String),
    LoadChannels(Uuid),
    CreateChannel { guild_id: Uuid, name: String },
    LoadMessages(Uuid),
    SendMessage { channel_id: Uuid, content: String },
    LoadDms,
    OpenDm(String),
}

/// A message as the UI sees it: already decrypted.
pub struct ChatMessage {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub author: User,
    pub created_at: DateTime<Utc>,
    /// `None` if this was an encrypted message we couldn't decrypt.
    pub text: Option<String>,
}

/// Results delivered back to the UI.
pub enum Event {
    LoggedIn { user: User, public_key: Vec<u8> },
    Guilds(Vec<Guild>),
    GuildAdded(Guild),
    Channels { guild_id: Uuid, channels: Vec<Channel> },
    Messages { channel_id: Uuid, messages: Vec<ChatMessage> },
    MessageReceived(ChatMessage),
    Dms(Vec<DmChannel>),
    DmOpened(DmChannel),
    /// Other live events (new channel, new DM).
    Server(ServerEvent),
    /// WebSocket connected (true) or lost (false).
    Connection(bool),
    Error(String),
}

/// Sends an event to the UI *and* wakes it up. egui only redraws when
/// something happens; without `request_repaint`, a new message would sit
/// unseen until you moved the mouse.
#[derive(Clone)]
pub struct UiSender {
    tx: mpsc::Sender<Event>,
    ctx: egui::Context,
}

impl UiSender {
    pub fn new(tx: mpsc::Sender<Event>, ctx: egui::Context) -> Self {
        Self { tx, ctx }
    }

    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
        self.ctx.request_repaint();
    }
}

// ---------- Encryption session ----------

/// Created at login. Shared (via `Arc`) between the command loop and the
/// WebSocket task, which both need to decrypt messages.
pub struct Session {
    user_id: Uuid,
    identity: Identity,
    /// DM channel id -> that conversation's key.
    dm_keys: Mutex<HashMap<Uuid, ConversationKey>>,
}

impl Session {
    fn new(user_id: Uuid, identity: Identity) -> Self {
        Self { user_id, identity, dm_keys: Mutex::new(HashMap::new()) }
    }

    /// Learn a DM's key from the other person's public key.
    fn add_dm(&self, dm: &DmChannel) {
        match self.identity.conversation_key(&dm.other_public_key, dm.channel.id) {
            Ok(key) => {
                self.dm_keys.lock().unwrap().insert(dm.channel.id, key);
            }
            Err(e) => eprintln!("can't set up encryption with {}: {e}", dm.other_user.username),
        }
    }

    /// Encrypt if this is a DM; plaintext for guild channels.
    fn seal(&self, channel_id: Uuid, message_id: Uuid, text: &str) -> MessageBody {
        match self.dm_keys.lock().unwrap().get(&channel_id) {
            Some(key) => {
                let (nonce, ciphertext) = key.encrypt(channel_id, message_id, self.user_id, text);
                MessageBody::Encrypted { nonce, ciphertext }
            }
            None => MessageBody::Plain { content: text.to_string() },
        }
    }

    fn open(&self, m: Message) -> ChatMessage {
        let text = match m.body {
            MessageBody::Plain { content } => Some(content),
            MessageBody::Encrypted { nonce, ciphertext } => self
                .dm_keys
                .lock()
                .unwrap()
                .get(&m.channel_id)
                .and_then(|key| key.decrypt(m.channel_id, m.id, m.author.id, &nonce, &ciphertext).ok()),
        };
        ChatMessage { id: m.id, channel_id: m.channel_id, author: m.author, created_at: m.created_at, text }
    }
}

// ---------- HTTP ----------

/// Thin typed wrapper over HTTP. Generic over the response type `T`, so
/// `api.get::<Vec<Guild>>("/guilds")` deserializes straight into our types.
struct Api {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl Api {
    fn new(base_url: &str) -> Self {
        Self { http: reqwest::Client::new(), base: base_url.trim_end_matches('/').to_string(), token: None }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        self.execute(self.http.get(format!("{}{path}", self.base))).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, String> {
        self.execute(self.http.post(format!("{}{path}", self.base)).json(body)).await
    }

    async fn execute<T: DeserializeOwned>(&self, mut req: reqwest::RequestBuilder) -> Result<T, String> {
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(|e| format!("can't reach server: {e}"))?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>().await.map_err(|e| format!("unexpected response from server: {e}"))
        } else {
            // Server errors come as {"error": "..."}; show that text to the user.
            match resp.json::<ApiError>().await {
                Ok(e) => Err(e.error),
                Err(_) => Err(format!("server returned {status}")),
            }
        }
    }
}

/// All state the network side owns.
struct Client {
    api: Api,
    session: Option<Arc<Session>>,
}

impl Client {
    fn session(&self) -> Result<Arc<Session>, String> {
        self.session.clone().ok_or_else(|| "not logged in".to_string())
    }
}

// ---------- Command loop ----------

/// The network task: processes UI commands one at a time, forever.
pub async fn run(mut commands: UnboundedReceiver<Command>, ui: UiSender, base_url: String) {
    let mut client = Client { api: Api::new(&base_url), session: None };
    // http://... -> ws://...   and   https://... -> wss://...
    let ws_url = format!("{}/ws", client.api.base.replacen("http", "ws", 1));
    let mut realtime_task: Option<tokio::task::JoinHandle<()>> = None;

    while let Some(cmd) = commands.recv().await {
        let logging_in = matches!(cmd, Command::Auth { .. });
        let result = handle(&mut client, cmd).await;

        // Logged in: start (or restart) the live WebSocket connection.
        if logging_in && result.is_ok() {
            if let (Some(token), Some(session)) = (client.api.token.clone(), client.session.clone()) {
                if let Some(task) = realtime_task.take() {
                    task.abort();
                }
                realtime_task = Some(tokio::spawn(realtime(ws_url.clone(), token, session, ui.clone())));
            }
        }

        match result {
            Ok(event) => ui.send(event),
            Err(e) => ui.send(Event::Error(e)),
        }
    }
}

async fn handle(client: &mut Client, cmd: Command) -> Result<Event, String> {
    Ok(match cmd {
        Command::Auth { username, password, register } => {
            let (user, public_key, session) = authenticate(&mut client.api, &username, password, register).await?;
            client.session = Some(Arc::new(session));
            Event::LoggedIn { user, public_key }
        }
        Command::LoadGuilds => Event::Guilds(client.api.get("/guilds").await?),
        Command::CreateGuild(name) => {
            Event::GuildAdded(client.api.post("/guilds", &CreateGuildRequest { name }).await?)
        }
        Command::JoinGuild(invite_code) => {
            Event::GuildAdded(client.api.post("/guilds/join", &JoinGuildRequest { invite_code }).await?)
        }
        Command::LoadChannels(guild_id) => Event::Channels {
            guild_id,
            channels: client.api.get(&format!("/guilds/{guild_id}/channels")).await?,
        },
        Command::CreateChannel { guild_id, name } => {
            let path = format!("/guilds/{guild_id}/channels");
            let channel = client.api.post(&path, &CreateChannelRequest { name }).await?;
            Event::Server(ServerEvent::ChannelCreated { channel })
        }
        Command::LoadMessages(channel_id) => {
            let session = client.session()?;
            let raw: Vec<Message> = client.api.get(&format!("/channels/{channel_id}/messages")).await?;
            Event::Messages { channel_id, messages: raw.into_iter().map(|m| session.open(m)).collect() }
        }
        Command::SendMessage { channel_id, content } => {
            let session = client.session()?;
            // We pick the id because it's part of the encryption's associated data.
            let id = Uuid::new_v4();
            let body = session.seal(channel_id, id, content.trim());
            let path = format!("/channels/{channel_id}/messages");
            let sent: Message = client.api.post(&path, &SendMessageRequest { id, body }).await?;
            Event::MessageReceived(session.open(sent))
        }
        Command::LoadDms => {
            let session = client.session()?;
            let dms: Vec<DmChannel> = client.api.get("/dms").await?;
            dms.iter().for_each(|dm| session.add_dm(dm));
            Event::Dms(dms)
        }
        Command::OpenDm(username) => {
            let session = client.session()?;
            let dm: DmChannel = client.api.post("/dms", &OpenDmRequest { username }).await?;
            session.add_dm(&dm);
            Event::DmOpened(dm)
        }
    })
}

/// Register or log in, then unlock (or create) the identity key.
async fn authenticate(
    api: &mut Api,
    username: &str,
    password: String,
    register: bool,
) -> Result<(User, Vec<u8>, Session), String> {
    let username = username.trim().to_string();

    // Argon2 takes real CPU time; keep it off the async worker threads.
    let name = username.clone();
    let keys = tokio::task::spawn_blocking(move || crypto::derive_password_keys(&name, &password))
        .await
        .map_err(|e| e.to_string())??;

    let resp: AuthResponse = if register {
        let identity = Identity::generate();
        let req = RegisterRequest {
            username: username.clone(),
            auth_key: keys.auth_key.clone(),
            public_key: identity.public.to_vec(),
            encrypted_private_key: identity.wrap(&keys, &username),
        };
        api.post("/auth/register", &req).await?
    } else {
        api.post("/auth/login", &LoginRequest { username: username.clone(), auth_key: keys.auth_key.clone() }).await?
    };

    // Same path for both: unlock the backup the server returned. This also
    // proves the server gave us back exactly what we stored.
    let identity = Identity::unwrap(&resp.encrypted_private_key, &keys, &username, &resp.public_key)?;
    api.token = Some(resp.token);
    let public_key = identity.public.to_vec();
    Ok((resp.user.clone(), public_key, Session::new(resp.user.id, identity)))
}

// ---------- WebSocket ----------

/// Keeps a WebSocket open, forwarding every server event to the UI.
/// If the connection drops (Wi-Fi blip, server restart), retry every 3s.
async fn realtime(ws_url: String, token: String, session: Arc<Session>, ui: UiSender) {
    loop {
        match connect(&ws_url, &token).await {
            Ok(mut stream) => {
                ui.send(Event::Connection(true));
                while let Some(frame) = stream.next().await {
                    match frame {
                        Ok(WsMessage::Text(text)) => {
                            if let Ok(event) = serde_json::from_str::<ServerEvent>(text.as_str()) {
                                ui.send(match event {
                                    ServerEvent::MessageCreated { message } => {
                                        Event::MessageReceived(session.open(message))
                                    }
                                    ServerEvent::DmCreated { dm } => {
                                        session.add_dm(&dm);
                                        Event::Server(ServerEvent::DmCreated { dm })
                                    }
                                    other => Event::Server(other),
                                });
                            }
                        }
                        Ok(WsMessage::Close(_)) | Err(_) => break,
                        Ok(_) => {} // pings are answered automatically by tungstenite
                    }
                }
            }
            Err(e) => eprintln!("websocket connect failed: {e}"),
        }
        ui.send(Event::Connection(false));
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn connect(
    url: &str,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).expect("token is valid ASCII"));
    let (stream, _response) = tokio_tungstenite::connect_async(request).await?;
    Ok(stream)
}

// ---------- Live end-to-end test ----------

/// Needs a running server, so it's skipped by default. Run with:
/// `cargo test -p client -- --ignored --nocapture`
#[cfg(test)]
mod live_tests {
    use super::*;

    const SERVER: &str = "http://127.0.0.1:3000";
    const PASSWORD: &str = "correct horse battery";

    async fn login_or_register(name: &str) -> Client {
        let mut api = Api::new(SERVER);
        let session = match authenticate(&mut api, name, PASSWORD.into(), true).await {
            Ok((_, _, s)) => s,
            Err(_) => authenticate(&mut api, name, PASSWORD.into(), false).await.expect("login").2,
        };
        Client { api, session: Some(Arc::new(session)) }
    }

    #[tokio::test]
    #[ignore]
    async fn dm_is_unreadable_by_the_server() {
        let mut alice = login_or_register("e2e_alice").await;
        let mut bob = login_or_register("e2e_bob").await;

        let Event::DmOpened(dm) = handle(&mut alice, Command::OpenDm("e2e_bob".into())).await.unwrap() else {
            panic!("expected DmOpened")
        };
        let channel_id = dm.channel.id;
        handle(&mut bob, Command::LoadDms).await.unwrap();

        let secret = format!("the eagle lands at {}", Uuid::new_v4());
        handle(&mut alice, Command::SendMessage { channel_id, content: secret.clone() }).await.unwrap();
        handle(&mut bob, Command::SendMessage { channel_id, content: "copy that, alice".into() }).await.unwrap();

        // 1. Bob's client decrypts Alice's message.
        let Event::Messages { messages, .. } = handle(&mut bob, Command::LoadMessages(channel_id)).await.unwrap()
        else {
            panic!("expected Messages")
        };
        assert!(messages.iter().any(|m| m.text.as_deref() == Some(secret.as_str())), "bob reads alice's DM");
        assert!(messages.iter().all(|m| m.text.is_some()), "every DM decrypts");

        // 2. What the server stores and sends: raw JSON, as an attacker with
        //    full server/database access would see it.
        let raw = bob
            .api
            .http
            .get(format!("{SERVER}/channels/{channel_id}/messages"))
            .bearer_auth(bob.api.token.as_ref().unwrap())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        println!("\n--- raw server data (last message) ---\n{}\n", &raw[raw.len().saturating_sub(400)..]);
        assert!(!raw.contains("eagle"), "plaintext must never reach the server");
        assert!(!raw.contains("copy that"), "plaintext must never reach the server");
        assert!(raw.contains("\"kind\":\"Encrypted\""));

        // 3. The server refuses a plaintext DM, even from a buggy/malicious client.
        let plain = SendMessageRequest { id: Uuid::new_v4(), body: MessageBody::Plain { content: "oops".into() } };
        let err = alice.api.post::<_, Message>(&format!("/channels/{channel_id}/messages"), &plain).await.unwrap_err();
        assert!(err.contains("end-to-end encrypted"), "got: {err}");

        // 4. Wrong password can't log in (and so can't unlock the key).
        let mut api = Api::new(SERVER);
        assert!(authenticate(&mut api, "e2e_alice", "wrong password".into(), false).await.is_err());

        // 5. Safety numbers match on both sides.
        let Event::Dms(bob_dms) = handle(&mut bob, Command::LoadDms).await.unwrap() else { panic!() };
        let bob_view = bob_dms.iter().find(|d| d.channel.id == channel_id).unwrap();
        let alice_pk = &bob_view.other_public_key;
        let bob_pk = &dm.other_public_key;
        assert_eq!(crypto::safety_number(alice_pk, bob_pk), crypto::safety_number(bob_pk, alice_pk));
    }
}
