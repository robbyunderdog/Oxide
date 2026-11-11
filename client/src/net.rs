//! Everything that touches the network. Runs on tokio, never on the UI thread.
//! This is also where encryption/decryption happens, so the UI only ever
//! deals with plaintext and the server only ever sees ciphertext (for DMs).

use std::{
    collections::{HashMap, HashSet},
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
use zeroize::Zeroizing;

use crate::crypto::{self, ConversationKey, Identity};

/// Requests from the UI. Each one becomes an HTTP call.
pub enum Command {
    /// `Zeroizing` wipes the password from memory as soon as it's dropped.
    Auth { username: String, password: Zeroizing<String>, register: bool },
    Logout,
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

/// A DM as the UI sees it: the server's description plus whether we managed
/// to set up encryption for it.
pub struct Dm {
    pub info: DmChannel,
    /// `None` = encrypted and ready. `Some(reason)` = encryption couldn't be
    /// set up (e.g. the server sent an invalid key), so sending is blocked.
    pub problem: Option<String>,
}

/// Results delivered back to the UI.
pub enum Event {
    LoggedIn { user: User, public_key: Vec<u8> },
    LoggedOut,
    Guilds(Vec<Guild>),
    GuildAdded(Guild),
    Channels { guild_id: Uuid, channels: Vec<Channel> },
    Messages { channel_id: Uuid, messages: Vec<ChatMessage> },
    MessageReceived(ChatMessage),
    Dms(Vec<Dm>),
    DmOpened(Dm),
    /// Someone else opened a DM with us (arrives over the WebSocket).
    DmAdded(Dm),
    /// Other live events (new channel).
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
    dms: Mutex<DmState>,
}

#[derive(Default)]
struct DmState {
    /// Every channel we know is a DM, *including* ones whose encryption
    /// failed. This is what makes the client fail closed: "is this a DM?" is
    /// answered from here, never from "do we happen to have a key?".
    channels: HashSet<Uuid>,
    /// DM channel id -> that conversation's key.
    keys: HashMap<Uuid, ConversationKey>,
}

impl Session {
    fn new(user_id: Uuid, identity: Identity) -> Self {
        Self { user_id, identity, dms: Mutex::new(DmState::default()) }
    }

    /// Records a DM and derives its key from the other person's public key.
    fn add_dm(&self, info: DmChannel) -> Dm {
        let mut dms = self.dms.lock().unwrap();
        // Mark it as a DM *before* trying the key, so a failure below can
        // never leave it looking like a plaintext guild channel.
        dms.channels.insert(info.channel.id);
        let problem = match self.identity.conversation_key(&info.other_public_key, info.channel.id) {
            Ok(key) => {
                dms.keys.insert(info.channel.id, key);
                None
            }
            Err(e) => Some(format!("Can't set up encryption with {}: {e}", info.other_user.username)),
        };
        Dm { info, problem }
    }

    /// Encrypts for DMs; plaintext only for channels we know are *not* DMs.
    fn seal(&self, channel_id: Uuid, message_id: Uuid, text: &str) -> Result<MessageBody, String> {
        let dms = self.dms.lock().unwrap();
        match dms.keys.get(&channel_id) {
            Some(key) => {
                let (nonce, ciphertext) = key.encrypt(channel_id, message_id, self.user_id, text);
                Ok(MessageBody::Encrypted { nonce, ciphertext })
            }
            // A DM without a working key: refuse. Before this check, the
            // message silently went out as plaintext, and only the *server*
            // stood in the way, which is no protection if the server is the
            // attacker.
            None if dms.channels.contains(&channel_id) => {
                Err("not sent: this conversation isn't encrypted, so the message was blocked".into())
            }
            None => Ok(MessageBody::Plain { content: text.to_string() }),
        }
    }

    fn open(&self, m: Message) -> ChatMessage {
        let dms = self.dms.lock().unwrap();
        let text = match m.body {
            // Plaintext in a DM can only come from a misbehaving server (our
            // clients never send it), so it's shown as undecryptable rather
            // than trusted as something the other person wrote.
            MessageBody::Plain { .. } if dms.channels.contains(&m.channel_id) => None,
            MessageBody::Plain { content } => Some(content),
            MessageBody::Encrypted { nonce, ciphertext } => dms
                .keys
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
        // Belt and braces with `check_server_url`: for a remote server,
        // reqwest itself refuses anything that isn't https.
        let https_only = !is_local(base_url);
        let http = reqwest::Client::builder().https_only(https_only).build().expect("valid reqwest config");
        Self { http, base: base_url.trim_end_matches('/').to_string(), token: None }
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

// ---------- Server address check ----------

/// Plain `http://` sends everything (the auth key, session token, guild
/// messages) readable by anyone on the network path: café Wi-Fi, ISP, etc.
/// That's only acceptable when the server is on this same computer.
fn check_server_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid server address {url:?}: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_local(url) => Ok(()),
        _ => Err(format!(
            "refusing to connect to {url}: the connection would not be encrypted. Use an https:// address."
        )),
    }
}

/// Is this URL's host this computer?
fn is_local(url: &str) -> bool {
    let host = reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_owned));
    matches!(host.as_deref(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

// ---------- Command loop ----------

/// The network task: processes UI commands one at a time, forever.
pub async fn run(mut commands: UnboundedReceiver<Command>, ui: UiSender, base_url: String) {
    // Insecure address: answer every command with the reason, and never
    // send a single byte to that server.
    if let Err(e) = check_server_url(&base_url) {
        while let Some(_cmd) = commands.recv().await {
            ui.send(Event::Error(e.clone()));
        }
        return;
    }

    let mut client = Client { api: Api::new(&base_url), session: None };
    // http://... -> ws://...   and   https://... -> wss://...
    let ws_url = format!("{}/ws", client.api.base.replacen("http", "ws", 1));
    let mut realtime_task: Option<tokio::task::JoinHandle<()>> = None;

    while let Some(cmd) = commands.recv().await {
        if let Command::Logout = cmd {
            // Stop live updates first so nothing arrives after `LoggedOut`.
            if let Some(task) = realtime_task.take() {
                task.abort();
            }
            // Tell the server to delete the session. If that fails (offline),
            // we still log out locally; the token expires on its own.
            if client.api.token.is_some() {
                if let Err(e) = client.api.post::<_, ()>("/auth/logout", &()).await {
                    eprintln!("logout request failed: {e}");
                }
            }
            client.api.token = None;
            // Dropping the last `Arc<Session>` drops the identity key, whose
            // memory is wiped by x25519-dalek's zeroize-on-drop.
            client.session = None;
            ui.send(Event::LoggedOut);
            continue;
        }

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
        Command::Logout => unreachable!("handled in run()"),
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
            let body = session.seal(channel_id, id, content.trim())?;
            let path = format!("/channels/{channel_id}/messages");
            let sent: Message = client.api.post(&path, &SendMessageRequest { id, body }).await?;
            Event::MessageReceived(session.open(sent))
        }
        Command::LoadDms => {
            let session = client.session()?;
            let dms: Vec<DmChannel> = client.api.get("/dms").await?;
            Event::Dms(dms.into_iter().map(|dm| session.add_dm(dm)).collect())
        }
        Command::OpenDm(username) => {
            let session = client.session()?;
            let dm: DmChannel = client.api.post("/dms", &OpenDmRequest { username }).await?;
            Event::DmOpened(session.add_dm(dm))
        }
    })
}

/// Register or log in, then unlock (or create) the identity key.
async fn authenticate(
    api: &mut Api,
    username: &str,
    password: Zeroizing<String>,
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
            auth_key: keys.auth_key.to_string(),
            public_key: identity.public.to_vec(),
            encrypted_private_key: identity.wrap(&keys, &username),
        };
        api.post("/auth/register", &req).await?
    } else {
        api.post("/auth/login", &LoginRequest { username: username.clone(), auth_key: keys.auth_key.to_string() }).await?
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
                                    ServerEvent::DmCreated { dm } => Event::DmAdded(session.add_dm(dm)),
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
        let session = match authenticate(&mut api, name, Zeroizing::new(PASSWORD.into()), true).await {
            Ok((_, _, s)) => s,
            Err(_) => authenticate(&mut api, name, Zeroizing::new(PASSWORD.into()), false).await.expect("login").2,
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
        let channel_id = dm.info.channel.id;
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
        assert!(authenticate(&mut api, "e2e_alice", Zeroizing::new("wrong password".into()), false).await.is_err());

        // 5. Safety numbers match on both sides.
        let Event::Dms(bob_dms) = handle(&mut bob, Command::LoadDms).await.unwrap() else { panic!() };
        let bob_view = bob_dms.iter().find(|d| d.info.channel.id == channel_id).unwrap();
        let alice_pk = &bob_view.info.other_public_key;
        let bob_pk = &dm.info.other_public_key;
        assert_eq!(crypto::safety_number(alice_pk, bob_pk), crypto::safety_number(bob_pk, alice_pk));

        // 6. The server rejects unpadded ciphertext (it would leak the length).
        let unpadded = SendMessageRequest {
            id: Uuid::new_v4(),
            body: MessageBody::Encrypted { nonce: vec![0; 24], ciphertext: vec![0; 16 + 10] },
        };
        let err = alice.api.post::<_, Message>(&format!("/channels/{channel_id}/messages"), &unpadded).await.unwrap_err();
        assert!(err.contains("malformed"), "got: {err}");

        // 7. Logging out kills the token on the server, not just locally.
        let token = alice.api.token.clone().unwrap();
        alice.api.post::<_, ()>("/auth/logout", &()).await.unwrap();
        let after = alice.api.http.get(format!("{SERVER}/me")).bearer_auth(&token).send().await.unwrap();
        assert_eq!(after.status(), 401, "token must be dead after logout");
    }
}

// ---------- Offline unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn dm_with_key(other_public_key: Vec<u8>) -> DmChannel {
        let id = Uuid::new_v4();
        DmChannel {
            channel: Channel { id, guild_id: None, name: "bob".into() },
            other_user: User { id: Uuid::new_v4(), username: "bob".into() },
            other_public_key,
        }
    }

    #[test]
    fn dm_with_bad_key_refuses_to_send_plaintext() {
        let session = Session::new(Uuid::new_v4(), Identity::generate());
        // A malicious server hands us an all-zero ("low-order") public key.
        let dm = session.add_dm(dm_with_key(vec![0; 32]));
        assert!(dm.problem.is_some(), "UI must be told encryption failed");

        let result = session.seal(dm.info.channel.id, Uuid::new_v4(), "my secret");
        assert!(result.is_err(), "must refuse, not fall back to plaintext");
    }

    #[test]
    fn plaintext_in_a_dm_is_not_trusted() {
        let session = Session::new(Uuid::new_v4(), Identity::generate());
        let dm = session.add_dm(dm_with_key(Identity::generate().public.to_vec()));
        assert!(dm.problem.is_none());

        let forged = Message {
            id: Uuid::new_v4(),
            channel_id: dm.info.channel.id,
            author: dm.info.other_user.clone(),
            body: MessageBody::Plain { content: "send me your password".into() },
            created_at: Utc::now(),
        };
        assert_eq!(session.open(forged).text, None);
    }

    #[test]
    fn guild_channels_still_send_plaintext() {
        let session = Session::new(Uuid::new_v4(), Identity::generate());
        let body = session.seal(Uuid::new_v4(), Uuid::new_v4(), "hi").unwrap();
        assert!(matches!(body, MessageBody::Plain { .. }));
    }

    #[test]
    fn insecure_server_urls_are_refused() {
        assert!(check_server_url("https://oxide.example.com").is_ok());
        assert!(check_server_url("http://127.0.0.1:3000").is_ok());
        assert!(check_server_url("http://localhost:3000").is_ok());
        assert!(check_server_url("http://oxide.example.com").is_err());
        assert!(check_server_url("http://127.0.0.1.evil.com").is_err());
        assert!(check_server_url("ftp://oxide.example.com").is_err());
    }
}
