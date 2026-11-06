//! Everything that touches the network. Runs on tokio, never on the UI thread.

use std::{sync::mpsc, time::Duration};

use eframe::egui;
use futures_util::StreamExt;
use serde::{Serialize, de::DeserializeOwned};
use shared::{
    ApiError, AuthRequest, AuthResponse, Channel, CreateChannelRequest, CreateGuildRequest,
    DmChannel, Guild, JoinGuildRequest, Message, OpenDmRequest, SendMessageRequest, ServerEvent,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_tungstenite::tungstenite::{
    Message as WsMessage,
    client::IntoClientRequest,
    http::{HeaderValue, header::AUTHORIZATION},
};
use uuid::Uuid;

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

/// Results delivered back to the UI.
pub enum Event {
    LoggedIn(AuthResponse),
    Guilds(Vec<Guild>),
    GuildAdded(Guild),
    Channels { guild_id: Uuid, channels: Vec<Channel> },
    Messages { channel_id: Uuid, messages: Vec<Message> },
    Dms(Vec<DmChannel>),
    DmOpened(DmChannel),
    /// A live event from the WebSocket (or an HTTP result shaped like one).
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

/// Thin typed wrapper over HTTP. Generic over the response type `T`, so
/// `api.get::<Vec<Guild>>("/guilds")` deserializes straight into our types.
struct Api {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl Api {
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

/// The network task: processes UI commands one at a time, forever.
pub async fn run(mut commands: UnboundedReceiver<Command>, ui: UiSender, base_url: String) {
    let base = base_url.trim_end_matches('/').to_string();
    // http://... -> ws://...   and   https://... -> wss://...
    let ws_url = format!("{}/ws", base.replacen("http", "ws", 1));
    let mut api = Api { http: reqwest::Client::new(), base, token: None };
    let mut realtime_task: Option<tokio::task::JoinHandle<()>> = None;

    while let Some(cmd) = commands.recv().await {
        match handle(&mut api, cmd).await {
            Ok(Event::LoggedIn(auth)) => {
                // Logged in: start (or restart) the live WebSocket connection.
                if let Some(task) = realtime_task.take() {
                    task.abort();
                }
                realtime_task = Some(tokio::spawn(realtime(ws_url.clone(), auth.token.clone(), ui.clone())));
                ui.send(Event::LoggedIn(auth));
            }
            Ok(event) => ui.send(event),
            Err(e) => ui.send(Event::Error(e)),
        }
    }
}

async fn handle(api: &mut Api, cmd: Command) -> Result<Event, String> {
    Ok(match cmd {
        Command::Auth { username, password, register } => {
            let path = if register { "/auth/register" } else { "/auth/login" };
            let resp: AuthResponse = api.post(path, &AuthRequest { username, password }).await?;
            api.token = Some(resp.token.clone());
            Event::LoggedIn(resp)
        }
        Command::LoadGuilds => Event::Guilds(api.get("/guilds").await?),
        Command::CreateGuild(name) => {
            Event::GuildAdded(api.post("/guilds", &CreateGuildRequest { name }).await?)
        }
        Command::JoinGuild(invite_code) => {
            Event::GuildAdded(api.post("/guilds/join", &JoinGuildRequest { invite_code }).await?)
        }
        Command::LoadChannels(guild_id) => Event::Channels {
            guild_id,
            channels: api.get(&format!("/guilds/{guild_id}/channels")).await?,
        },
        Command::CreateChannel { guild_id, name } => {
            let channel = api.post(&format!("/guilds/{guild_id}/channels"), &CreateChannelRequest { name }).await?;
            Event::Server(ServerEvent::ChannelCreated { channel })
        }
        Command::LoadMessages(channel_id) => Event::Messages {
            channel_id,
            messages: api.get(&format!("/channels/{channel_id}/messages")).await?,
        },
        Command::SendMessage { channel_id, content } => {
            // The server also pushes this over the WebSocket; the UI de-duplicates
            // by id, so your own message shows up even if the socket is down.
            let message = api.post(&format!("/channels/{channel_id}/messages"), &SendMessageRequest { content }).await?;
            Event::Server(ServerEvent::MessageCreated { message })
        }
        Command::LoadDms => Event::Dms(api.get("/dms").await?),
        Command::OpenDm(username) => Event::DmOpened(api.post("/dms", &OpenDmRequest { username }).await?),
    })
}

/// Keeps a WebSocket open, forwarding every server event to the UI.
/// If the connection drops (Wi-Fi blip, server restart), retry every 3s.
async fn realtime(ws_url: String, token: String, ui: UiSender) {
    loop {
        match connect(&ws_url, &token).await {
            Ok(mut stream) => {
                ui.send(Event::Connection(true));
                while let Some(frame) = stream.next().await {
                    match frame {
                        Ok(WsMessage::Text(text)) => {
                            if let Ok(event) = serde_json::from_str::<ServerEvent>(text.as_str()) {
                                ui.send(Event::Server(event));
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
