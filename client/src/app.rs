//! The UI. egui is "immediate mode": `update` runs every frame and simply
//! describes the whole UI from the current state. There are no widget objects
//! to keep in sync; change the state and the next frame reflects it.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Receiver;

use eframe::egui::{self, Align2, Button, Color32, Key, RichText, ScrollArea, TextEdit, vec2};
use shared::{Channel, DmChannel, Guild, Message, ServerEvent, User};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::net::{Command, Event};

/// What the left side is showing: your DMs, or one guild's channels.
#[derive(Clone, Copy, PartialEq)]
enum View {
    Home,
    Guild(Uuid),
}

pub struct App {
    cmd: UnboundedSender<Command>,
    events: Receiver<Event>,

    // Session
    me: Option<User>,
    busy: bool,
    error: Option<String>,
    connected: bool,
    ever_connected: bool,

    // Data received from the server (a local cache)
    guilds: Vec<Guild>,
    channels: HashMap<Uuid, Vec<Channel>>, // guild id -> channels
    dms: Vec<DmChannel>,
    messages: HashMap<Uuid, Vec<Message>>, // channel id -> messages
    unread: HashSet<Uuid>,                 // channel ids with unseen messages

    // Navigation
    view: View,
    selected_channel: Option<Uuid>,

    // Text boxes. egui widgets edit a `&mut String` you own.
    username: String,
    password: String,
    composer: String,
    new_guild_name: String,
    invite_code: String,
    new_channel_name: String,
    dm_username: String,
    show_guild_dialog: bool,
}

impl App {
    pub fn new(cmd: UnboundedSender<Command>, events: Receiver<Event>) -> Self {
        Self {
            cmd,
            events,
            me: None,
            busy: false,
            error: None,
            connected: false,
            ever_connected: false,
            guilds: Vec::new(),
            channels: HashMap::new(),
            dms: Vec::new(),
            messages: HashMap::new(),
            unread: HashSet::new(),
            view: View::Home,
            selected_channel: None,
            username: String::new(),
            password: String::new(),
            composer: String::new(),
            new_guild_name: String::new(),
            invite_code: String::new(),
            new_channel_name: String::new(),
            dm_username: String::new(),
            show_guild_dialog: false,
        }
    }

    fn send(&self, command: Command) {
        let _ = self.cmd.send(command);
    }

    // ---------- Applying events from the network ----------

    /// Drain everything the network task sent since last frame.
    fn process_events(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::LoggedIn(auth) => {
                    self.me = Some(auth.user);
                    self.busy = false;
                    self.error = None;
                    self.password.clear();
                    self.send(Command::LoadGuilds);
                    self.send(Command::LoadDms);
                }
                Event::Guilds(guilds) => {
                    // Preload every guild's channel list so unread markers
                    // work even for guilds you haven't clicked yet.
                    for g in &guilds {
                        self.send(Command::LoadChannels(g.id));
                    }
                    self.guilds = guilds;
                }
                Event::GuildAdded(guild) => {
                    let id = guild.id;
                    if !self.guilds.iter().any(|g| g.id == id) {
                        self.guilds.push(guild);
                    }
                    self.show_guild_dialog = false;
                    self.select_guild(id);
                }
                Event::Channels { guild_id, channels } => {
                    let first = channels.first().map(|c| c.id);
                    self.channels.insert(guild_id, channels);
                    // Just opened this guild: auto-select its first channel.
                    if self.view == View::Guild(guild_id) && self.selected_channel.is_none() {
                        if let Some(first) = first {
                            self.select_channel(first);
                        }
                    }
                }
                Event::Messages { channel_id, messages } => {
                    self.messages.insert(channel_id, messages);
                }
                Event::Dms(dms) => self.dms = dms,
                Event::DmOpened(dm) => {
                    let id = dm.channel.id;
                    self.add_dm(dm);
                    self.view = View::Home;
                    self.select_channel(id);
                }
                Event::Server(event) => self.apply_server_event(event),
                Event::Connection(up) => {
                    // After a reconnect we may have missed messages: drop the
                    // cache and re-fetch whatever is on screen.
                    if up && self.ever_connected {
                        self.messages.clear();
                        if let Some(c) = self.selected_channel {
                            self.send(Command::LoadMessages(c));
                        }
                    }
                    self.ever_connected |= up;
                    self.connected = up;
                }
                Event::Error(e) => {
                    self.busy = false;
                    self.error = Some(e);
                }
            }
        }
    }

    fn apply_server_event(&mut self, event: ServerEvent) {
        match event {
            ServerEvent::MessageCreated { message } => {
                let mine = self.me.as_ref().is_some_and(|me| me.id == message.author.id);
                if Some(message.channel_id) != self.selected_channel && !mine {
                    self.unread.insert(message.channel_id);
                }
                // Only append if we've loaded this channel; otherwise it'll
                // come with the history when opened. Dedupe by id because the
                // same message can arrive via both HTTP and WebSocket.
                if let Some(list) = self.messages.get_mut(&message.channel_id) {
                    if !list.iter().any(|m| m.id == message.id) {
                        list.push(message);
                    }
                }
            }
            ServerEvent::ChannelCreated { channel } => {
                if let Some(list) = channel.guild_id.and_then(|g| self.channels.get_mut(&g)) {
                    if !list.iter().any(|c| c.id == channel.id) {
                        list.push(channel);
                    }
                }
            }
            ServerEvent::DmCreated { dm } => self.add_dm(dm),
        }
    }

    fn add_dm(&mut self, dm: DmChannel) {
        if !self.dms.iter().any(|d| d.channel.id == dm.channel.id) {
            self.dms.push(dm);
        }
    }

    // ---------- Navigation ----------

    fn select_home(&mut self) {
        self.view = View::Home;
        self.selected_channel = None;
    }

    fn select_guild(&mut self, id: Uuid) {
        self.view = View::Guild(id);
        self.selected_channel = None;
        match self.channels.get(&id) {
            Some(chs) => {
                if let Some(first) = chs.first().map(|c| c.id) {
                    self.select_channel(first);
                }
            }
            None => self.send(Command::LoadChannels(id)),
        }
    }

    fn select_channel(&mut self, id: Uuid) {
        self.selected_channel = Some(id);
        self.unread.remove(&id);
        if !self.messages.contains_key(&id) {
            self.send(Command::LoadMessages(id));
        }
    }

    fn channel_title(&self, id: Uuid) -> String {
        if let Some(dm) = self.dms.iter().find(|d| d.channel.id == id) {
            return format!("@{}", dm.other_user.username);
        }
        self.channels
            .values()
            .flatten()
            .find(|c| c.id == id)
            .map(|c| format!("#{}", c.name))
            .unwrap_or_default()
    }

    // ---------- Screens ----------

    fn login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.25);
                ui.heading(RichText::new("Oxide").size(32.0));
                ui.add_space(16.0);

                ui.add(TextEdit::singleline(&mut self.username).hint_text("username").desired_width(240.0));
                let pw = ui.add(
                    TextEdit::singleline(&mut self.password)
                        .hint_text("password")
                        .password(true)
                        .desired_width(240.0),
                );
                let pressed_enter = pw.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.add_space(8.0);

                ui.add_enabled_ui(!self.busy, |ui| {
                    if ui.add(Button::new("Log in").min_size(vec2(240.0, 28.0))).clicked() || pressed_enter {
                        self.auth(false);
                    }
                    if ui.add(Button::new("Create account").min_size(vec2(240.0, 28.0))).clicked() {
                        self.auth(true);
                    }
                });

                if self.busy {
                    ui.spinner();
                }
                if let Some(err) = &self.error {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                }
            });
        });
    }

    fn auth(&mut self, register: bool) {
        if self.username.trim().is_empty() || self.password.is_empty() {
            self.error = Some("enter a username and password".into());
            return;
        }
        self.busy = true;
        self.error = None;
        self.send(Command::Auth {
            username: self.username.trim().to_string(),
            password: self.password.clone(),
            register,
        });
    }

    /// Far-left column: DMs button, one button per guild, and "+".
    fn guild_column(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("guilds").resizable(false).exact_width(72.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.vertical_centered(|ui| {
                let size = vec2(52.0, 52.0);

                let dm_unread = self.dms.iter().any(|d| self.unread.contains(&d.channel.id));
                let home = ui
                    .add(Button::new(with_dot("DMs", dm_unread)).min_size(size).selected(self.view == View::Home))
                    .on_hover_text("Direct messages");
                if home.clicked() {
                    self.select_home();
                }
                ui.separator();

                // Collect the click and act after the loop: we can't call
                // `&mut self` methods while iterating over `&self.guilds`.
                let mut clicked = None;
                for g in &self.guilds {
                    let unread = self
                        .channels
                        .get(&g.id)
                        .is_some_and(|chs| chs.iter().any(|c| self.unread.contains(&c.id)));
                    let button = Button::new(with_dot(&initials(&g.name), unread))
                        .min_size(size)
                        .selected(self.view == View::Guild(g.id));
                    if ui.add(button).on_hover_text(&g.name).clicked() {
                        clicked = Some(g.id);
                    }
                }
                if let Some(id) = clicked {
                    self.select_guild(id);
                }

                let plus = ui.add(Button::new(RichText::new("+").size(22.0)).min_size(size));
                if plus.on_hover_text("Create or join a server").clicked() {
                    self.show_guild_dialog = true;
                }
            });
        });
    }

    /// Second column: DM list or channel list, plus "logged in as" footer.
    fn channel_column(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("channels").resizable(false).exact_width(220.0).show(ctx, |ui| {
            egui::TopBottomPanel::bottom("me").show_inside(ui, |ui| {
                ui.add_space(6.0);
                if let Some(me) = &self.me {
                    ui.label(RichText::new(&me.username).strong());
                }
                let (color, text) = if self.connected {
                    (Color32::from_rgb(67, 181, 129), "connected")
                } else {
                    (Color32::from_rgb(250, 166, 26), "reconnecting...")
                };
                ui.horizontal(|ui| {
                    // Draw the status dot ourselves: allocate a small square and
                    // paint a circle in it (the default font has no ● glyph).
                    let (rect, _) = ui.allocate_exact_size(vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 4.0, color);
                    ui.colored_label(color, text);
                });
                ui.add_space(6.0);
            });

            match self.view {
                View::Home => self.dm_list(ui),
                View::Guild(id) => self.channel_list(ui, id),
            }
        });
    }

    fn dm_list(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Direct messages");
        ui.horizontal(|ui| {
            let input = ui.add(TextEdit::singleline(&mut self.dm_username).hint_text("username").desired_width(140.0));
            let enter = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            if (ui.button("Open").clicked() || enter) && !self.dm_username.trim().is_empty() {
                // `mem::take` moves the String out and leaves an empty one behind.
                let name = std::mem::take(&mut self.dm_username);
                self.send(Command::OpenDm(name.trim().to_string()));
            }
        });
        ui.separator();

        let mut clicked = None;
        ScrollArea::vertical().show(ui, |ui| {
            if self.dms.is_empty() {
                ui.weak("No conversations yet.\nType a username above.");
            }
            for dm in &self.dms {
                let id = dm.channel.id;
                let label = with_dot(&format!("@{}", dm.other_user.username), self.unread.contains(&id));
                if ui.selectable_label(self.selected_channel == Some(id), label).clicked() {
                    clicked = Some(id);
                }
            }
        });
        if let Some(id) = clicked {
            self.select_channel(id);
        }
    }

    fn channel_list(&mut self, ui: &mut egui::Ui, guild_id: Uuid) {
        let Some(guild) = self.guilds.iter().find(|g| g.id == guild_id).cloned() else {
            return;
        };
        ui.add_space(8.0);
        ui.heading(&guild.name);
        ui.horizontal(|ui| {
            ui.weak(format!("Invite: {}", guild.invite_code));
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(guild.invite_code.clone());
            }
        });
        ui.separator();

        let mut clicked = None;
        match self.channels.get(&guild_id) {
            None => {
                ui.spinner();
            }
            Some(channels) => {
                for c in channels {
                    let label = with_dot(&format!("# {}", c.name), self.unread.contains(&c.id));
                    if ui.selectable_label(self.selected_channel == Some(c.id), label).clicked() {
                        clicked = Some(c.id);
                    }
                }
            }
        }
        if let Some(id) = clicked {
            self.select_channel(id);
        }

        let is_owner = self.me.as_ref().is_some_and(|me| me.id == guild.owner_id);
        if is_owner {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let input = ui.add(
                    TextEdit::singleline(&mut self.new_channel_name).hint_text("new-channel").desired_width(140.0),
                );
                let enter = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if (ui.button("Add").clicked() || enter) && !self.new_channel_name.trim().is_empty() {
                    let name = std::mem::take(&mut self.new_channel_name);
                    self.send(Command::CreateChannel { guild_id, name });
                }
            });
        }
    }

    fn chat_area(&mut self, ctx: &egui::Context) {
        let title = self.selected_channel.map(|c| self.channel_title(c));

        // The composer is a bottom panel, added *before* the central panel so
        // egui reserves its space first.
        if let (Some(channel_id), Some(title)) = (self.selected_channel, &title) {
            egui::TopBottomPanel::bottom("composer").show(ctx, |ui| {
                ui.add_space(8.0);
                let input = ui.add(
                    TextEdit::singleline(&mut self.composer)
                        .hint_text(format!("Message {title}"))
                        .desired_width(f32::INFINITY),
                );
                if input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    let content = std::mem::take(&mut self.composer);
                    if !content.trim().is_empty() {
                        self.send(Command::SendMessage { channel_id, content });
                    }
                    input.request_focus(); // keep typing without re-clicking
                }
                ui.add_space(8.0);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(err) = self.error.clone() {
                ui.horizontal(|ui| {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                    if ui.small_button("Dismiss").clicked() {
                        self.error = None;
                    }
                });
                ui.separator();
            }

            let Some(channel_id) = self.selected_channel else {
                ui.centered_and_justified(|ui| {
                    ui.weak("Pick a channel or conversation");
                });
                return;
            };
            ui.heading(title.unwrap_or_default());
            ui.separator();

            let Some(messages) = self.messages.get(&channel_id) else {
                ui.spinner();
                return;
            };

            ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true) // follows new messages like a chat should
                .show(ui, |ui| {
                    if messages.is_empty() {
                        ui.weak("No messages yet. Say hi!");
                    }
                    let mut prev: Option<&Message> = None;
                    for m in messages {
                        // Like Discord: consecutive messages from the same person
                        // within 5 minutes share one name header.
                        let grouped = prev.is_some_and(|p| {
                            p.author.id == m.author.id && (m.created_at - p.created_at).num_minutes() < 5
                        });
                        if !grouped {
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&m.author.username).strong());
                                ui.weak(
                                    m.created_at.with_timezone(&chrono::Local).format("%b %d, %H:%M").to_string(),
                                );
                            });
                        }
                        ui.label(&m.content);
                        prev = Some(m);
                    }
                });
        });
    }

    fn guild_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_guild_dialog {
            return;
        }
        let mut open = true;
        egui::Window::new("Add a server")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Create your own");
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut self.new_guild_name).hint_text("server name"));
                    if ui.button("Create").clicked() && !self.new_guild_name.trim().is_empty() {
                        let name = std::mem::take(&mut self.new_guild_name);
                        self.send(Command::CreateGuild(name));
                    }
                });
                ui.add_space(12.0);
                ui.label("Or join with an invite code");
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut self.invite_code).hint_text("invite code"));
                    if ui.button("Join").clicked() && !self.invite_code.trim().is_empty() {
                        let code = std::mem::take(&mut self.invite_code);
                        self.send(Command::JoinGuild(code));
                    }
                });
            });
        if !open {
            self.show_guild_dialog = false;
        }
    }
}

/// eframe calls this every frame.
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_events();
        if self.me.is_none() {
            self.login_screen(ctx);
        } else {
            self.guild_column(ctx);
            self.channel_column(ctx);
            self.chat_area(ctx);
            self.guild_dialog(ctx);
        }
    }
}

/// "Rust Club" -> "RC"
fn initials(name: &str) -> String {
    name.split_whitespace().take(2).filter_map(|w| w.chars().next()).flat_map(char::to_uppercase).collect()
}

/// Appends an unread marker.
fn with_dot(text: &str, unread: bool) -> String {
    if unread { format!("{text} •") } else { text.to_string() }
}
