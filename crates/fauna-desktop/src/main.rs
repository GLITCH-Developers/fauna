#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use eframe::egui;
use fauna_core::{DeviceIdentity, EncryptedMessage, ExchangeKeypair, Invite, PeerId, SessionKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod tor;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([760.0, 520.0])
            .with_title("Fauna"),
        ..Default::default()
    };

    eframe::run_native(
        "Fauna",
        options,
        Box::new(|cc| Ok(Box::new(FaunaApp::new(cc)))),
    )
}

struct FaunaApp {
    display_name: String,
    bind_addr: String,
    public_addr: String,
    tor_enabled: bool,
    tor_auto_start: bool,
    tor_exe_path: String,
    tor_control_addr: String,
    tor_socks_addr: String,
    tor_service_port: String,
    join_invite: String,
    current_invite: String,
    draft_message: String,
    connection: Option<ConnectionHandle>,
    tor_runtime: Option<tor::TorRuntime>,
    messages: Vec<MessageLine>,
    status: String,
    peer_name: Option<String>,
}

struct ConnectionHandle {
    outbound: Sender<String>,
    events: Receiver<NetworkEvent>,
}

struct MessageLine {
    author: MessageAuthor,
    body: String,
}

enum MessageAuthor {
    Local,
    Remote,
    System,
}

enum NetworkEvent {
    InviteCreated(String),
    Connected(String),
    Incoming(String),
    Disconnected(String),
    Error(String),
}

impl FaunaApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_ui(&cc.egui_ctx);

        Self {
            display_name: "Kivan".to_owned(),
            bind_addr: "127.0.0.1:0".to_owned(),
            public_addr: "127.0.0.1:45123".to_owned(),
            tor_enabled: true,
            tor_auto_start: true,
            tor_exe_path: String::new(),
            tor_control_addr: "127.0.0.1:9151".to_owned(),
            tor_socks_addr: "127.0.0.1:9150".to_owned(),
            tor_service_port: "45123".to_owned(),
            join_invite: String::new(),
            current_invite: String::new(),
            draft_message: String::new(),
            connection: None,
            tor_runtime: None,
            messages: vec![MessageLine {
                author: MessageAuthor::System,
                body: "Fauna hazir. Sohbet baslatabilir veya davet linkiyle katilabilirsin."
                    .to_owned(),
            }],
            status: "Hazir".to_owned(),
            peer_name: None,
        }
    }

    fn start_host(&mut self) {
        let name = self.display_name.trim().to_owned();
        let bind = if self.tor_enabled {
            self.bind_addr.trim().to_owned()
        } else {
            normalize_direct_bind_addr(self.bind_addr.trim())
        };
        let public_addr = self.public_addr.trim().to_owned();
        let tor_config = match self.prepare_tor_config() {
            Ok(config) => config,
            Err(error) => {
                self.push_system(&error.to_string());
                self.status = "Tor baslatilamadi".to_owned();
                return;
            }
        };

        if name.is_empty() || bind.is_empty() {
            self.push_system("Isim ve host adresi bos olamaz.");
            return;
        }

        if tor_config.is_none() && public_addr.is_empty() {
            self.push_system("Tor kapaliyken paylasilan adres bos olamaz.");
            return;
        }

        let (outbound, events) = start_host_thread(name, bind, public_addr, tor_config);
        self.connection = Some(ConnectionHandle { outbound, events });
        self.current_invite.clear();
        self.status = "Davet olusturuluyor".to_owned();
    }

    fn start_join(&mut self) {
        let name = self.display_name.trim().to_owned();
        let invite = self.join_invite.trim().to_owned();

        if name.is_empty() || invite.is_empty() {
            self.push_system("Isim ve davet linki bos olamaz.");
            return;
        }

        if invite_contains_onion_address(&invite) && !self.tor_enabled {
            self.tor_enabled = true;
            self.tor_auto_start = true;
            self.push_system("Onion daveti algilandi; Tor modu otomatik acildi.");
        }

        let tor_socks_addr = match self.prepare_tor_config() {
            Ok(Some(config)) => config.socks_addr,
            Ok(None) => self.tor_socks_addr.trim().to_owned(),
            Err(error) => {
                self.push_system(&error.to_string());
                self.status = "Tor baslatilamadi".to_owned();
                return;
            }
        };

        let (outbound, events) = start_join_thread(name, invite, tor_socks_addr);
        self.connection = Some(ConnectionHandle { outbound, events });
        self.status = "Baglaniyor".to_owned();
    }

    fn prepare_tor_config(&mut self) -> Result<Option<TorConfig>> {
        if !self.tor_enabled {
            return Ok(None);
        }

        if self.tor_auto_start {
            self.ensure_managed_tor()?;
        }

        let service_port = self.tor_service_port.trim().parse().unwrap_or(45123);
        Ok(Some(TorConfig {
            control_addr: self.tor_control_addr.trim().to_owned(),
            socks_addr: self.tor_socks_addr.trim().to_owned(),
            service_port,
        }))
    }

    fn ensure_managed_tor(&mut self) -> Result<()> {
        if self.tor_runtime.is_some() {
            return Ok(());
        }

        self.status = "Tor baslatiliyor".to_owned();
        let exe_hint = if self.tor_exe_path.trim().is_empty() {
            None
        } else {
            Some(self.tor_exe_path.trim())
        };
        let runtime = tor::start_managed_tor(exe_hint)?;
        self.tor_control_addr = runtime.control_addr().to_owned();
        self.tor_socks_addr = runtime.socks_addr().to_owned();
        self.tor_runtime = Some(runtime);
        Ok(())
    }

    fn send_message(&mut self) {
        let body = self.draft_message.trim().to_owned();
        if body.is_empty() {
            return;
        }

        let Some(connection) = &self.connection else {
            self.push_system("Once bir sohbet baslat veya davete katil.");
            return;
        };

        let outbound = connection.outbound.clone();
        match outbound.send(body.clone()) {
            Ok(()) => {
                self.messages.push(MessageLine {
                    author: MessageAuthor::Local,
                    body,
                });
                self.draft_message.clear();
            }
            Err(_) => self.push_system("Mesaj gonderilemedi; baglanti kapanmis olabilir."),
        }
    }

    fn drain_network_events(&mut self) {
        let Some(connection) = &self.connection else {
            return;
        };

        let events: Vec<_> = connection.events.try_iter().collect();
        for event in events {
            match event {
                NetworkEvent::InviteCreated(invite) => {
                    self.current_invite = invite;
                    self.status = "Davet hazir, karsi tarafi bekliyor".to_owned();
                    if self.current_invite.contains("127.0.0.1")
                        || self.current_invite.contains("localhost")
                    {
                        self.push_system(
                            "Bu davet sadece ayni bilgisayarda test icindir. Baska bilgisayar icin Tor modunu ac.",
                        );
                    }
                }
                NetworkEvent::Connected(peer_name) => {
                    self.status = format!("{peer_name} ile sifreli oturum kuruldu");
                    self.peer_name = Some(peer_name);
                    self.push_system(&self.status.clone());
                }
                NetworkEvent::Incoming(body) => {
                    self.messages.push(MessageLine {
                        author: MessageAuthor::Remote,
                        body,
                    });
                }
                NetworkEvent::Disconnected(reason) => {
                    self.status = "Baglanti kapandi".to_owned();
                    self.peer_name = None;
                    self.push_system(&reason);
                }
                NetworkEvent::Error(error) => {
                    self.status = "Hata".to_owned();
                    self.push_system(&error);
                }
            }
        }
    }

    fn push_system(&mut self, body: &str) {
        self.messages.push(MessageLine {
            author: MessageAuthor::System,
            body: body.to_owned(),
        });
    }
}

impl eframe::App for FaunaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_network_events();
        ctx.request_repaint_after(Duration::from_millis(100));

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(15, 20, 28))
                .inner_margin(egui::Margin::symmetric(20.0, 14.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("Fauna")
                                .size(28.0)
                                .strong()
                                .color(egui::Color32::from_rgb(235, 244, 241)),
                        );
                        ui.add_space(14.0);
                        ui.separator();
                        ui.add_space(14.0);
                        status_pill(ui, &self.status);
                    });
                });
        });

        egui::SidePanel::left("setup_panel")
            .resizable(false)
            .exact_width(380.0)
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(18, 24, 33))
                    .inner_margin(egui::Margin::symmetric(18.0, 18.0)),
            )
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    section_title(ui, "Baglanti");

                    field_label(ui, "Gorunen ad");
                    ui.add_sized(
                        [ui.available_width(), 34.0],
                        egui::TextEdit::singleline(&mut self.display_name),
                    );

                    ui.add_space(14.0);
                    ui.checkbox(&mut self.tor_enabled, "Tor modu");

                    if self.tor_enabled {
                        ui.checkbox(&mut self.tor_auto_start, "Tor'u Fauna baslatsin");

                        egui::CollapsingHeader::new("Gelistirilmis Tor ayarlari")
                            .default_open(false)
                            .show(ui, |ui| {
                                field_label(ui, "Paketli tor.exe yolu");
                                ui.add_sized(
                                    [ui.available_width(), 32.0],
                                    egui::TextEdit::singleline(&mut self.tor_exe_path)
                                        .hint_text("Bos birakilabilir"),
                                );
                                field_label(ui, "Tor control");
                                ui.add_sized(
                                    [ui.available_width(), 32.0],
                                    egui::TextEdit::singleline(&mut self.tor_control_addr),
                                );
                                field_label(ui, "Tor SOCKS");
                                ui.add_sized(
                                    [ui.available_width(), 32.0],
                                    egui::TextEdit::singleline(&mut self.tor_socks_addr),
                                );
                                field_label(ui, "Onion port");
                                ui.add_sized(
                                    [ui.available_width(), 32.0],
                                    egui::TextEdit::singleline(&mut self.tor_service_port),
                                );
                            });
                    }

                    ui.add_space(14.0);
                    egui::CollapsingHeader::new("Yerel ag ayarlari")
                        .default_open(!self.tor_enabled)
                        .show(ui, |ui| {
                            field_label(ui, "Host adresi");
                            ui.add_sized(
                                [ui.available_width(), 32.0],
                                egui::TextEdit::singleline(&mut self.bind_addr),
                            );

                            if !self.tor_enabled {
                                field_label(ui, "Paylasilan adres");
                                ui.add_sized(
                                    [ui.available_width(), 32.0],
                                    egui::TextEdit::singleline(&mut self.public_addr),
                                );
                            }
                        });

                    ui.add_space(16.0);
                    if primary_button(ui, "Sohbet Baslat").clicked() {
                        self.start_host();
                    }

                    if !self.current_invite.is_empty() {
                        ui.add_space(16.0);
                        section_title(ui, "Davet linki");
                        ui.add_sized(
                            [ui.available_width(), 92.0],
                            egui::TextEdit::multiline(&mut self.current_invite),
                        );
                        ui.add_space(8.0);
                        if secondary_button(ui, "Davet Linkini Kopyala").clicked() {
                            ui.ctx().copy_text(self.current_invite.clone());
                        }
                    } else if ui
                        .add_sized(
                            [ui.available_width(), 38.0],
                            egui::Button::new("Bu Bilgisayarda Test Ayarla"),
                        )
                        .clicked()
                    {
                        self.bind_addr = "127.0.0.1:45123".to_owned();
                        self.public_addr = "127.0.0.1:45123".to_owned();
                    }

                    ui.add_space(18.0);
                    ui.separator();
                    ui.add_space(16.0);

                    section_title(ui, "Davete Katil");
                    ui.add_sized(
                        [ui.available_width(), 112.0],
                        egui::TextEdit::multiline(&mut self.join_invite)
                            .hint_text("fauna://join/..."),
                    );
                    ui.add_space(8.0);
                    if primary_button(ui, "Baglan").clicked() {
                        self.start_join();
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(11, 15, 21))
                    .inner_margin(egui::Margin::symmetric(22.0, 18.0)),
            )
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    chat_header(ui, self.peer_name.as_deref(), &self.status);
                    ui.add_space(12.0);

                    let message_area_height = (ui.available_height() - 76.0).max(180.0);
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), message_area_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgb(13, 18, 25))
                                .rounding(egui::Rounding::same(12.0))
                                .inner_margin(egui::Margin::symmetric(14.0, 14.0))
                                .show(ui, |ui| {
                                    ui.set_min_size(ui.available_size());
                                    egui::ScrollArea::vertical()
                                        .stick_to_bottom(true)
                                        .auto_shrink([false, false])
                                        .max_height(ui.available_height())
                                        .show(ui, |ui| {
                                            if self.messages.is_empty() {
                                                empty_chat(ui);
                                            }

                                            for message in &self.messages {
                                                message_row(ui, message);
                                                ui.add_space(8.0);
                                            }
                                        });
                                });
                        },
                    );

                    ui.add_space(12.0);
                    if composer(ui, &mut self.draft_message, self.connection.is_some()) {
                        self.send_message();
                    }
                });
            });
    }
}

fn chat_header(ui: &mut egui::Ui, peer_name: Option<&str>, status: &str) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new(peer_name.unwrap_or("Sohbet"))
                    .size(24.0)
                    .strong()
                    .color(egui::Color32::from_rgb(226, 235, 232)),
            );
            ui.label(
                egui::RichText::new(status)
                    .size(14.0)
                    .color(egui::Color32::from_rgb(145, 160, 170)),
            );
        });
    });
}

fn empty_chat(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(
            egui::RichText::new("Mesajlar burada gorunecek")
                .size(18.0)
                .strong()
                .color(egui::Color32::from_rgb(170, 184, 192)),
        );
        ui.label(
            egui::RichText::new("Baglanti kurulduktan sonra alttaki kutudan yazabilirsin.")
                .size(14.0)
                .color(egui::Color32::from_rgb(125, 140, 150)),
        );
    });
}

fn composer(ui: &mut egui::Ui, draft_message: &mut String, can_send: bool) -> bool {
    let mut should_send = false;

    egui::Frame::none()
        .fill(egui::Color32::from_rgb(18, 24, 33))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(10.0, 10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let response = ui.add_enabled(
                    can_send,
                    egui::TextEdit::singleline(draft_message)
                        .hint_text("Mesaj yaz")
                        .desired_width(ui.available_width() - 118.0),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));

                let send_clicked = ui
                    .add_enabled(
                        can_send,
                        egui::Button::new(egui::RichText::new("Gonder").size(16.0).strong())
                            .fill(egui::Color32::from_rgb(35, 122, 106)),
                    )
                    .clicked();

                if send_clicked || enter_pressed {
                    should_send = true;
                }
            });
        });

    should_send
}

fn configure_ui(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 10.0);
    style.visuals = egui::Visuals::dark();
    style.visuals.window_fill = egui::Color32::from_rgb(11, 15, 21);
    style.visuals.panel_fill = egui::Color32::from_rgb(11, 15, 21);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(31, 39, 50);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(43, 55, 68);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(32, 116, 102);
    ctx.set_style(style);

    let mut fonts = egui::FontDefinitions::default();
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default();
    ctx.set_fonts(fonts);
}

fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(20.0)
            .strong()
            .color(egui::Color32::from_rgb(232, 241, 238)),
    );
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        egui::RichText::new(text)
            .size(14.0)
            .color(egui::Color32::from_rgb(164, 177, 188)),
    );
}

fn status_pill(ui: &mut egui::Ui, status: &str) {
    let color = if status.contains("Hata") || status.contains("kapandi") {
        egui::Color32::from_rgb(185, 68, 68)
    } else if status.contains("hazir") || status.contains("kuruldu") {
        egui::Color32::from_rgb(45, 132, 112)
    } else {
        egui::Color32::from_rgb(70, 92, 120)
    };

    egui::Frame::none()
        .fill(color)
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(12.0, 6.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(status)
                    .size(15.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
        });
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 44.0],
        egui::Button::new(egui::RichText::new(text).size(17.0).strong())
            .fill(egui::Color32::from_rgb(35, 122, 106)),
    )
}

fn secondary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_sized(
        [ui.available_width(), 38.0],
        egui::Button::new(egui::RichText::new(text).size(15.0))
            .fill(egui::Color32::from_rgb(39, 49, 63)),
    )
}

fn message_row(ui: &mut egui::Ui, message: &MessageLine) {
    match message.author {
        MessageAuthor::Local => {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                message_bubble(
                    ui,
                    &message.body,
                    egui::Color32::from_rgb(34, 116, 102),
                    egui::Color32::WHITE,
                );
            });
        }
        MessageAuthor::Remote => {
            message_bubble(
                ui,
                &message.body,
                egui::Color32::from_rgb(35, 43, 55),
                egui::Color32::from_rgb(235, 241, 238),
            );
        }
        MessageAuthor::System => {
            ui.centered_and_justified(|ui| {
                ui.label(
                    egui::RichText::new(&message.body)
                        .size(14.0)
                        .color(egui::Color32::from_rgb(137, 150, 160)),
                );
            });
        }
    }
}

fn message_bubble(ui: &mut egui::Ui, body: &str, fill: egui::Color32, text: egui::Color32) {
    egui::Frame::none()
        .fill(fill)
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
        .show(ui, |ui| {
            ui.set_max_width(520.0);
            ui.label(egui::RichText::new(body).size(16.0).color(text));
        });
}

fn start_host_thread(
    name: String,
    bind: String,
    public_addr: String,
    tor_config: Option<TorConfig>,
) -> (Sender<String>, Receiver<NetworkEvent>) {
    let (outbound_tx, outbound_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    thread::spawn(move || {
        if let Err(error) = host_network(
            name,
            bind,
            public_addr,
            tor_config,
            outbound_rx,
            event_tx.clone(),
        ) {
            let _ = event_tx.send(NetworkEvent::Error(error.to_string()));
        }
    });

    (outbound_tx, event_rx)
}

fn start_join_thread(
    name: String,
    invite: String,
    tor_socks_addr: String,
) -> (Sender<String>, Receiver<NetworkEvent>) {
    let (outbound_tx, outbound_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    thread::spawn(move || {
        if let Err(error) =
            join_network(name, invite, tor_socks_addr, outbound_rx, event_tx.clone())
        {
            let _ = event_tx.send(NetworkEvent::Error(error.to_string()));
        }
    });

    (outbound_tx, event_rx)
}

#[derive(Clone)]
struct TorConfig {
    control_addr: String,
    socks_addr: String,
    service_port: u16,
}

fn host_network(
    name: String,
    bind: String,
    public_addr: String,
    tor_config: Option<TorConfig>,
    outbound: Receiver<String>,
    events: Sender<NetworkEvent>,
) -> Result<()> {
    let identity = DeviceIdentity::generate();
    let listener = TcpListener::bind(&bind)
        .with_context(|| format!("{bind} adresinde dinleme baslatilamadi"))?;
    let local_addr = listener.local_addr().context("local adres okunamadi")?;
    let advertised_addr = if let Some(config) = tor_config {
        events
            .send(NetworkEvent::Connected(
                "Tor onion servisi hazirlaniyor".to_owned(),
            ))
            .ok();
        let onion = tor::publish_onion_service(
            &config.control_addr,
            config.service_port,
            &local_addr.to_string(),
        )?;
        format!("onion://{}:{}", onion.service_id, config.service_port)
    } else {
        normalize_direct_public_addr(&public_addr, local_addr.to_string())
    };

    let invite = Invite::new(&identity, &name).with_address(advertised_addr);
    events
        .send(NetworkEvent::InviteCreated(invite.encode()?))
        .ok();

    let (stream, _) = listener.accept().context("baglanti kabul edilemedi")?;
    run_session(stream, identity, name, None, outbound, events)
}

fn join_network(
    name: String,
    invite_text: String,
    tor_socks_addr: String,
    outbound: Receiver<String>,
    events: Sender<NetworkEvent>,
) -> Result<()> {
    let invite = Invite::decode(&invite_text).context("davet linki okunamadi")?;
    let address = invite
        .addresses
        .first()
        .ok_or_else(|| anyhow!("davet linkinde adres yok"))?;
    let stream = connect_to_invite_address(address, &tor_socks_addr)?;
    let identity = DeviceIdentity::generate();

    run_session(
        stream,
        identity,
        name,
        Some(invite.public_key),
        outbound,
        events,
    )
}

fn run_session(
    stream: TcpStream,
    identity: DeviceIdentity,
    display_name: String,
    expected_remote_identity_public_key: Option<String>,
    outbound: Receiver<String>,
    events: Sender<NetworkEvent>,
) -> Result<()> {
    stream.set_nodelay(true).ok();

    let mut writer = stream.try_clone().context("socket klonlanamadi")?;
    let mut reader = BufReader::new(stream);

    let exchange = ExchangeKeypair::generate();
    let hello = create_hello(&identity, display_name, &exchange);
    write_json_line(&mut writer, &hello)?;

    let remote_hello: HelloFrame = read_json_line(&mut reader)?;
    verify_hello(
        &remote_hello,
        expected_remote_identity_public_key.as_deref(),
    )?;

    let session_key = exchange.derive_session_key(&remote_hello.exchange_public_key)?;
    events
        .send(NetworkEvent::Connected(remote_hello.display_name))
        .ok();

    let receive_key = session_key.clone();
    let receive_events = events.clone();
    thread::spawn(move || {
        if let Err(error) = receive_loop(reader, receive_key, receive_events.clone()) {
            let _ = receive_events.send(NetworkEvent::Disconnected(error.to_string()));
        }
    });

    for body in outbound {
        let encrypted = session_key.encrypt(body.as_bytes())?;
        write_json_line(
            &mut writer,
            &ChatFrame {
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext,
            },
        )?;
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct HelloFrame {
    peer_id: PeerId,
    display_name: String,
    identity_public_key: String,
    exchange_public_key: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatFrame {
    nonce: String,
    ciphertext: String,
}

fn create_hello(
    identity: &DeviceIdentity,
    display_name: String,
    exchange: &ExchangeKeypair,
) -> HelloFrame {
    let exchange_public_key = exchange.public_key_base64();
    let signature = identity.sign(exchange_public_key.as_bytes());

    HelloFrame {
        peer_id: identity.peer_id(),
        display_name,
        identity_public_key: identity.public_key_base64(),
        exchange_public_key,
        signature: URL_SAFE_NO_PAD.encode(signature),
    }
}

fn verify_hello(hello: &HelloFrame, expected_public_key: Option<&str>) -> Result<()> {
    if let Some(expected_public_key) = expected_public_key {
        if hello.identity_public_key != expected_public_key {
            bail!("baglanan cihaz davet kimligiyle eslesmedi");
        }
    }

    let public_key = DeviceIdentity::public_key_from_base64(&hello.identity_public_key)?;
    if PeerId::from_public_key(&public_key) != hello.peer_id {
        bail!("peer id public key ile eslesmedi");
    }

    let signature = URL_SAFE_NO_PAD
        .decode(&hello.signature)
        .context("imza okunamadi")?;
    DeviceIdentity::verify(
        &public_key,
        hello.exchange_public_key.as_bytes(),
        &signature,
    )?;

    Ok(())
}

fn receive_loop(
    mut reader: BufReader<TcpStream>,
    key: SessionKey,
    events: Sender<NetworkEvent>,
) -> Result<()> {
    loop {
        let frame: ChatFrame = read_json_line(&mut reader)?;
        let plaintext = key.decrypt(&EncryptedMessage {
            nonce: frame.nonce,
            ciphertext: frame.ciphertext,
        })?;
        events
            .send(NetworkEvent::Incoming(
                String::from_utf8_lossy(&plaintext).into_owned(),
            ))
            .ok();
    }
}

fn write_json_line<T: Serialize>(writer: &mut TcpStream, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_json_line<T: DeserializeOwned>(reader: &mut BufReader<TcpStream>) -> Result<T> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        bail!("karsi taraf baglantiyi kapatti");
    }

    Ok(serde_json::from_str(line.trim_end())?)
}

fn normalize_address(address: &str) -> Result<String> {
    if let Some(rest) = address.strip_prefix("/ip4/") {
        let (host, port) = rest
            .split_once("/tcp/")
            .ok_or_else(|| anyhow!("desteklenmeyen adres formati: {address}"))?;
        return Ok(format!("{host}:{port}"));
    }

    if address.contains(':') {
        return Ok(address.to_owned());
    }

    bail!("desteklenmeyen adres formati: {address}")
}

fn normalize_direct_bind_addr(address: &str) -> String {
    match address {
        "" => "127.0.0.1:45123".to_owned(),
        address if address.contains(':') => address.to_owned(),
        port => format!("127.0.0.1:{port}"),
    }
}

fn normalize_direct_public_addr(address: &str, local_addr: String) -> String {
    match address.trim() {
        "" => local_addr,
        address if address.ends_with(":0") => local_addr,
        address => address.to_owned(),
    }
}

fn connect_to_invite_address(address: &str, tor_socks_addr: &str) -> Result<TcpStream> {
    if let Some(onion_target) = parse_onion_address(address)? {
        return tor::connect_via_socks5_with_retry(
            tor_socks_addr,
            &onion_target.host,
            onion_target.port,
            Duration::from_secs(75),
        );
    }

    let address = normalize_address(address)?;
    if address.starts_with("127.") || address.starts_with("localhost:") {
        bail!(
            "{address} sadece bu bilgisayari gosterir. Baska bilgisayarda kullanmak icin host tarafinda Tor modunu acip yeni davet olustur."
        );
    }

    TcpStream::connect(&address).with_context(|| format!("{address} adresine baglanilamadi"))
}

fn invite_contains_onion_address(invite_text: &str) -> bool {
    Invite::decode(invite_text)
        .map(|invite| {
            invite
                .addresses
                .iter()
                .any(|address| address.contains(".onion"))
        })
        .unwrap_or(false)
}

struct OnionTarget {
    host: String,
    port: u16,
}

fn parse_onion_address(address: &str) -> Result<Option<OnionTarget>> {
    let address = address.strip_prefix("onion://").unwrap_or(address);
    if !address.contains(".onion") {
        return Ok(None);
    }

    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("onion adresinde port yok: {address}"))?;
    let port = port
        .parse()
        .with_context(|| format!("onion port okunamadi: {address}"))?;

    Ok(Some(OnionTarget {
        host: host.to_owned(),
        port,
    }))
}
