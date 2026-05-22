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
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

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
        }
    }

    fn start_host(&mut self) {
        let name = self.display_name.trim().to_owned();
        let bind = self.bind_addr.trim().to_owned();
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
                }
                NetworkEvent::Connected(peer_name) => {
                    self.status = format!("{peer_name} ile sifreli oturum kuruldu");
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
            ui.horizontal(|ui| {
                ui.heading("Fauna");
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::SidePanel::left("setup_panel")
            .resizable(false)
            .exact_width(320.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading("Baglanti");
                ui.add_space(8.0);

                ui.label("Gorunen ad");
                ui.text_edit_singleline(&mut self.display_name);

                ui.add_space(12.0);
                ui.checkbox(&mut self.tor_enabled, "Tor modu");

                if self.tor_enabled {
                    ui.checkbox(&mut self.tor_auto_start, "Tor'u Fauna baslatsin");
                    if self.tor_auto_start {
                        ui.label("Paketli tor.exe yolu (bos birakilabilir)");
                        ui.text_edit_singleline(&mut self.tor_exe_path);
                    }
                    ui.label("Tor control");
                    ui.text_edit_singleline(&mut self.tor_control_addr);
                    ui.label("Tor SOCKS");
                    ui.text_edit_singleline(&mut self.tor_socks_addr);
                    ui.label("Onion port");
                    ui.text_edit_singleline(&mut self.tor_service_port);
                }

                ui.add_space(12.0);
                ui.label("Host adresi");
                ui.text_edit_singleline(&mut self.bind_addr);

                if !self.tor_enabled {
                    ui.label("Paylasilan adres");
                    ui.text_edit_singleline(&mut self.public_addr);
                }

                if ui.button("Sohbet Baslat").clicked() {
                    self.start_host();
                }

                if !self.current_invite.is_empty() {
                    ui.add_space(10.0);
                    ui.label("Davet linki");
                    ui.text_edit_multiline(&mut self.current_invite);
                    if ui.button("Davet Linkini Kopyala").clicked() {
                        ui.ctx().copy_text(self.current_invite.clone());
                    }
                }

                ui.separator();
                ui.heading("Davete Katil");
                ui.text_edit_multiline(&mut self.join_invite);
                if ui.button("Baglan").clicked() {
                    self.start_join();
                }

                ui.separator();
                ui.label("Sunucu yok. Tor modunda davet linki .onion adresi tasir.");
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for message in &self.messages {
                        match message.author {
                            MessageAuthor::Local => {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::TOP),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(&message.body)
                                                .background_color(egui::Color32::from_rgb(
                                                    36, 92, 82,
                                                ))
                                                .color(egui::Color32::WHITE),
                                        );
                                    },
                                );
                            }
                            MessageAuthor::Remote => {
                                ui.label(
                                    egui::RichText::new(&message.body)
                                        .background_color(egui::Color32::from_rgb(55, 59, 68))
                                        .color(egui::Color32::WHITE),
                                );
                            }
                            MessageAuthor::System => {
                                ui.centered_and_justified(|ui| {
                                    ui.label(
                                        egui::RichText::new(&message.body)
                                            .small()
                                            .color(egui::Color32::GRAY),
                                    );
                                });
                            }
                        }
                        ui.add_space(6.0);
                    }
                });

            ui.separator();
            ui.horizontal(|ui| {
                let response = ui.add_sized(
                    [ui.available_width() - 92.0, 36.0],
                    egui::TextEdit::singleline(&mut self.draft_message).hint_text("Mesaj yaz"),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));

                if ui.button("Gonder").clicked() || enter_pressed {
                    self.send_message();
                }
            });
        });
    }
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
        public_addr
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

fn connect_to_invite_address(address: &str, tor_socks_addr: &str) -> Result<TcpStream> {
    if let Some(onion_target) = parse_onion_address(address)? {
        return tor::connect_via_socks5(tor_socks_addr, &onion_target.host, onion_target.port);
    }

    let address = normalize_address(address)?;
    TcpStream::connect(&address).with_context(|| format!("{address} adresine baglanilamadi"))
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
