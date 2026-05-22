use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct OnionService {
    pub service_id: String,
}

pub struct TorRuntime {
    child: Child,
    control_addr: String,
    socks_addr: String,
    data_dir: PathBuf,
}

impl TorRuntime {
    pub fn control_addr(&self) -> &str {
        &self.control_addr
    }

    pub fn socks_addr(&self) -> &str {
        &self.socks_addr
    }
}

impl Drop for TorRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

pub fn start_managed_tor(exe_hint: Option<&str>) -> Result<TorRuntime> {
    let tor_exe = find_tor_executable(exe_hint)?;
    let socks_port = reserve_local_port()?;
    let control_port = reserve_local_port()?;
    let socks_addr = format!("127.0.0.1:{socks_port}");
    let control_addr = format!("127.0.0.1:{control_port}");
    let data_dir = env::temp_dir().join(format!("fauna-tor-{}", std::process::id()));

    if data_dir.exists() {
        fs::remove_dir_all(&data_dir).ok();
    }
    fs::create_dir_all(&data_dir)?;

    let child = spawn_tor(&tor_exe, &data_dir, socks_port, control_port)?;
    wait_for_port(&socks_addr, Duration::from_secs(45))
        .with_context(|| format!("Tor SOCKS port hazir olmadi: {socks_addr}"))?;
    wait_for_port(&control_addr, Duration::from_secs(10))
        .with_context(|| format!("Tor control port hazir olmadi: {control_addr}"))?;
    wait_for_bootstrap(&control_addr, Duration::from_secs(90))
        .with_context(|| "Tor ag baglantisi hazir olmadi")?;

    Ok(TorRuntime {
        child,
        control_addr,
        socks_addr,
        data_dir,
    })
}

pub fn publish_onion_service(
    control_addr: &str,
    virtual_port: u16,
    local_addr: &str,
) -> Result<OnionService> {
    let mut control = TorControl::connect(control_addr)?;
    control.authenticate()?;

    let lines = control.command(&format!(
        "ADD_ONION NEW:ED25519-V3 Port={virtual_port},{local_addr}"
    ))?;

    let service_id = lines
        .iter()
        .find_map(|line| line.strip_prefix("250-ServiceID="))
        .ok_or_else(|| anyhow!("Tor onion service id donmedi"))?
        .trim()
        .to_owned();

    Ok(OnionService {
        service_id: format!("{service_id}.onion"),
    })
}

pub fn connect_via_socks5(socks_addr: &str, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(socks_addr)
        .with_context(|| format!("Tor SOCKS adresine baglanilamadi: {socks_addr}"))?;

    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response)?;
    if response != [0x05, 0x00] {
        bail!("Tor SOCKS kimliksiz baglantiyi kabul etmedi");
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > u8::MAX as usize {
        bail!("onion host cok uzun");
    }

    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request)?;

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        bail!(
            "Tor SOCKS baglantisi reddedildi: {}",
            socks_reply_message(header[1])
        );
    }

    match header[3] {
        0x01 => {
            let mut skip = [0_u8; 6];
            stream.read_exact(&mut skip)?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            let mut skip = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut skip)?;
        }
        0x04 => {
            let mut skip = [0_u8; 18];
            stream.read_exact(&mut skip)?;
        }
        _ => bail!("Tor SOCKS bilinmeyen adres tipi dondu"),
    }

    Ok(stream)
}

pub fn connect_via_socks5_with_retry(
    socks_addr: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    let started = Instant::now();
    let mut last_error = None;

    while started.elapsed() < timeout {
        match connect_via_socks5(socks_addr, host, port) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_secs(2));
            }
        }
    }

    match last_error {
        Some(error) => Err(error)
            .with_context(|| format!("{host}:{port} onion adresine Tor uzerinden baglanilamadi")),
        None => bail!("{host}:{port} onion adresine Tor uzerinden baglanilamadi"),
    }
}

struct TorControl {
    reader: BufReader<TcpStream>,
}

impl TorControl {
    fn connect(control_addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(control_addr)
            .with_context(|| format!("Tor control port baglantisi kurulamadi: {control_addr}"))?;
        Ok(Self {
            reader: BufReader::new(stream),
        })
    }

    fn authenticate(&mut self) -> Result<()> {
        if self.command("AUTHENTICATE").is_ok() {
            return Ok(());
        }

        let cookie = read_control_cookie()?;
        self.authenticate_safe_cookie(&cookie)
    }

    fn authenticate_safe_cookie(&mut self, cookie: &[u8]) -> Result<()> {
        let mut client_nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut client_nonce);

        let lines = self.command(&format!(
            "AUTHCHALLENGE SAFECOOKIE {}",
            hex_encode(&client_nonce)
        ))?;
        let challenge = lines
            .iter()
            .find(|line| line.starts_with("250 AUTHCHALLENGE"))
            .or_else(|| {
                lines
                    .iter()
                    .find(|line| line.starts_with("250-AUTHCHALLENGE"))
            })
            .ok_or_else(|| anyhow!("Tor SAFECOOKIE challenge donmedi"))?;

        let server_hash = read_field(challenge, "SERVERHASH=")?;
        let server_nonce = hex_decode(read_field(challenge, "SERVERNONCE=")?)?;
        let expected_server_hash = safe_cookie_hmac(
            b"Tor safe cookie authentication server-to-controller hash",
            cookie,
            &client_nonce,
            &server_nonce,
        )?;

        if !server_hash.eq_ignore_ascii_case(&hex_encode(&expected_server_hash)) {
            bail!("Tor SAFECOOKIE server hash dogrulanamadi");
        }

        let client_hash = safe_cookie_hmac(
            b"Tor safe cookie authentication controller-to-server hash",
            cookie,
            &client_nonce,
            &server_nonce,
        )?;
        self.command(&format!("AUTHENTICATE {}", hex_encode(&client_hash)))?;
        Ok(())
    }

    fn command(&mut self, command: &str) -> Result<Vec<String>> {
        let stream = self.reader.get_mut();
        stream.write_all(command.as_bytes())?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;

        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let bytes = self.reader.read_line(&mut line)?;
            if bytes == 0 {
                bail!("Tor control port kapandi");
            }

            let line = line.trim_end().to_owned();
            let done = line.starts_with("250 ");
            let error = line.starts_with("5") || line.starts_with("4");
            lines.push(line);

            if done {
                return Ok(lines);
            }

            if error {
                bail!("Tor control komutu basarisiz: {}", lines.join(" | "));
            }
        }
    }
}

fn wait_for_bootstrap(control_addr: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();

    while started.elapsed() < timeout {
        let mut control = TorControl::connect(control_addr)?;
        control.authenticate()?;
        let lines = control.command("GETINFO status/bootstrap-phase")?;
        if lines
            .iter()
            .any(|line| line.contains("PROGRESS=100") || line.contains("SUMMARY=\"Done\""))
        {
            return Ok(());
        }

        thread::sleep(Duration::from_secs(1));
    }

    bail!("Tor bootstrap zaman asimina ugradi")
}

fn socks_reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "genel SOCKS sunucu hatasi",
        0x02 => "kurallar baglantiya izin vermedi",
        0x03 => "ag erisilemiyor",
        0x04 => "hedef erisilemiyor; onion servisi henuz yayilmamis olabilir",
        0x05 => "baglanti reddedildi; host tarafinda sohbet henuz dinlemiyor olabilir",
        0x06 => "TTL suresi doldu",
        0x07 => "komut desteklenmiyor",
        0x08 => "adres tipi desteklenmiyor",
        _ => "bilinmeyen SOCKS hatasi",
    }
}

fn find_tor_executable(exe_hint: Option<&str>) -> Result<PathBuf> {
    if let Some(exe_hint) = exe_hint {
        let path = PathBuf::from(exe_hint);
        if path.exists() {
            return Ok(path);
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(app_dir) = exe.parent() {
            for relative in bundled_tor_candidates() {
                let path = app_dir.join(relative);
                if path.exists() {
                    return Ok(path);
                }
            }
        }
    }

    for relative in bundled_tor_candidates() {
        let path = PathBuf::from(relative);
        if path.exists() {
            return Ok(path);
        }
    }

    Ok(PathBuf::from("tor"))
}

fn bundled_tor_candidates() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            "bin/tor/tor.exe",
            "tor/tor.exe",
            "Browser/TorBrowser/Tor/tor.exe",
        ]
    } else {
        &["bin/tor/tor", "tor/tor"]
    }
}

fn reserve_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn spawn_tor(tor_exe: &Path, data_dir: &Path, socks_port: u16, control_port: u16) -> Result<Child> {
    let mut command = Command::new(tor_exe);
    command
        .arg("--SocksPort")
        .arg(format!("127.0.0.1:{socks_port}"))
        .arg("--ControlPort")
        .arg(format!("127.0.0.1:{control_port}"))
        .arg("--CookieAuthentication")
        .arg("0")
        .arg("--DataDirectory")
        .arg(data_dir)
        .arg("--AvoidDiskWrites")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }

    command
        .spawn()
        .with_context(|| format!("Tor baslatilamadi: {}", tor_exe.display()))
}

fn wait_for_port(addr: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    bail!("{addr} zamaninda acilmadi")
}

fn read_control_cookie() -> Result<Vec<u8>> {
    for path in candidate_cookie_paths() {
        if path.exists() {
            return fs::read(&path)
                .with_context(|| format!("Tor control cookie okunamadi: {}", path.display()));
        }
    }

    bail!(
        "Tor control kimlik dogrulamasi gerekiyor ama cookie bulunamadi. Tor Browser veya Tor Expert Bundle calisiyor mu?"
    )
}

fn candidate_cookie_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(appdata) = env::var("APPDATA") {
        let appdata = PathBuf::from(appdata);
        paths.push(appdata.join("tor").join("control_auth_cookie"));
        paths.push(
            appdata
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Tor")
                .join("control_auth_cookie"),
        );
    }

    if let Ok(localappdata) = env::var("LOCALAPPDATA") {
        paths.push(
            PathBuf::from(localappdata)
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Tor")
                .join("control_auth_cookie"),
        );
    }

    if let Ok(userprofile) = env::var("USERPROFILE") {
        let userprofile = PathBuf::from(userprofile);
        paths.push(
            userprofile
                .join("Desktop")
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Tor")
                .join("control_auth_cookie"),
        );
        paths.push(
            userprofile
                .join("OneDrive")
                .join("Desktop")
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Tor")
                .join("control_auth_cookie"),
        );
        paths.push(
            userprofile
                .join("OneDrive")
                .join("Masaüstü")
                .join("Tor Browser")
                .join("Browser")
                .join("TorBrowser")
                .join("Data")
                .join("Tor")
                .join("control_auth_cookie"),
        );
    }

    paths.push(PathBuf::from("control_auth_cookie"));
    paths
}

fn safe_cookie_hmac(
    label: &[u8],
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(label)?;
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn read_field<'a>(line: &'a str, name: &str) -> Result<&'a str> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(name))
        .ok_or_else(|| anyhow!("Tor yanitinda {name} alani yok"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        bail!("hex veri tek uzunlukta");
    }

    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).context("hex okunamadi"))
        .collect()
}
