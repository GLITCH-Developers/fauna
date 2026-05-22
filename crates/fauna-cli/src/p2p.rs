use std::{
    io::{self, BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fauna_core::{DeviceIdentity, ExchangeKeypair, Invite, PeerId, SessionKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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

pub fn host(name: String, bind: String, public_addr: Option<String>) -> Result<()> {
    let identity = DeviceIdentity::generate();
    let listener = TcpListener::bind(&bind)
        .with_context(|| format!("could not bind direct chat listener to {bind}"))?;

    let advertised_addr = public_addr.unwrap_or_else(|| bind.clone());
    let invite = Invite::new(&identity, &name).with_address(advertised_addr);

    println!("Fauna direct chat is listening on {bind}");
    println!("Share this invite with the other device:");
    println!("{}", invite.encode()?);
    println!();
    println!("Waiting for one peer...");

    let (stream, remote_addr) = listener.accept().context("could not accept peer")?;
    println!("Peer connected from {remote_addr}");

    run_session(stream, identity, name, None)
}

pub fn join(name: String, invite: String) -> Result<()> {
    let invite = Invite::decode(&invite).context("invalid invite")?;
    let address = invite
        .addresses
        .first()
        .ok_or_else(|| anyhow!("invite does not contain a direct address"))?;
    let address = normalize_address(address)?;

    println!("Connecting to {address}...");
    let stream =
        TcpStream::connect(&address).with_context(|| format!("could not connect to {address}"))?;

    let identity = DeviceIdentity::generate();
    run_session(stream, identity, name, Some(invite.public_key))
}

fn run_session(
    stream: TcpStream,
    identity: DeviceIdentity,
    display_name: String,
    expected_remote_identity_public_key: Option<String>,
) -> Result<()> {
    stream.set_nodelay(true).ok();

    let mut writer = stream.try_clone().context("could not clone stream")?;
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
    println!(
        "Encrypted session established with {}",
        remote_hello.display_name
    );
    println!("Type a message and press Enter. Ctrl+C exits.");

    let read_key = session_key.clone();
    let receive_thread = thread::spawn(move || receive_loop(reader, read_key));
    let send_result = send_loop(writer, session_key);

    if let Err(error) = send_result {
        eprintln!("send loop ended: {error}");
    }

    match receive_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("receive loop ended: {error}"),
        Err(_) => eprintln!("receive loop ended unexpectedly"),
    }

    Ok(())
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
            bail!("remote identity does not match invite");
        }
    }

    let public_key = DeviceIdentity::public_key_from_base64(&hello.identity_public_key)?;
    if PeerId::from_public_key(&public_key) != hello.peer_id {
        bail!("remote peer id does not match public key");
    }

    let signature = URL_SAFE_NO_PAD
        .decode(&hello.signature)
        .context("invalid hello signature encoding")?;
    DeviceIdentity::verify(
        &public_key,
        hello.exchange_public_key.as_bytes(),
        &signature,
    )?;

    Ok(())
}

fn send_loop(mut writer: TcpStream, key: SessionKey) -> Result<()> {
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = line.context("could not read stdin")?;
        if line.trim().is_empty() {
            continue;
        }

        let encrypted = key.encrypt(line.as_bytes())?;
        let frame = ChatFrame {
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        write_json_line(&mut writer, &frame)?;
    }

    Ok(())
}

fn receive_loop(mut reader: BufReader<TcpStream>, key: SessionKey) -> Result<()> {
    loop {
        let frame: ChatFrame = read_json_line(&mut reader)?;
        let plaintext = key.decrypt(&fauna_core::EncryptedMessage {
            nonce: frame.nonce,
            ciphertext: frame.ciphertext,
        })?;
        println!("< {}", String::from_utf8_lossy(&plaintext));
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
        bail!("peer disconnected");
    }

    Ok(serde_json::from_str(line.trim_end())?)
}

fn normalize_address(address: &str) -> Result<String> {
    if let Some(rest) = address.strip_prefix("/ip4/") {
        let (host, rest) = rest
            .split_once("/tcp/")
            .ok_or_else(|| anyhow!("unsupported address format: {address}"))?;
        return Ok(format!("{host}:{rest}"));
    }

    if address.contains(':') {
        return Ok(address.to_owned());
    }

    bail!("unsupported address format: {address}")
}
