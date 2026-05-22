# Fauna

Fauna is an early Rust foundation for a peer-to-peer, end-to-end encrypted messaging app. The long-term goal is a lightweight desktop app where the person who starts a chat can use their own computer like a small server, without storing message contents on a central service.

## Current Scope

This repository starts with the parts that should stay independent from any UI:

- `fauna-core`: identity keys, invite encoding, key agreement, and symmetric message encryption primitives.
- `fauna-cli`: a small developer CLI for generating identities and invites while the core is evolving.
- `fauna-desktop`: a native Rust desktop app for hosting or joining direct encrypted chats without a terminal chat UI.

The desktop app uses a native Rust UI instead of Electron or a bundled browser runtime.

## Requirements

Install Rust from:

https://rustup.rs

Then verify:

```powershell
rustc --version
cargo --version
```

## Development

```powershell
cargo test
cargo run -p fauna-desktop
cargo run -p fauna-cli -- identity
cargo run -p fauna-cli -- invite --name "Kivan" --addr "/ip4/192.168.1.10/tcp/45123"
```

## Desktop App

Run the native windowed app:

```powershell
cargo run -p fauna-desktop
```

Inside the app:

1. Enter your display name.
2. Keep `Tor modu` enabled for internet use without port forwarding.
3. Keep `Tor'u Fauna baslatsin` enabled if the package includes `bin/tor/tor.exe`.
4. Click `Sohbet Baslat` and share the generated `fauna://join/...` invite link.
5. On the other device, paste the invite link under `Davete Katil` and click `Baglan`.

If no bundled Tor binary is present, Fauna falls back to the `tor` command on `PATH`. You can also disable auto-start and use Tor Browser ports manually: control `127.0.0.1:9151`, SOCKS `127.0.0.1:9150`.

For direct LAN testing without Tor, disable `Tor modu`, set `Host adresi` to `0.0.0.0:45123`, and set `Paylasilan adres` to the host computer's LAN address, for example `192.168.1.10:45123`.

## Tor Mode

Tor mode creates a temporary onion service for the host and puts its `.onion` address inside the Fauna invite. This avoids router port forwarding and usually works across countries and CGNAT connections.

Fauna still encrypts the chat payload itself:

```text
Tor = reachability and IP privacy
Fauna crypto = message confidentiality
```

If Tor Browser control authentication is not available on your machine, install and run Tor Expert Bundle or configure Tor with a reachable `ControlPort` and `SocksPort`.

## Windows Package

Build and package a downloadable Windows zip:

```powershell
cargo build -p fauna-desktop --release
.\scripts\package-windows.ps1
```

The package is written to:

```text
dist/fauna-windows-x64.zip
```

It contains:

```text
Fauna.exe
bin/tor/tor.exe
README.md
LICENSE
THIRD_PARTY_NOTICES.txt
```

GitHub Actions also includes a `Release` workflow. Run it manually from GitHub Actions to get a downloadable artifact, or push a tag like `v0.1.0` to publish `fauna-windows-x64.zip` as a GitHub Release asset.

## Direct Encrypted Chat

Fauna can run a one-to-one encrypted chat without a central server. The host opens a TCP listener on their own computer and shares the generated invite. The CLI remains useful for development and debugging.

On the host computer:

```powershell
cargo run -p fauna-cli -- host --name "Kivan" --bind "0.0.0.0:45123" --public-addr "192.168.1.10:45123"
```

On the joining computer:

```powershell
cargo run -p fauna-cli -- join --name "Ada" "fauna://join/..."
```

Notes:

- Both devices must be online at the same time.
- On the same Wi-Fi, use the host computer's local IP as `--public-addr`.
- Over the internet, the host needs firewall permission and router port forwarding.
- For internet use without port forwarding, prefer the desktop app's Tor mode.
- Message contents are encrypted before they are written to the socket.

## First GitHub Push

```powershell
git add .
git commit -m "Initial Fauna Rust workspace"
git branch -M main
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

## Architecture Direction

```text
fauna-core
  identity      Ed25519 device identity and peer id derivation
  key_exchange  X25519 session key agreement
  crypto        XChaCha20-Poly1305 local message encryption
  invite        shareable connection invite payloads

future
  network       direct TCP and Tor onion service mode now
  storage       encrypted local SQLite
  desktop       native Rust UI
```

## Security Note

This is a starter foundation, not audited cryptographic software. Before real users rely on Fauna, the protocol design, key exchange, storage encryption, and authentication UX should be reviewed carefully.
