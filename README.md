# Oxide

A Discord-style chat app written in Rust, built around one rule: **whoever runs the server shouldn't be able to read your private messages.** That includes me.

- **Server:** [axum](https://github.com/tokio-rs/axum) + Postgres (via [sqlx](https://github.com/launchbadge/sqlx))
- **Client:** native desktop app using [egui](https://github.com/emilk/egui)
- **Encryption:** end-to-end for direct messages, using audited [RustCrypto](https://github.com/RustCrypto) and [dalek](https://github.com/dalek-cryptography) libraries

## Features

- accounts, servers ("guilds") with invite codes, and text channels
- live updates over WebSockets
- end-to-end encrypted direct messages with safety numbers you can compare
- unread markers, auto-reconnect, logout

## How the security works

The server only ever stores things it can't use: public keys, a locked backup of your private key, and ciphertext.

```text
password ─Argon2id─▶ master key ─┬─HKDF─▶ auth key ─▶ sent to server (proves the password, nothing more)
                                 └─HKDF─▶ wrap key ─▶ never leaves your computer; locks your private key

your private key + their public key ─X25519─▶ shared secret ─HKDF─▶ per-conversation key
message ─pad─▶ XChaCha20-Poly1305 ─▶ ciphertext (tied to channel, message id and author)
```

- **Your password never leaves your computer.** The client turns it into two keys with Argon2id (256 MiB, 3 passes). One proves your password to the server. The other unlocks your private key, and the server never sees it.
- **Passwords are hashed twice.** The server hashes the auth key again with Argon2, so a leaked database can't be replayed to log in.
- **Your private key is stored encrypted on the server.** That lets you log in from another computer, but only your password can unlock it.
- **DMs are end-to-end encrypted.** The server rejects plaintext DMs, and the client refuses to send one even if the server misbehaves.
- **Tampering is detected.** If the server moves a message to another chat, replays it, or changes who wrote it, decryption fails.
- **Message length is hidden.** Messages are padded to 256-byte blocks before encryption, so the server only learns a rough size.
- **Safety numbers.** Compare the number shown in a DM with your friend's, in person or on a call. If they match, nobody is intercepting the conversation, including the server.
- **Session tokens are stored hashed** and expire after 30 days.
- **Abuse limits.** Login and register are limited to 10 attempts per IP every 15 minutes, and the number of Argon2 hashes the server runs at once is capped.
- **https required.** The client refuses unencrypted `http://` unless the server is on your own machine.

### What's not protected (yet)

Being honest about this matters more than sounding secure:

- **Guild channels are plaintext.** Anyone with database access can read them. Group encryption (MLS or sender keys) is planned.
- **No forward secrecy.** If someone gets your password, they can unlock your key backup and read your *past* DMs too.
- **Metadata is visible.** The server can see who talks to whom, when, your IP address, and rough message sizes.
- **Weak passwords can be cracked.** Whoever runs the server holds your locked key backup and can try guessing your password offline. Argon2 makes every guess expensive, and the client won't accept weak passwords, but a long passphrase is still your best protection.
- **Key changes are only caught by safety numbers.** The client doesn't remember contacts' keys yet, so a swapped key is only noticed if you compare safety numbers.

## Getting started

You'll need [Rust](https://rustup.rs) (2024 edition) and a Postgres database. A free [Neon](https://neon.tech) database works fine.

### 1. Configure the server

Create a `.env` file in the repo root (it's gitignored):

```env
DATABASE_URL=postgres://user:password@host/dbname?sslmode=require
```

### 2. Run the server

```sh
cargo run -p server
```

Database migrations run automatically on startup. By default the server listens on `http://127.0.0.1:3000`, which is only reachable from your own computer.

### 3. Run the client

```sh
cargo run -p client
```

The client connects to `http://127.0.0.1:3000` unless you tell it otherwise (see below). The first build takes a while; after that it's quick.

## Configuration

| Variable | Used by | What it does |
| --- | --- | --- |
| `DATABASE_URL` | server | Postgres connection string (required) |
| `BIND_ADDR` | server | Address to listen on. Default `127.0.0.1:3000`; use `0.0.0.0:<port>` in the cloud |
| `TRUST_PROXY` | server | Set to `1` when running behind a load balancer that sets `X-Forwarded-For` (most cloud hosts). Otherwise everyone shares one rate limit. Leave it unset if there's no proxy, or clients could fake their IP |
| `RUST_LOG` | server | Log filter. Default `server=debug,info` |
| `OXIDE_SERVER` | client | Server URL. Read at runtime, or at compile time so a release build can include it. Must be `https://` unless it's localhost |

To build a release client that points at your deployed server:

```powershell
$env:OXIDE_SERVER = "https://your-server.example.com"
cargo build --release -p client
```

## Tests

```sh
# unit tests (crypto, padding, fail-closed DMs, rate limiter): no server needed
cargo test --workspace

# live end-to-end test: start the server first, then
cargo test -p client -- --ignored --nocapture
```

The live test logs in two users, sends DMs both ways, and checks what the server actually stores, confirming it never sees plaintext. It also checks that plaintext and unpadded DMs are rejected, that a wrong password fails, that safety numbers match, and that logout really kills the token.

Running the live test a few times in a row can trip the login rate limit. Restarting the server resets it.

## Project layout

```text
shared/   types both sides use (requests, responses, events). The compiler keeps client and server in sync
server/
  src/auth.rs       register, login, logout, session tokens
  src/chat.rs       message history and sending, channel permissions
  src/dms.rs        opening and listing DMs
  src/guilds.rs     guilds, invites, channels
  src/realtime.rs   WebSocket push
  src/limits.rs     rate limiting
  migrations/       SQL, applied automatically on startup
client/
  src/crypto.rs     all the encryption
  src/net.rs        HTTP + WebSocket; encrypts and decrypts so the UI only sees plaintext
  src/app.rs        the egui UI
```

> **Don't edit migration files after they've been applied.** sqlx checksums them and the server will refuse to start. Add a new numbered file instead.

## Roadmap

- [ ] cloud deployment
- [ ] remember contacts' keys and warn when one changes
- [ ] end-to-end encryption for guild channels (MLS or sender keys)
- [ ] forward secrecy
