# Hush

Private one-to-one chat and voice calls in the browser. No accounts, no database, no message history.

## How it works

```
 Browser A ──── WebRTC (DTLS chat + SRTP audio, peer-to-peer) ──── Browser B
     │                                                                 │
     └──────── WebSocket: offer / answer / ICE only ── server ─────────┘
```

1. **Create a room.** The browser generates a 32-byte random secret and puts it in the URL fragment (`/#…`). Browsers never send the fragment to the server.
2. **Share the link** with one person over a channel you trust.
3. Each browser sends the server only `HMAC(secret, "room")` to find the other. The server can't reverse it.
4. The server relays the WebRTC handshake. Chat and audio then flow **directly** between the two browsers, encrypted by WebRTC (DTLS / SRTP).
5. **Mutual verification.** Before anything is sent, each side proves it knows the secret by sending `HMAC(secret, role | both DTLS fingerprints)`. A server trying to sit in the middle doesn't know the secret and sees different fingerprints on each side, so it can't forge this. If verification fails, the app stops.
6. **Calls need consent.** The audio sender has no track until the callee presses Accept; mic access is released when the call ends.

A 12-digit **safety code** is shown once connected. Reading it aloud on a call confirms nobody is in the middle, even if the invite link itself leaked.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
```

Open the page, create a room, and open the invite link in a second browser window (or another device on your network — see HTTPS below).

## Deploy

Browsers only allow microphone access and WebCrypto on **HTTPS** (or localhost), so put it behind TLS, e.g. Caddy:

```
chat.example.com {
  reverse_proxy localhost:3000
}
```

Environment variables:

| Variable | Purpose |
|---|---|
| `PORT` | Port to listen on (default 3000) |
| `ALLOWED_ORIGINS` | Comma-separated origins allowed to open the WebSocket, e.g. `https://chat.example.com` |
| `TRUST_PROXY=1` | Use `X-Forwarded-For` for per-IP limits (only behind a proxy you control) |
| `HSTS=1` | Send Strict-Transport-Security |
| `STUN_URLS` | STUN servers (default Google's public STUN) |
| `TURN_URLS`, `TURN_SECRET` | Your TURN server and its shared secret (short-lived credentials are generated per visit) |
| `RELAY_ONLY=1` | Force all traffic through TURN so the two users never learn each other's IP address |

### TURN (strongly recommended for real use)

Roughly 10–20% of connections (mobile carriers, corporate networks) can't connect directly. A TURN server relays the **already encrypted** traffic; it can't read it. Install [coturn](https://github.com/coturn/coturn) with:

```
use-auth-secret
static-auth-secret=<long random string>
realm=chat.example.com
```

then set `TURN_URLS=turn:turn.example.com:3478,turns:turn.example.com:5349?transport=tcp` and `TURN_SECRET=<same string>`.

## What Hush protects, and what it doesn't

**Protected:** message and audio content (from the server, TURN, and the network); room secret; tampering by the server (detected by mutual verification).

**Not protected:**
- **Metadata.** The server sees IP addresses, connection times and that two people shared a room. It keeps no logs, but a malicious host could.
- **IP addresses between peers**, unless `RELAY_ONLY=1` with TURN.
- **The invite link.** Anyone who gets it before your contact joins can take the seat. Share it privately; compare the safety code for important conversations.
- **The code you're served.** Like any web app, a compromised server could serve modified JavaScript. Self-host, or for higher assurance package it as a desktop/mobile app.
- **Endpoint compromise** — screenshots, malware, someone looking over a shoulder.

## Project layout

```
server.js          signaling + static files + security headers (only dependency: ws)
public/index.html  UI
public/app.js      WebRTC, verification, chat, calls
public/style.css   styles (light & dark)
```

## Ideas for next steps

Video calls, file sharing over the data channel, group rooms (needs an SFU such as LiveKit with Insertable Streams E2EE), a PWA wrapper, or push notifications for incoming calls.
