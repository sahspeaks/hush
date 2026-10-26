# Hush

Private group chat, voice and video calls in the browser, for up to 6 people. No accounts, no database, no message history.

## How it works

```
            Browser A
           ╱         ╲        every pair has its own WebRTC connection
   Browser B ───────── Browser C    (DTLS chat + SRTP audio/video, peer-to-peer)

   All browsers ── WebSocket: offer / answer / ICE only ── server
```

Rooms are a **full mesh**: there is no media server, so nothing in the middle ever handles your audio or video. The cost is upload bandwidth: each person sends their camera once per other participant, which is why rooms are capped (6 by default).

1. **Create a room.** The browser generates a 32-byte random secret and puts it in the URL fragment (`/#…`). Browsers never send the fragment to the server.
2. **Share the link** with the people you want, over a channel you trust.
3. Each browser sends the server only `HMAC(secret, "room")` to find the others. The server can't reverse it. The server gives each person a random id; a newcomer sends a WebRTC offer to everyone already in the room.
4. The server relays each pair's WebRTC handshake. Chat, audio and video then flow **directly** between browsers, encrypted by WebRTC (DTLS / SRTP).
5. **Mutual verification, per pair.** Before anything is sent to someone, both sides of that connection prove they know the secret by sending `HMAC(secret, role | both DTLS fingerprints)`. A server trying to sit in the middle doesn't know the secret and sees different fingerprints on each side, so it can't forge this. If verification fails, the app stops.
6. **Calls are join/leave.** Anyone can start a voice or video call; others see who's in it and join when they choose. Audio and video only flow between two people while **both** are in the call; otherwise the senders have no track at all. The microphone and camera are released when you leave the call, and the camera when you turn it off.

Each pair of people shares a 12-digit **safety code**, listed in the people panel. If you and someone read out the same code, nobody is in the middle between you, even if the invite link itself leaked.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
```

Open the page, create a room, and open the invite link in more browser windows (or another device on your network — see HTTPS below).

## Deploy

Browsers only allow microphone and camera access and WebCrypto on **HTTPS** (or localhost), so put it behind TLS, e.g. Caddy:

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
| `TURN_USERNAME`, `TURN_CREDENTIAL` | Fixed TURN credentials from a hosted provider (used with `TURN_URLS` when `TURN_SECRET` isn't set) |
| `RELAY_ONLY=1` | Force all traffic through TURN so participants never learn each other's IP addresses |
| `MAX_PEERS` | People per room (default 6, max 12). Above ~6, video in a mesh gets heavy on phones and slow uplinks |

### TURN (strongly recommended for real use)

Roughly 10–20% of connections (mobile carriers, corporate networks) can't connect directly. A TURN server relays the **already encrypted** traffic; it can't read it. Install [coturn](https://github.com/coturn/coturn) with:

```
use-auth-secret
static-auth-secret=<long random string>
realm=chat.example.com
```

then set `TURN_URLS=turn:turn.example.com:3478,turns:turn.example.com:5349?transport=tcp` and `TURN_SECRET=<same string>`.

## What Hush protects, and what it doesn't

**Protected:** message, audio and video content (from the server, TURN, and the network); room secret; tampering by the server (detected by mutual verification).

**Not protected:**
- **Metadata.** The server sees IP addresses, connection times and how many people shared a room. It keeps no logs, but a malicious host could.
- **IP addresses between peers**, unless `RELAY_ONLY=1` with TURN.
- **The invite link.** Anyone who has it can join the room. Share it privately, and check the people list; compare safety codes for important conversations.
- **Members from each other.** Everyone in a room holds the same secret, so a member who also controls the server could try to sit between two other members. Comparing the safety code for that pair catches it.
- **The code you're served.** Like any web app, a compromised server could serve modified JavaScript. Self-host, or for higher assurance package it as a desktop/mobile app.
- **Endpoint compromise** — screenshots, malware, someone looking over a shoulder.

## Project layout

```
server.js          signaling + static files + security headers (only dependency: ws)
public/index.html  UI
public/app.js      WebRTC mesh, verification, chat, group calls
public/style.css   styles (light & dark)
```

## Ideas for next steps

File sharing over the data channel, larger rooms (needs an SFU such as LiveKit with Insertable Streams E2EE), a PWA wrapper, or push notifications for calls.
