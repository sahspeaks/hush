'use strict';
/**
 * Hush signaling server.
 *
 * This server never sees chat messages, audio, or the room secret.
 * It only:
 *   1. serves the static web app,
 *   2. groups up to MAX_PEERS browsers that present the same room id (an HMAC of the secret),
 *   3. relays WebRTC offer/answer/ICE messages between each pair of them (a full mesh).
 * After that, all chat, audio and video flows peer-to-peer, encrypted with DTLS/SRTP.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const MAX_CONN_PER_IP = Number(process.env.MAX_CONN_PER_IP) || 20;
// Every browser uploads its media to every other one, so keep groups small.
const MAX_PEERS = Math.min(Math.max(Number(process.env.MAX_PEERS) || 6, 2), 12);

// Token-bucket rate limit per socket (ICE gathering bursts a few dozen messages per peer).
const BUCKET_MAX = 200;
const REFILL_PER_SEC = 20;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' ws: wss:",
    "media-src 'self' blob: mediastream:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'microphone=(self), camera=(self), geolocation=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
};
if (process.env.HSTS === '1') {
  SECURITY_HEADERS['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
}

/**
 * ICE servers handed to the browser.
 * TURN credentials are short-lived (coturn "use-auth-secret" / TURN REST API),
 * so a leaked credential expires after an hour.
 */
function iceConfig() {
  const iceServers = [{
    urls: (process.env.STUN_URLS || 'stun:stun.l.google.com:19302').split(',').map((s) => s.trim()),
  }];
  if (process.env.TURN_URLS && process.env.TURN_SECRET) {
    const username = `${Math.floor(Date.now() / 1000) + 3600}:hush`;
    const credential = crypto.createHmac('sha1', process.env.TURN_SECRET).update(username).digest('base64');
    iceServers.push({
      urls: process.env.TURN_URLS.split(',').map((s) => s.trim()),
      username,
      credential,
    });
  } else if (process.env.TURN_URLS && process.env.TURN_USERNAME && process.env.TURN_CREDENTIAL) {
    // Static credentials (hosted TURN providers like Metered). Visible to every visitor.
    iceServers.push({
      urls: process.env.TURN_URLS.split(',').map((s) => s.trim()),
      username: process.env.TURN_USERNAME,
      credential: process.env.TURN_CREDENTIAL,
    });
  }
  // RELAY_ONLY=1 hides users' IP addresses from each other (all traffic via TURN).
  return { iceServers, relayOnly: process.env.RELAY_ONLY === '1' };
}

// ---------- HTTP (static files + /config) ----------
const server = http.createServer((req, res) => {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end();
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    res.writeHead(400);
    return res.end();
  }

  if (pathname === '/config') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(iceConfig()));
  }
  if (pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }

  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(404);
    return res.end();
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
});

// ---------- WebSocket signaling ----------
/** roomId -> Map<peerId, WebSocket> (max MAX_PEERS) */
const rooms = new Map();
/** ip -> open connection count */
const ipCounts = new Map();

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });

function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (typeof xf === 'string' && xf) return xf.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function send(ws, msg) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}

function allow(ws) {
  const now = Date.now();
  ws.tokens = Math.min(BUCKET_MAX, ws.tokens + ((now - ws.lastRefill) / 1000) * REFILL_PER_SEC);
  ws.lastRefill = now;
  if (ws.tokens < 1) return false;
  ws.tokens -= 1;
  return true;
}

function join(ws, room) {
  if (ws.room) return;
  if (typeof room !== 'string' || !/^[0-9a-f]{64}$/.test(room)) {
    return send(ws, { type: 'error', message: 'bad room id' });
  }
  let members = rooms.get(room);
  if (!members) {
    members = new Map();
    rooms.set(room, members);
  }
  if (members.size >= MAX_PEERS) return send(ws, { type: 'full', max: MAX_PEERS });

  const id = crypto.randomBytes(8).toString('hex');
  send(ws, { type: 'joined', id, peers: [...members.keys()] }); // the newcomer makes the offers
  for (const p of members.values()) send(p, { type: 'peer-joined', id });
  members.set(id, ws);
  ws.room = room;
  ws.id = id;
}

function leave(ws) {
  if (!ws.room) return;
  const members = rooms.get(ws.room);
  if (members) {
    members.delete(ws.id);
    if (members.size === 0) rooms.delete(ws.room);
    else for (const p of members.values()) send(p, { type: 'peer-left', id: ws.id });
  }
  ws.room = null;
  ws.id = null;
}

/** Forward a handshake message to one other member of the same room. */
function relay(ws, to, msg) {
  if (!ws.room || typeof to !== 'string' || to === ws.id) return;
  const target = rooms.get(ws.room)?.get(to);
  if (target) send(target, { ...msg, from: ws.id });
}

wss.on('connection', (ws, req) => {
  if (ALLOWED_ORIGINS.length && !ALLOWED_ORIGINS.includes(req.headers.origin)) {
    return ws.close(1008, 'Origin not allowed');
  }
  const ip = clientIp(req);
  const count = (ipCounts.get(ip) || 0) + 1;
  if (count > MAX_CONN_PER_IP) return ws.close(1008, 'Too many connections');
  ipCounts.set(ip, count);

  ws.isAlive = true;
  ws.room = null;
  ws.tokens = BUCKET_MAX;
  ws.lastRefill = Date.now();

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (data, isBinary) => {
    if (isBinary || !allow(ws)) return ws.close(1008, 'Rate limited');
    let m;
    try { m = JSON.parse(data.toString('utf8')); } catch { return; }
    if (!m || typeof m !== 'object') return;

    switch (m.type) {
      case 'join':
        return join(ws, m.room);
      case 'offer':
      case 'answer': {
        const d = m.sdp;
        if (!d || d.type !== m.type || typeof d.sdp !== 'string') return;
        return relay(ws, m.to, { type: m.type, sdp: { type: d.type, sdp: d.sdp } });
      }
      case 'ice': {
        const c = m.candidate;
        if (!c || typeof c !== 'object' || typeof c.candidate !== 'string') return;
        return relay(ws, m.to, {
          type: 'ice',
          candidate: {
            candidate: c.candidate,
            sdpMid: typeof c.sdpMid === 'string' ? c.sdpMid : null,
            sdpMLineIndex: Number.isInteger(c.sdpMLineIndex) ? c.sdpMLineIndex : null,
            usernameFragment: typeof c.usernameFragment === 'string' ? c.usernameFragment : null,
          },
        });
      }
      default:
        // ignore unknown types
    }
  });

  ws.on('close', () => {
    leave(ws);
    const c = (ipCounts.get(ip) || 1) - 1;
    if (c <= 0) ipCounts.delete(ip); else ipCounts.set(ip, c);
  });
  ws.on('error', () => {});
});

// Drop dead connections so rooms free up.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`Hush running on http://localhost:${PORT}`);
});
