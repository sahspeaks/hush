'use strict';
/**
 * Hush signaling server.
 *
 * This server never sees chat messages, audio, or the room secret.
 * It only:
 *   1. serves the static web app,
 *   2. pairs two browsers that present the same room id (a SHA-256 hash of the secret),
 *   3. relays WebRTC offer/answer/ICE messages between them.
 * After that, all chat and audio flows peer-to-peer, encrypted with DTLS/SRTP.
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

// Token-bucket rate limit per socket (ICE gathering bursts a few dozen messages).
const BUCKET_MAX = 100;
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
  'Permissions-Policy': 'microphone=(self), camera=(), geolocation=(), payment=()',
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
/** roomId -> Set<WebSocket> (max 2) */
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

function peerOf(ws) {
  const set = rooms.get(ws.room);
  if (!set) return null;
  for (const p of set) if (p !== ws) return p;
  return null;
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
  let set = rooms.get(room);
  if (!set) {
    set = new Set();
    rooms.set(room, set);
  }
  if (set.size >= 2) return send(ws, { type: 'full' });

  set.add(ws);
  ws.room = room;
  if (set.size === 1) {
    send(ws, { type: 'waiting' });
  } else {
    send(ws, { type: 'joined' });
    send(peerOf(ws), { type: 'peer-joined' }); // the earlier peer makes the offer
  }
}

function leave(ws) {
  if (!ws.room) return;
  const set = rooms.get(ws.room);
  if (set) {
    set.delete(ws);
    if (set.size === 0) rooms.delete(ws.room);
    else for (const p of set) send(p, { type: 'peer-left' });
  }
  ws.room = null;
}

function relay(ws, msg) {
  if (!ws.room) return;
  send(peerOf(ws), msg);
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
        return relay(ws, { type: m.type, sdp: { type: d.type, sdp: d.sdp } });
      }
      case 'ice': {
        const c = m.candidate;
        if (!c || typeof c !== 'object' || typeof c.candidate !== 'string') return;
        return relay(ws, {
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
