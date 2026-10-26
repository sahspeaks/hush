'use strict';
/**
 * Hush client.
 *
 * Security model
 * - The room secret (32 random bytes) lives only in the URL fragment (#...), which
 *   browsers never send to the server.
 * - The server only sees roomId = HMAC(secret, "room"), which it cannot reverse.
 * - A room holds a small group connected as a full mesh: every pair of browsers has its
 *   own WebRTC connection. Chat runs over data channels (DTLS) and audio/video over SRTP,
 *   peer-to-peer. There is no media server.
 * - Because the server relays the WebRTC handshakes, it could try to sit in the middle.
 *   We stop that by having each side of every pair send HMAC(secret, role | both DTLS
 *   fingerprints). A middleman doesn't know the secret and sees different fingerprints
 *   on each side, so it cannot produce a valid proof. Nothing is sent to a peer until
 *   it has proven itself.
 * - Audio and video only flow between two people while both have joined the call.
 *   Otherwise the senders have no track at all.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const MAX_LEN = 4000;
  const MAX_NAME = 32;

  const S = {
    key: null, roomId: null, cfg: null,
    ws: null, leaving: false, everJoined: false, reconnectDelay: 1000,
    name: '',
    peers: new Map(), // peer id -> peer state, one RTCPeerConnection each
    inCall: false, joining: false, mic: null, cam: null, muted: false,
    facing: 'user', multiCam: false, camBusy: false, timerInt: null, callStart: 0,
    unread: 0,
  };
  const tiles = new Map(); // 'me' | peer id -> call tile element

  // ---------- helpers ----------
  const b64url = (bytes) => {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const fromB64url = (str) => {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  };
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const hmac = async (label) =>
    new Uint8Array(await crypto.subtle.sign('HMAC', S.key, enc.encode(label)));
  const sha256 = async (text) =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  const equalBytes = (a, b) => {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  };
  const isReady = (p) => p.sentAuth && p.peerAuthed;
  const readyPeers = () => [...S.peers.values()].filter(isReady);
  const cleanName = (n) => (typeof n === 'string' ? n.replace(/\s+/g, ' ').trim().slice(0, MAX_NAME) : '');
  const listNames = (ps) => {
    const names = ps.map((p) => p.name);
    return names.length <= 2 ? names.join(' and ') : `${names.slice(0, -1).join(', ')} and ${names.at(-1)}`;
  };

  function show(id) {
    for (const s of ['landing', 'room', 'fatal']) $(s).hidden = s !== id;
  }
  function setStatus(text, kind) {
    const el = $('status');
    el.textContent = text;
    el.dataset.kind = kind;
  }
  function fatal(msg) {
    S.leaving = true;
    teardown();
    $('fatalMsg').textContent = msg;
    show('fatal');
  }

  // ---------- startup ----------
  async function init() {
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      return fatal('Hush needs a secure connection. Open it over HTTPS (or on localhost).');
    }
    if (!window.RTCPeerConnection) return fatal('This browser does not support WebRTC.');

    const frag = location.hash.slice(1);
    if (!frag) {
      show('landing');
      $('createBtn').addEventListener('click', createRoom);
      return;
    }

    let secret = null;
    try { secret = fromB64url(frag); } catch { /* invalid */ }
    if (!secret || secret.length !== 32) return fatal('That invite link is invalid or incomplete.');

    S.key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    secret.fill(0);
    S.roomId = hex(await hmac('hush/v1/room'));

    try {
      const r = await fetch('/config', { cache: 'no-store' });
      S.cfg = await r.json();
    } catch {
      S.cfg = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }], relayOnly: false };
    }

    S.name = loadName();
    $('nameInput').value = S.name;
    show('room');
    wireUI();
    renderAll();
    setStatus('Connecting…', 'wait');
    connectSignaling();
  }

  function createRoom() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    location.hash = b64url(bytes); // triggers hashchange -> reload
  }
  window.addEventListener('hashchange', () => location.reload());

  function loadName() {
    let n = '';
    try { n = cleanName(localStorage.getItem('hush.name')); } catch { /* storage unavailable */ }
    if (!n) $('people').open = true; // first visit: invite them to pick a name
    return n || `Guest ${Math.floor(1000 + Math.random() * 9000)}`;
  }

  function setName(value) {
    const n = cleanName(value);
    if (n) {
      S.name = n;
      try { localStorage.setItem('hush.name', n); } catch { /* storage unavailable */ }
      broadcast({ t: 'hello', name: S.name });
    }
    $('nameInput').value = S.name;
    renderStage();
  }

  // ---------- signaling (WebSocket) ----------
  function sig(msg) {
    if (S.ws && S.ws.readyState === WebSocket.OPEN) S.ws.send(JSON.stringify(msg));
  }

  function connectSignaling() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    S.ws = ws;
    ws.onopen = () => {
      S.reconnectDelay = 1000;
      ws.send(JSON.stringify({ type: 'join', room: S.roomId }));
    };
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      onSignal(m).catch((err) => console.error('signal error', err));
    };
    ws.onclose = () => {
      if (S.ws !== ws || S.leaving) return;
      S.ws = null;
      if (!readyPeers().length) setStatus('Reconnecting…', 'wait');
      setTimeout(() => { if (!S.leaving && !S.ws) connectSignaling(); }, S.reconnectDelay);
      S.reconnectDelay = Math.min(S.reconnectDelay * 2, 15000);
    };
  }

  async function onSignal(m) {
    const from = typeof m.from === 'string' ? S.peers.get(m.from) : null;
    switch (m.type) {
      case 'joined': {
        // (Re)entered the room with a fresh id: rebuild the mesh. We offer to everyone already here.
        S.everJoined = true;
        for (const p of [...S.peers.values()]) removePeer(p);
        const ids = Array.isArray(m.peers) ? m.peers.filter((id) => typeof id === 'string') : [];
        for (const id of ids) createPeer(id, 'offerer');
        renderAll();
        for (const id of ids) {
          const p = S.peers.get(id);
          if (!p) continue;
          await p.pc.setLocalDescription();
          sig({ type: 'offer', to: id, sdp: p.pc.localDescription });
        }
        break;
      }
      case 'peer-joined':
        if (typeof m.id !== 'string' || S.peers.has(m.id)) return;
        createPeer(m.id, 'answerer');
        renderAll();
        break;
      case 'peer-left': {
        const p = S.peers.get(m.id);
        if (!p) return;
        if (isReady(p)) systemMsg(`${p.name} left.`);
        removePeer(p);
        break;
      }
      case 'offer': {
        if (!from || from.role !== 'answerer' || from.pc.signalingState !== 'stable') return;
        const pc = from.pc;
        await pc.setRemoteDescription(m.sdp);
        for (const t of pc.getTransceivers()) {
          const kind = t.receiver.track.kind;
          if (kind === 'audio' || kind === 'video') {
            t.direction = 'sendrecv';
            if (kind === 'audio') from.sender = t.sender;
            else from.vsender = t.sender;
          }
        }
        await flushIce(from);
        await pc.setLocalDescription();
        sig({ type: 'answer', to: from.id, sdp: pc.localDescription });
        break;
      }
      case 'answer':
        if (!from || from.role !== 'offerer' || from.pc.signalingState !== 'have-local-offer') return;
        await from.pc.setRemoteDescription(m.sdp);
        await flushIce(from);
        break;
      case 'ice':
        if (!from) return;
        if (!from.pc.remoteDescription) from.pendingIce.push(m.candidate);
        else await from.pc.addIceCandidate(m.candidate).catch(() => {});
        break;
      case 'full':
        if (S.everJoined) {
          // Our previous socket may not have been cleaned up yet; retry shortly.
          setStatus('Reconnecting…', 'wait');
          S.ws && S.ws.close();
        } else {
          fatal(`This room is full. Hush rooms hold up to ${Number(m.max) || 6} people.`);
        }
        break;
      case 'error':
        fatal('Could not join this room.');
        break;
      default:
    }
  }

  async function flushIce(p) {
    const list = p.pendingIce;
    p.pendingIce = [];
    for (const c of list) await p.pc.addIceCandidate(c).catch(() => {});
  }

  // ---------- peer connections (one per other person) ----------
  function createPeer(id, role) {
    const pc = new RTCPeerConnection({
      iceServers: S.cfg.iceServers,
      iceTransportPolicy: S.cfg.relayOnly ? 'relay' : 'all',
    });
    const p = {
      id, role, pc, dc: null, pendingIce: [], sender: null, vsender: null,
      sentAuth: false, peerAuthed: false, failed: false, inbox: Promise.resolve(),
      name: 'Someone', greeted: false, code: '',
      call: false, cam: false, muted: false,
      audio: document.createElement('audio'), video: null,
    };
    p.audio.autoplay = true;
    p.audio.muted = true;
    $('audios').append(p.audio);
    S.peers.set(id, p);
    const current = () => S.peers.get(id) === p;

    pc.onicecandidate = (e) => {
      if (current() && e.candidate) sig({ type: 'ice', to: id, candidate: e.candidate.toJSON() });
    };
    pc.ontrack = (e) => {
      if (!current()) return;
      const stream = new MediaStream([e.track]);
      if (e.track.kind === 'video') {
        p.video = stream;
        renderStage();
      } else {
        p.audio.srcObject = stream;
      }
    };
    pc.onconnectionstatechange = () => {
      if (!current()) return;
      const st = pc.connectionState;
      if (st === 'failed' && !p.failed) {
        p.failed = true;
        systemMsg(`Couldn't connect to ${p.name}. One of your networks may block direct connections — the host can add a TURN server to fix this.`);
      } else if (st === 'connected') {
        p.failed = false;
      }
      renderAll();
    };

    if (role === 'offerer') {
      // Both media slots exist from the start, so calls never need renegotiation via the server.
      p.sender = pc.addTransceiver('audio', { direction: 'sendrecv' }).sender;
      p.vsender = pc.addTransceiver('video', { direction: 'sendrecv' }).sender;
    }

    const dc = pc.createDataChannel('hush', { negotiated: true, id: 0, ordered: true });
    p.dc = dc;
    dc.onopen = () => { if (current()) sendAuth(p).catch((err) => authFailed(err)); };
    dc.onmessage = (e) => {
      if (!current()) return;
      // Handle one message at a time so nothing is processed before the auth check finishes.
      p.inbox = p.inbox.then(() => onData(p, e.data)).catch((err) => authFailed(err));
    };
    dc.onclose = () => {
      if (!current()) return;
      if (isReady(p)) systemMsg(`Lost connection to ${p.name}.`);
      removePeer(p);
    };
    return p;
  }

  function removePeer(p) {
    if (S.peers.get(p.id) !== p) return;
    S.peers.delete(p.id);
    if (p.dc) { p.dc.onclose = null; try { p.dc.close(); } catch {} }
    try { p.pc.close(); } catch {}
    p.audio.srcObject = null;
    p.audio.remove();
    renderAll();
  }

  function teardown() {
    leaveCall({ note: null });
    for (const p of [...S.peers.values()]) removePeer(p);
    if (S.ws) { const ws = S.ws; S.ws = null; ws.close(); }
  }

  // ---------- mutual authentication (per pair) ----------
  function fingerprints(sdp) {
    const lines = sdp.match(/^a=fingerprint:.+$/gim) || [];
    return [...new Set(lines.map((l) => l.slice('a=fingerprint:'.length).trim().toUpperCase()))].sort().join(',');
  }

  function sessionBinding(p) {
    const local = fingerprints(p.pc.localDescription.sdp);
    const remote = fingerprints(p.pc.remoteDescription.sdp);
    if (!local || !remote) throw new Error('missing DTLS fingerprint');
    const offer = p.role === 'offerer' ? local : remote;
    const answer = p.role === 'offerer' ? remote : local;
    return `${offer}|${answer}`;
  }

  async function sendAuth(p) {
    const binding = sessionBinding(p);
    const mac = await hmac(`hush/v1/auth|${p.role}|${binding}`);
    p.code = await safetyCode(binding);
    p.dc.send(JSON.stringify({ t: 'auth', mac: b64url(mac) }));
    p.sentAuth = true;
    maybeReady(p);
  }

  async function verifyAuth(p, macB64) {
    if (typeof macB64 !== 'string') throw new Error('bad auth');
    const peerRole = p.role === 'offerer' ? 'answerer' : 'offerer';
    const expected = await hmac(`hush/v1/auth|${peerRole}|${sessionBinding(p)}`);
    let got;
    try { got = fromB64url(macB64); } catch { throw new Error('bad auth'); }
    if (!equalBytes(expected, got)) throw new Error('auth mismatch');
    p.peerAuthed = true;
    maybeReady(p);
  }

  function authFailed(err) {
    console.error(err);
    fatal('Could not verify someone in this room. They don\'t hold the same secret link, or someone tried to intercept the connection. Nothing was sent to them. Create a new room and share the link another way.');
  }

  function maybeReady(p) {
    if (!isReady(p)) return;
    dcSend(p, { t: 'hello', name: S.name });
    dcSend(p, stateMsg());
    syncMedia(p);
    renderAll();
  }

  async function safetyCode(binding) {
    const h = await sha256(`hush/v1/sas|${binding}`);
    const groups = [];
    for (let i = 0; i < 3; i++) {
      groups.push(String(((h[i * 2] << 8) | h[i * 2 + 1]) % 10000).padStart(4, '0'));
    }
    return groups.join(' ');
  }

  // ---------- data channel messages ----------
  function dcSend(p, obj) {
    if (p.dc && p.dc.readyState === 'open') p.dc.send(JSON.stringify(obj));
  }

  function broadcast(obj) {
    for (const p of readyPeers()) dcSend(p, obj);
  }

  async function onData(p, raw) {
    if (typeof raw !== 'string' || raw.length > MAX_LEN * 2 + 200) return;
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'auth') {
      if (p.peerAuthed) return;
      return verifyAuth(p, m.mac);
    }
    if (!p.peerAuthed) return; // ignore everything until this peer has proven itself

    switch (m.t) {
      case 'hello': {
        const name = cleanName(m.name) || 'Someone';
        if (!p.greeted) systemMsg(`${name} is here.`);
        else if (name !== p.name) systemMsg(`${p.name} is now ${name}.`);
        p.greeted = true;
        p.name = name;
        renderAll();
        break;
      }
      case 'msg':
        if (typeof m.text === 'string' && m.text.length > 0 && m.text.length <= MAX_LEN) {
          addMsg('them', m.text, p.name);
        }
        break;
      case 'state': {
        const wasInCall = p.call;
        p.call = m.call === true;
        p.cam = p.call && m.cam === true;
        p.muted = m.muted === true;
        if (p.call !== wasInCall) {
          systemMsg(p.call ? `${p.name} joined the call.` : `${p.name} left the call.`);
          if (p.call && !S.inCall && document.hidden) document.title = '📞 Call in progress · Hush';
        }
        syncMedia(p);
        renderAll();
        break;
      }
      default:
    }
  }

  // ---------- chat UI ----------
  function setComposer(on) {
    $('input').disabled = !on;
    $('sendBtn').disabled = !on;
    $('input').placeholder = on ? 'Write a message…' : 'Waiting for a verified connection…';
  }

  function timeNow() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function addMsg(who, text, name) {
    const li = document.createElement('li');
    li.className = `msg ${who}`;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = text; // never innerHTML: peer text is untrusted
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = name ? `${name} · ${timeNow()}` : timeNow();
    li.append(bubble, meta);
    appendItem(li);
    if (who === 'them' && document.hidden) {
      S.unread++;
      document.title = `(${S.unread}) Hush`;
    }
  }

  function systemMsg(text) {
    const li = document.createElement('li');
    li.className = 'msg sys';
    li.textContent = text;
    appendItem(li);
  }

  function appendItem(li) {
    const list = $('messages');
    const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80;
    list.append(li);
    if (nearBottom || li.classList.contains('me')) list.scrollTop = list.scrollHeight;
  }

  function sendChat() {
    const input = $('input');
    const text = input.value.trim();
    if (!text || !readyPeers().length) return;
    if (text.length > MAX_LEN) return systemMsg(`Messages are limited to ${MAX_LEN} characters.`);
    broadcast({ t: 'msg', text });
    addMsg('me', text);
    input.value = '';
    autosize();
  }

  function autosize() {
    const input = $('input');
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
  }

  // ---------- group call ----------
  async function getMic() {
    if (S.mic) return S.mic;
    S.mic = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
    return S.mic;
  }

  async function getCam() {
    if (S.cam) return S.cam;
    // Modest resolution: in a mesh every camera is uploaded once per participant.
    S.cam = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: S.facing, width: { ideal: 640 }, height: { ideal: 360 }, frameRate: { ideal: 24 } },
    });
    const devices = await navigator.mediaDevices.enumerateDevices().catch(() => []);
    S.multiCam = devices.filter((d) => d.kind === 'videoinput').length > 1;
    return S.cam;
  }

  function stopCam() {
    if (!S.cam) return;
    for (const t of S.cam.getTracks()) t.stop(); // releases the device, camera light goes off
    S.cam = null;
  }

  function releaseMedia() {
    if (S.mic) {
      for (const t of S.mic.getTracks()) t.stop();
      S.mic = null;
    }
    stopCam();
  }

  function micError(err) {
    console.error(err);
    systemMsg(err && err.name === 'NotAllowedError'
      ? 'Microphone access was blocked. Allow it in your browser\'s site settings to join calls.'
      : 'Could not access a microphone.');
  }

  function camError(err) {
    console.error(err);
    systemMsg(err && err.name === 'NotAllowedError'
      ? 'Camera access was blocked. Allow it in your browser\'s site settings to use video.'
      : 'Could not access a camera.');
  }

  function stateMsg() {
    return { t: 'state', call: S.inCall, cam: S.inCall && !!S.cam, muted: S.muted };
  }

  // Send our mic/camera to a peer only while both of us are in the call.
  function syncMedia(p) {
    if (!p.sender || !p.vsender || p.pc.connectionState === 'closed') return;
    const share = S.inCall && p.call && isReady(p);
    const audio = share && S.mic ? S.mic.getAudioTracks()[0] : null;
    const video = share && S.cam ? S.cam.getVideoTracks()[0] : null;
    if (p.sender.track !== audio) p.sender.replaceTrack(audio).catch(() => {});
    if (p.vsender.track !== video) p.vsender.replaceTrack(video).catch(() => {});
  }

  function syncAll() {
    for (const p of S.peers.values()) syncMedia(p);
  }

  async function joinCall(video) {
    if (S.inCall || S.joining) return;
    S.joining = true;
    renderCall();
    try {
      await getMic();
    } catch (err) {
      S.joining = false;
      renderCall();
      return micError(err);
    }
    if (video) await getCam().catch(camError); // no camera: join with voice only
    S.joining = false;
    if (S.leaving) return releaseMedia();
    S.inCall = true;
    S.callStart = Date.now();
    $('timer').textContent = '00:00';
    S.timerInt = setInterval(() => {
      const s = Math.floor((Date.now() - S.callStart) / 1000);
      $('timer').textContent = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    }, 1000);
    setMuted(false);
    syncAll();
    renderAll();
    const others = readyPeers().filter((p) => p.call);
    systemMsg(others.length ? 'You joined the call.' : 'You started a call. Others can join from their call bar.');
  }

  function leaveCall({ note }) {
    if (!S.inCall) return;
    S.inCall = false;
    clearInterval(S.timerInt);
    releaseMedia();
    S.muted = false;
    broadcast(stateMsg());
    syncAll();
    renderAll();
    if (note) systemMsg(note);
  }

  function setMuted(muted) {
    S.muted = muted;
    if (S.mic) for (const t of S.mic.getAudioTracks()) t.enabled = !muted;
    broadcast(stateMsg());
    renderCall();
  }

  // Camera on/off during a call; also turns a voice call into a video call.
  async function toggleCam() {
    if (!S.inCall || S.camBusy) return;
    S.camBusy = true;
    try {
      if (S.cam) stopCam();
      else await getCam();
      if (!S.inCall) stopCam();
    } catch (err) {
      camError(err);
      stopCam();
    } finally {
      S.camBusy = false;
    }
    broadcast(stateMsg());
    syncAll();
    renderAll();
  }

  async function flipCam() {
    if (!S.inCall || !S.cam || S.camBusy) return;
    S.camBusy = true;
    S.facing = S.facing === 'user' ? 'environment' : 'user';
    stopCam(); // many phones can't open both cameras at once
    try {
      await getCam();
      if (!S.inCall) stopCam();
    } catch (err) {
      camError(err);
      stopCam();
      broadcast(stateMsg());
    } finally {
      S.camBusy = false;
      syncAll();
      renderAll();
    }
  }

  // ---------- rendering ----------
  function renderAll() {
    renderStatus();
    setComposer(readyPeers().length > 0);
    renderPeople();
    renderCall();
  }

  function renderStatus() {
    if (!S.everJoined) return;
    const n = readyPeers().length;
    if (n) {
      setStatus(`Connected to ${n} ${n === 1 ? 'person' : 'people'} · end-to-end encrypted`, 'ok');
    } else if ([...S.peers.values()].some((p) => p.failed)) {
      setStatus('Connection failed. Your networks may block direct connections — the host can add a TURN server to fix this.', 'bad');
    } else if (S.peers.size) {
      setStatus('Connecting securely…', 'wait');
    } else {
      setStatus('Waiting for others — send them your invite link.', 'wait');
    }
  }

  function renderPeople() {
    const n = readyPeers().length;
    $('peopleCount').textContent = n ? `${n + 1} people here` : 'Just you';
    const list = $('peopleList');
    list.replaceChildren();
    for (const p of S.peers.values()) {
      const li = document.createElement('li');
      const name = document.createElement('span');
      name.className = 'pname';
      name.textContent = p.name;
      const state = document.createElement('span');
      state.className = 'pstate';
      if (isReady(p)) {
        state.textContent = [p.call && (p.cam ? '🎥 in call' : '📞 in call'), p.call && p.muted && '🔇'].filter(Boolean).join(' ') || 'verified';
      } else {
        state.textContent = p.failed ? 'couldn\'t connect' : 'connecting…';
      }
      const code = document.createElement('span');
      code.className = 'code';
      code.textContent = isReady(p) ? p.code : '';
      li.append(name, state, code);
      list.append(li);
    }
  }

  function renderCall() {
    const others = readyPeers().filter((p) => p.call);
    $('idlecall').hidden = S.inCall;
    $('incall').hidden = !S.inCall;
    $('joinVoice').disabled = S.joining;
    $('joinVideo').disabled = S.joining;
    $('joinVoice').textContent = others.length ? '📞 Join call' : '📞 Voice call';
    $('joinVideo').textContent = others.length ? '🎥 Join with video' : '🎥 Video call';
    $('callInfo').textContent = others.length
      ? `${listNames(others)} ${others.length === 1 ? 'is' : 'are'} in the call`
      : '';

    const mute = $('mute');
    mute.setAttribute('aria-pressed', String(S.muted));
    mute.textContent = S.muted ? 'Unmute' : 'Mute';
    mute.classList.toggle('on', S.muted);
    $('camBtn').textContent = S.cam ? 'Camera off' : 'Camera on';
    $('flipBtn').hidden = !S.cam || !S.multiCam;

    // Only play someone's audio while we're both in the call (they send nothing otherwise).
    for (const p of S.peers.values()) {
      const hear = S.inCall && p.call && isReady(p);
      p.audio.muted = !hear;
      if (hear) p.audio.play().catch(() => {});
    }
    renderStage();
  }

  function makeTile() {
    const el = document.createElement('div');
    el.className = 'tile';
    const video = document.createElement('video');
    video.autoplay = true;
    video.playsInline = true;
    video.muted = true; // audio plays through the per-peer <audio> elements
    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    const label = document.createElement('div');
    label.className = 'label';
    el.append(video, avatar, label);
    return el;
  }

  function renderStage() {
    const stage = $('stage');
    stage.hidden = !S.inCall;
    const want = new Map();
    if (S.inCall) {
      want.set('me', { name: `${S.name} (you)`, stream: S.cam, muted: S.muted, mirror: S.facing === 'user' });
      for (const p of S.peers.values()) {
        if (isReady(p) && p.call) {
          want.set(p.id, { name: p.name, stream: p.cam ? p.video : null, muted: p.muted, mirror: false });
        }
      }
    }
    for (const [key, el] of tiles) {
      if (!want.has(key)) { el.remove(); tiles.delete(key); }
    }
    for (const [key, t] of want) {
      let el = tiles.get(key);
      if (!el) {
        el = makeTile();
        tiles.set(key, el);
        stage.append(el);
      }
      const video = el.querySelector('video');
      if (video.srcObject !== t.stream) video.srcObject = t.stream;
      video.hidden = !t.stream;
      video.classList.toggle('mirror', t.mirror);
      if (t.stream) video.play().catch(() => {});
      const avatar = el.querySelector('.avatar');
      avatar.hidden = !!t.stream;
      avatar.textContent = (t.name[0] || '?').toUpperCase();
      el.querySelector('.label').textContent = t.muted ? `🔇 ${t.name}` : t.name;
    }
    stage.dataset.n = String(want.size);
  }

  // ---------- wiring ----------
  function wireUI() {
    $('composer').addEventListener('submit', (e) => { e.preventDefault(); sendChat(); });
    $('input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendChat(); }
    });
    $('input').addEventListener('input', autosize);

    $('nameInput').addEventListener('change', () => setName($('nameInput').value));
    $('nameInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); $('nameInput').blur(); }
    });

    $('joinVoice').addEventListener('click', () => joinCall(false));
    $('joinVideo').addEventListener('click', () => joinCall(true));
    $('leaveCall').addEventListener('click', () => leaveCall({ note: 'You left the call.' }));
    $('mute').addEventListener('click', () => setMuted(!S.muted));
    $('camBtn').addEventListener('click', toggleCam);
    $('flipBtn').addEventListener('click', flipCam);

    $('copyBtn').addEventListener('click', async () => {
      const btn = $('copyBtn');
      try {
        await navigator.clipboard.writeText(location.href);
        btn.textContent = 'Copied!';
      } catch {
        window.prompt('Copy this invite link:', location.href);
      }
      setTimeout(() => { btn.textContent = 'Copy invite link'; }, 1500);
    });

    $('leaveBtn').addEventListener('click', () => {
      S.leaving = true;
      teardown();
      location.href = '/';
    });

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) { S.unread = 0; document.title = 'Hush — private chat & calls'; }
    });
    window.addEventListener('pagehide', () => leaveCall({ note: null }));
  }

  init().catch((err) => {
    console.error(err);
    fatal('Something went wrong while starting Hush.');
  });
})();
