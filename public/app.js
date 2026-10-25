'use strict';
/**
 * Hush client.
 *
 * Security model
 * - The room secret (32 random bytes) lives only in the URL fragment (#...), which
 *   browsers never send to the server.
 * - The server only sees roomId = HMAC(secret, "room"), which it cannot reverse.
 * - Chat runs over a WebRTC data channel (DTLS) and audio over SRTP, peer-to-peer.
 * - Because the server relays the WebRTC handshake, it could try to sit in the middle.
 *   We stop that by having each side send HMAC(secret, role | both DTLS fingerprints).
 *   A middleman doesn't know the secret and sees different fingerprints on each side,
 *   so it cannot produce a valid proof. Nothing is sent until both proofs check out.
 * - Audio is only transmitted after the callee clicks Accept. Before that, the audio
 *   sender has no track at all.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const MAX_LEN = 4000;
  const RING_TIMEOUT_MS = 45000;

  const S = {
    key: null, roomId: null, cfg: null,
    ws: null, leaving: false, everJoined: false, reconnectDelay: 1000,
    pc: null, dc: null, role: null, pendingIce: [],
    sentAuth: false, peerAuthed: false,
    call: 'idle', mic: null, sender: null, ringTimer: null, timerInt: null, callStart: 0,
    unread: 0,
  };

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
  const ready = () => S.sentAuth && S.peerAuthed;

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

    show('room');
    wireUI();
    setComposer(false);
    renderCall();
    connectSignaling();
  }

  function createRoom() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    location.hash = b64url(bytes); // triggers hashchange -> reload
  }
  window.addEventListener('hashchange', () => location.reload());

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
      if (!ready()) setStatus('Reconnecting…', 'wait');
      setTimeout(() => { if (!S.leaving && !S.ws) connectSignaling(); }, S.reconnectDelay);
      S.reconnectDelay = Math.min(S.reconnectDelay * 2, 15000);
    };
  }

  async function onSignal(m) {
    switch (m.type) {
      case 'waiting':
        S.everJoined = true;
        resetPeer();
        setStatus('Waiting for the other person — send them your invite link.', 'wait');
        break;
      case 'joined':
        S.everJoined = true;
        resetPeer();
        S.role = 'answerer';
        createPeer();
        setStatus('Connecting securely…', 'wait');
        break;
      case 'peer-joined':
        resetPeer();
        S.role = 'offerer';
        createPeer();
        setStatus('Connecting securely…', 'wait');
        await S.pc.setLocalDescription();
        sig({ type: 'offer', sdp: S.pc.localDescription });
        break;
      case 'peer-left':
        if (ready()) systemMsg('The other person left.');
        resetPeer();
        setStatus('Waiting for the other person…', 'wait');
        break;
      case 'offer': {
        const pc = S.pc;
        if (S.role !== 'answerer' || !pc || pc.signalingState !== 'stable') return;
        await pc.setRemoteDescription(m.sdp);
        for (const t of pc.getTransceivers()) {
          if (t.receiver.track.kind === 'audio') {
            t.direction = 'sendrecv';
            S.sender = t.sender;
          }
        }
        await flushIce();
        await pc.setLocalDescription();
        sig({ type: 'answer', sdp: pc.localDescription });
        break;
      }
      case 'answer':
        if (S.role !== 'offerer' || !S.pc || S.pc.signalingState !== 'have-local-offer') return;
        await S.pc.setRemoteDescription(m.sdp);
        await flushIce();
        break;
      case 'ice':
        if (!S.pc) return;
        if (!S.pc.remoteDescription) S.pendingIce.push(m.candidate);
        else await S.pc.addIceCandidate(m.candidate).catch(() => {});
        break;
      case 'full':
        if (S.everJoined) {
          // Our previous socket may not have been cleaned up yet; retry shortly.
          setStatus('Reconnecting…', 'wait');
          S.ws && S.ws.close();
        } else {
          fatal('This room already has two people in it. Hush rooms are strictly one-to-one.');
        }
        break;
      case 'error':
        fatal('Could not join this room.');
        break;
      default:
    }
  }

  async function flushIce() {
    const list = S.pendingIce;
    S.pendingIce = [];
    for (const c of list) await S.pc.addIceCandidate(c).catch(() => {});
  }

  // ---------- peer connection ----------
  function createPeer() {
    const pc = new RTCPeerConnection({
      iceServers: S.cfg.iceServers,
      iceTransportPolicy: S.cfg.relayOnly ? 'relay' : 'all',
    });
    S.pc = pc;

    pc.onicecandidate = (e) => {
      if (S.pc === pc && e.candidate) sig({ type: 'ice', candidate: e.candidate.toJSON() });
    };
    pc.ontrack = (e) => {
      if (S.pc !== pc) return;
      $('remoteAudio').srcObject = e.streams[0] || new MediaStream([e.track]);
    };
    pc.onconnectionstatechange = () => {
      if (S.pc !== pc) return;
      const st = pc.connectionState;
      if (st === 'failed') {
        endCall({ notify: false, note: 'Call dropped.' });
        setComposer(false);
        setStatus('Connection failed. Your networks may block direct connections — the host can add a TURN server to fix this.', 'bad');
      } else if (st === 'disconnected') {
        setStatus('Connection unstable…', 'wait');
      } else if (st === 'connected' && ready()) {
        setStatus('Connected · end-to-end encrypted', 'ok');
      }
    };

    if (S.role === 'offerer') {
      S.sender = pc.addTransceiver('audio', { direction: 'sendrecv' }).sender;
    }

    const dc = pc.createDataChannel('hush', { negotiated: true, id: 0, ordered: true });
    S.dc = dc;
    dc.onopen = () => { if (S.dc === dc) sendAuth().catch(authFailed); };
    dc.onmessage = (e) => { if (S.dc === dc) onData(e.data).catch(authFailed); };
    dc.onclose = () => {
      if (S.dc !== dc) return;
      setComposer(false);
      endCall({ notify: false, note: 'Call ended.' });
    };
  }

  function resetPeer() {
    endCall({ notify: false, note: ready() ? 'Call ended.' : null });
    if (S.dc) { S.dc.onclose = null; try { S.dc.close(); } catch {} }
    if (S.pc) { try { S.pc.close(); } catch {} }
    Object.assign(S, {
      pc: null, dc: null, role: null, pendingIce: [], sender: null,
      sentAuth: false, peerAuthed: false,
    });
    setComposer(false);
    $('safety').hidden = true;
    renderCall();
  }

  function teardown() {
    resetPeer();
    if (S.ws) { const ws = S.ws; S.ws = null; ws.close(); }
  }

  // ---------- mutual authentication ----------
  function fingerprints(sdp) {
    const lines = sdp.match(/^a=fingerprint:.+$/gim) || [];
    return [...new Set(lines.map((l) => l.slice('a=fingerprint:'.length).trim().toUpperCase()))].sort().join(',');
  }

  function sessionBinding() {
    const pc = S.pc;
    const local = fingerprints(pc.localDescription.sdp);
    const remote = fingerprints(pc.remoteDescription.sdp);
    if (!local || !remote) throw new Error('missing DTLS fingerprint');
    const offer = S.role === 'offerer' ? local : remote;
    const answer = S.role === 'offerer' ? remote : local;
    return `${offer}|${answer}`;
  }

  async function sendAuth() {
    const binding = sessionBinding();
    const mac = await hmac(`hush/v1/auth|${S.role}|${binding}`);
    S.dc.send(JSON.stringify({ t: 'auth', mac: b64url(mac) }));
    S.sentAuth = true;
    await showSafetyCode(binding);
    maybeReady();
  }

  async function verifyAuth(macB64) {
    if (typeof macB64 !== 'string') throw new Error('bad auth');
    const peerRole = S.role === 'offerer' ? 'answerer' : 'offerer';
    const expected = await hmac(`hush/v1/auth|${peerRole}|${sessionBinding()}`);
    let got;
    try { got = fromB64url(macB64); } catch { throw new Error('bad auth'); }
    if (!equalBytes(expected, got)) throw new Error('auth mismatch');
    S.peerAuthed = true;
    maybeReady();
  }

  function authFailed(err) {
    console.error(err);
    fatal('Could not verify the other person. They don\'t hold the same secret link, or someone tried to intercept the connection. Nothing was sent. Create a new room and share the link another way.');
  }

  function maybeReady() {
    if (!ready()) return;
    setComposer(true);
    renderCall();
    $('safety').hidden = false;
    setStatus('Connected · end-to-end encrypted', 'ok');
    systemMsg('Connected and verified. Messages and calls now go directly between your two browsers.');
  }

  async function showSafetyCode(binding) {
    const h = await sha256(`hush/v1/sas|${binding}`);
    const groups = [];
    for (let i = 0; i < 3; i++) {
      groups.push(String(((h[i * 2] << 8) | h[i * 2 + 1]) % 10000).padStart(4, '0'));
    }
    $('safetyCode').textContent = groups.join(' ');
  }

  // ---------- data channel messages ----------
  function dcSend(obj) {
    if (S.dc && S.dc.readyState === 'open') S.dc.send(JSON.stringify(obj));
  }

  async function onData(raw) {
    if (typeof raw !== 'string' || raw.length > MAX_LEN * 2 + 200) return;
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'auth') {
      if (S.peerAuthed) return;
      // Wait until our own description pair is complete (it always is once the channel is open).
      return verifyAuth(m.mac);
    }
    if (!ready()) return; // ignore everything until the peer has proven itself

    switch (m.t) {
      case 'msg':
        if (typeof m.text === 'string' && m.text.length > 0 && m.text.length <= MAX_LEN) {
          addMsg('them', m.text);
        }
        break;
      case 'ring': onRing(); break;
      case 'accept': onAccepted(); break;
      case 'decline': if (S.call === 'outgoing') endCall({ notify: false, note: 'Call declined.' }); break;
      case 'cancel': if (S.call === 'incoming') endCall({ notify: false, note: 'Missed call.' }); break;
      case 'hangup': endCall({ notify: false, note: 'Call ended.' }); break;
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

  function addMsg(who, text) {
    const li = document.createElement('li');
    li.className = `msg ${who}`;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = text; // never innerHTML: peer text is untrusted
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = timeNow();
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
    if (!text || !ready()) return;
    if (text.length > MAX_LEN) return systemMsg(`Messages are limited to ${MAX_LEN} characters.`);
    dcSend({ t: 'msg', text });
    addMsg('me', text);
    input.value = '';
    autosize();
  }

  function autosize() {
    const input = $('input');
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
  }

  // ---------- voice calls ----------
  async function getMic() {
    if (S.mic) return S.mic;
    S.mic = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: false,
    });
    return S.mic;
  }

  function micError(err) {
    console.error(err);
    systemMsg(err && err.name === 'NotAllowedError'
      ? 'Microphone access was blocked. Allow it in your browser\'s site settings to make calls.'
      : 'Could not access a microphone.');
  }

  async function startCall() {
    if (!ready() || S.call !== 'idle') return;
    S.call = 'outgoing';
    renderCall();
    try {
      await getMic(); // ask for permission now, but transmit nothing until accepted
    } catch (err) {
      S.call = 'idle';
      renderCall();
      return micError(err);
    }
    if (S.call !== 'outgoing') return;
    dcSend({ t: 'ring' });
    S.ringTimer = setTimeout(() => {
      if (S.call === 'outgoing') endCall({ notify: true, note: 'No answer.' });
    }, RING_TIMEOUT_MS);
  }

  function onRing() {
    if (S.call === 'idle') {
      S.call = 'incoming';
      renderCall();
      systemMsg('Incoming voice call…');
      if (document.hidden) document.title = '📞 Incoming call · Hush';
    } else if (S.call === 'outgoing' && S.role === 'answerer') {
      // Both pressed call at the same time: one side accepts automatically.
      acceptCall();
    }
  }

  async function acceptCall() {
    if (S.call !== 'incoming' && S.call !== 'outgoing') return;
    try {
      await getMic();
    } catch (err) {
      micError(err);
      return endCall({ notify: true, note: null });
    }
    await S.sender.replaceTrack(S.mic.getAudioTracks()[0]);
    dcSend({ t: 'accept' });
    goLive();
  }

  async function onAccepted() {
    if (S.call !== 'outgoing' || !S.mic) return;
    await S.sender.replaceTrack(S.mic.getAudioTracks()[0]);
    goLive();
  }

  function goLive() {
    clearTimeout(S.ringTimer);
    S.call = 'live';
    const audio = $('remoteAudio');
    audio.muted = false;
    audio.play().catch(() => {});
    S.callStart = Date.now();
    $('timer').textContent = '00:00';
    S.timerInt = setInterval(() => {
      const s = Math.floor((Date.now() - S.callStart) / 1000);
      $('timer').textContent = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    }, 1000);
    setMuted(false);
    renderCall();
    systemMsg('Call connected.');
  }

  function endCall({ notify, note }) {
    if (S.call === 'idle') return;
    if (notify) {
      const kind = { outgoing: 'cancel', incoming: 'decline', live: 'hangup' }[S.call];
      dcSend({ t: kind });
    }
    clearTimeout(S.ringTimer);
    clearInterval(S.timerInt);
    if (S.sender && S.pc && S.pc.connectionState !== 'closed') {
      S.sender.replaceTrack(null).catch(() => {});
    }
    if (S.mic) {
      for (const t of S.mic.getTracks()) t.stop();
      S.mic = null;
    }
    $('remoteAudio').muted = true;
    S.call = 'idle';
    renderCall();
    if (note) systemMsg(note);
  }

  function setMuted(muted) {
    if (S.mic) for (const t of S.mic.getAudioTracks()) t.enabled = !muted;
    const b = $('mute');
    b.setAttribute('aria-pressed', String(muted));
    b.textContent = muted ? 'Unmute' : 'Mute';
    b.classList.toggle('on', muted);
  }

  function renderCall() {
    $('callBtn').hidden = S.call !== 'idle';
    $('callBtn').disabled = !ready();
    $('outgoing').hidden = S.call !== 'outgoing';
    $('incoming').hidden = S.call !== 'incoming';
    $('incall').hidden = S.call !== 'live';
  }

  // ---------- wiring ----------
  function wireUI() {
    $('composer').addEventListener('submit', (e) => { e.preventDefault(); sendChat(); });
    $('input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendChat(); }
    });
    $('input').addEventListener('input', autosize);

    $('callBtn').addEventListener('click', startCall);
    $('cancel').addEventListener('click', () => endCall({ notify: true, note: 'Call cancelled.' }));
    $('accept').addEventListener('click', acceptCall);
    $('decline').addEventListener('click', () => endCall({ notify: true, note: 'Call declined.' }));
    $('hangup').addEventListener('click', () => endCall({ notify: true, note: 'Call ended.' }));
    $('mute').addEventListener('click', () => {
      setMuted($('mute').getAttribute('aria-pressed') !== 'true');
    });

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
      endCall({ notify: true, note: null });
      S.leaving = true;
      teardown();
      location.href = '/';
    });

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) { S.unread = 0; document.title = 'Hush — private chat & calls'; }
    });
    window.addEventListener('pagehide', () => {
      if (S.call !== 'idle') endCall({ notify: true, note: null });
    });
  }

  init().catch((err) => {
    console.error(err);
    fatal('Something went wrong while starting Hush.');
  });
})();
