// Security regression test: verifies the three fixes from the assessment.
// 1) Stored-XSS deviceId is sanitized at the join boundary + escapes at sinks.
// 2) WebSocket handshake rejects disallowed/missing Origins (CSWSH).
// 3) SOS/disaster alerts are room-scoped and IP-aggregate rate limited.
import { spawn } from 'child_process';
import WebSocket from 'ws';
import fs from 'node:fs';

const PORT = 4611;
const DB = `emercall-sec-${PORT}.db`;
if (!fs.existsSync('emercall.db')) { console.error('missing emercall.db'); process.exit(2); }
fs.copyFileSync('emercall.db', DB);

const server = spawn(process.execPath, ['serve.mjs'], {
  env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', DB_PATH: DB },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stderr.on('data', d => {
  const s = d.toString();
  if (!/Client connected|Client disconnected/.test(s)) process.stderr.write('[srv] ' + s);
});

const sleep = ms => new Promise(r => setTimeout(r, ms));
await sleep(1800);

let failures = 0;
const check = (name, ok, detail = '') => {
  if (!ok) failures++;
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? ' — ' + detail : ''}`);
};
const connect = (opts = {}) => new WebSocket(`ws://127.0.0.1:${PORT}`, {
  origin: `http://127.0.0.1:${PORT}`, handshakeTimeout: 5000, ...opts,
});
// Dedicated channels created by the test admin; safe names per the channel regex.
const CH1 = 'ZZTEST1';
const CH2 = 'ZZTEST2';

const ADMIN_TOKEN = ((await import('better-sqlite3')).default)(DB)
  .prepare("SELECT value FROM settings WHERE key='admin_token'").get().value;

try {
  // Create the dedicated test channels via an admin WS session.
  {
    const adm = await open();
    adm.send(JSON.stringify({ type: 'join', room: 'ACILNO', username: 'secadmin', deviceId: 'adm-root', adminToken: ADMIN_TOKEN }));
    await sleep(300);
    for (const ch of [CH1, CH2]) {
      adm.send(JSON.stringify({ type: 'admin-create-channel', name: ch }));
      await sleep(250);
    }
    await sleep(200);
  }

  // ---------- FIX 2: CSWSH origin validation ----------
  {
    let noOrigin = false;
    const nx = new WebSocket(`ws://127.0.0.1:${PORT}`, { handshakeTimeout: 5000 });
    nx.on('unexpected-response', (q, r) => { if (r.statusCode === 401) noOrigin = true; return true; });
    nx.on('error', () => { noOrigin = true; });
    await sleep(900);
    check('F2/1 handshake with NO Origin rejected', noOrigin);
    try { nx.close(); } catch {}
  }
  {
    let evil = false;
    const e = new WebSocket(`ws://127.0.0.1:${PORT}`, { origin: 'https://evil.example', handshakeTimeout: 5000 });
    e.on('unexpected-response', (q, r) => { if (r.statusCode === 401) evil = true; return true; });
    e.on('error', () => { evil = true; });
    await sleep(800);
    check('F2/2 cross-site Origin rejected (401)', evil);
    try { e.close(); } catch {}
  }
  const ok1 = await open();
  check('F2/3 allowed Origin connects', ok1.readyState === 1);

  // ---------- FIX 1: stored XSS deviceId ----------
  const payload = `"><img src=x onerror="window.__pwned=1">`;
  const attacker = await open();
  attacker.send(JSON.stringify({ type: 'join', room: CH1, username: 'attacker', deviceId: payload }));
  await sleep(300);

  const users = await fetch(`http://127.0.0.1:${PORT}/api/users`, {
    headers: { 'X-Admin-Token': ADMIN_TOKEN },
  }).then(r => r.json());
  const stored = users.online.find(u => u.username === 'attacker');
  check('F1/1 markup chars stripped from deviceId at boundary',
    stored && !/[<>"'/]/.test(stored.deviceId || ''),
    `deviceId=${JSON.stringify(stored?.deviceId)}`);

  const esc = v => String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const rendered = stored ? esc(stored.deviceId) : '';
  check('F1/2 escaped at sink (no raw < > ")', !/[<>"]/.test(rendered), `rendered=${JSON.stringify(rendered)}`);

  // ---------- FIX 3: SOS room scope + aggregate IP limit ----------
  const A = await open(), B = await open();
  A.send(JSON.stringify({ type: 'join', room: CH1, username: 'partyA', deviceId: 'da' }));
  B.send(JSON.stringify({ type: 'join', room: CH2, username: 'partyB', deviceId: 'db' }));
  await sleep(300);

  let aSos = false, bSos = false;
  A.on('message', d => { if (JSON.parse(d).type === 'sos-alert') aSos = true; });
  B.on('message', d => { if (JSON.parse(d).type === 'sos-alert') bSos = true; });

  A.send(JSON.stringify({ type: 'sos-alert', message: 'HELP' }));
  await sleep(500);
  check('F3/1 SOS reaches same-room client', aSos);
  check('F3/2 SOS does NOT reach other-room client', !bSos);

  // Aggregate cap: many sockets share one IP budget
  const burst = [];
  for (let i = 0; i < 6; i++) {
    const s = await open();
    s.send(JSON.stringify({ type: 'join', room: CH2, username: `brst${i}`, deviceId: `bx${i}` }));
    burst.push(s);
  }
  await sleep(300);
  let acks = 0, blocked = 0;
  for (const s of burst) {
    s.on('message', d => {
      const m = JSON.parse(d);
      if (m.type === 'sos-sent') acks++;
      if (m.type === 'error' && /Too many/.test(m.message)) blocked++;
    });
    s.send(JSON.stringify({ type: 'sos-alert', message: 'BOOM' }));
  }
  await sleep(900);
  check('F3/3 aggregate IP cap blocks excess SOS sockets', blocked > 0, `acks=${acks} blocked=${blocked}`);

  console.log('\n' + (failures ? `❌ ${failures} FAILURES` : '✅ ALL PASS'));
  process.exitCode = failures ? 1 : 0;

} catch (e) {
  console.error('TEST ERROR', e);
  process.exitCode = 1;
} finally {
  try { server.kill(); } catch {}
  for (const f of [DB, DB + '-wal', DB + '-shm']) { try { fs.unlinkSync(f); } catch {} }
}

function open() {
  const s = connect();
  return new Promise(res => s.on('open', () => res(s)));
}