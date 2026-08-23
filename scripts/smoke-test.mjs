// Geçici duman testi: kullanıcı/çevrimiçi sayaçlarının doğruluğunu kanıtlar.
import { spawn } from 'child_process';
import WebSocket from 'ws';

const PORT = 4599;
const TOKEN = await (async () => {
  const Database = (await import('better-sqlite3')).default;
  const db = new Database('emercall.db');
  const row = db.prepare("SELECT value FROM settings WHERE key='admin_token'").get();
  const channel = db.prepare('SELECT name FROM channels WHERE password IS NULL LIMIT 1').get();
  db.close();
  process.env.TEST_CHANNEL = channel.name;
  return row.value;
})();
const CHANNEL = process.env.TEST_CHANNEL;

const server = spawn(process.execPath, ['serve.mjs'], {
  env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1' },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stderr.on('data', d => process.stderr.write('[srv] ' + d));

const sleep = ms => new Promise(r => setTimeout(r, ms));
await sleep(1500); // sunucunun açılmasını bekle

let failures = 0;
const check = (name, actual, expected) => {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`${ok ? '✅' : '❌'} ${name}: beklenen=${expected} gerçek=${actual}`);
};

// Origin must match the server's allow-list (CSWSH defense) for the handshake
// to succeed, mirroring what a real browser sends for this origin.
const connect = () => new WebSocket(`ws://127.0.0.1:${PORT}`, {
  origin: `http://127.0.0.1:${PORT}`,
});
const nextMessage = (ws, type, timeout = 5000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`timeout waiting ${type}`)), timeout);
  ws.on('message', raw => {
    const msg = JSON.parse(raw.toString());
    if (msg.type === type) { clearTimeout(t); resolve(msg); }
    else if (msg.type === 'error') { clearTimeout(t); reject(new Error('server error: ' + msg.message)); }
  });
});
const stats = async () =>
  (await fetch(`http://127.0.0.1:${PORT}/api/stats`, { headers: { 'X-Admin-Token': TOKEN } })).json();
const users = async () =>
  (await fetch(`http://127.0.0.1:${PORT}/api/users`, { headers: { 'X-Admin-Token': TOKEN } })).json();
const channelsPublic = async () =>
  (await fetch(`http://127.0.0.1:${PORT}/api/channels`)).json();
const channelUsers = async () =>
  (await channelsPublic()).find(c => c.name === CHANNEL)?.users;

let A, B, C, A2;
try {
  // 1) Tek kullanıcı odaya katılır → sayaç 1 olmalı (eski kodda 2 gösteriyordu)
  A = connect();
  const aJoined = nextMessage(A, 'room-joined');
  await new Promise(r => A.on('open', r));
  A.send(JSON.stringify({ type: 'join', room: CHANNEL, username: 'tester-a', deviceId: 'dev-A' }));
  check('Tek kullanıcı oda sayacı (room-joined.userCount)', (await aJoined).userCount, 1);
  check('Kendine oda sayısı duyurusu (room-count.userCount)', (await nextMessage(A, 'room-count')).userCount, 1);
  check('Kanal listesi canlı sayı (/api/channels users)', await channelUsers(), 1);

  // 2) İkinci kullanıcı katılır → herkese 2 duyurulmalı
  B = connect();
  const aSeesJoin = nextMessage(A, 'user-joined');
  const bJoined = nextMessage(B, 'room-joined');
  await new Promise(r => B.on('open', r));
  B.send(JSON.stringify({ type: 'join', room: CHANNEL, username: 'tester-b', deviceId: 'dev-B' }));
  check('İkinci katılım duyurusu (user-joined.userCount)', (await aSeesJoin).userCount, 2);
  await bJoined;

  // 3) B ayrılır → A'ya 1 duyurulmalı (user-left ve room-count ile)
  const aSeesLeft = nextMessage(A, 'user-left');
  const aSeesCount1 = nextMessage(A, 'room-count');
  B.close();
  check('Ayrılma sonrası sayaç (user-left.userCount)', (await aSeesLeft).userCount, 1);
  check('Ayrılma sonrası oda duyurusu (room-count.userCount)', (await aSeesCount1).userCount, 1);
  await sleep(300);

  // 4) Odaya katılmamış soket toplam kullanıcıya etki etmemeli
  C = connect();
  await new Promise(r => C.on('open', r));
  await sleep(200);
  let s = await stats();
  check('Katılmamış soket sayılmıyor (totalClients)', s.totalClients, 1);
  check('Dolu oda sayısı (totalRooms)', s.totalRooms, 1);

  // 5) Aynı cihazdan ikinci bağlantı (duplicate) tekil sayılmalı
  A2 = connect();
  const a2Joined = nextMessage(A2, 'room-joined');
  await new Promise(r => A2.on('open', r));
  A2.send(JSON.stringify({ type: 'join', room: CHANNEL, username: 'tester-a', deviceId: 'dev-A' }));
  await a2Joined;
  await sleep(200);
  s = await stats();
  check('Aynı cihaz tekil sayılıyor (totalClients)', s.totalClients, 1);
  const u = await users();
  check('Çevrimiçi listesi tekil (online.length)', u.online.length, 1);
  A2.close();
  C.close();
  await sleep(300);

  // 6) Son kullanıcı leave ile çıkınca: soket açık kalsa bile ayrıldığı kanalın
  //    sayısını 0 olarak duyurulmalı (kanal listesindeki eski "1 ÇEVRİMİÇİ" hatası)
  const aSeesCount0 = nextMessage(A, 'room-count');
  A.send(JSON.stringify({ type: 'leave' }));
  const rc = await aSeesCount0;
  check('Ayrılan kullanıcıya kanal sayısı 0 duyurulur (room-count)', rc.userCount, 0);
  check('Duyuru doğru kanal için (room-count.roomId)', rc.roomId, CHANNEL);
  await sleep(300);
  s = await stats();
  check('Oda boşaldıktan sonra (totalRooms)', s.totalRooms, 0);
  check('Herkes çıkınca (totalClients)', s.totalClients, 0);
  check('Kanal listesi 0 gösterir (/api/channels users)', await channelUsers(), 0);
  check('Leave sonrası boşta soket sayılmaz (totalClients)', s.totalClients, 0);
} catch (e) {
  failures++;
  console.error('💥 Test hatası:', e.message);
} finally {
  A?.close?.(); B?.close?.(); C?.close?.(); A2?.close?.();
  server.kill();
  await sleep(300);
  console.log(failures === 0 ? '\n🎉 Tüm kontroller geçti' : `\n⚠️ ${failures} kontrol başarısız`);
  process.exit(failures === 0 ? 0 : 1);
}
