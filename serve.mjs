#!/usr/bin/env node
/**
 * EmercallPlus Intranet PTT Sunucusu
 * GPS koordinat takip sistemi
 * Peer-to-peer ses ağ mesh için WebRTC sinyalleme
 * Kullanıcı yönetimi, kanal şifreleri, cihaz yasakları
 */

import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { networkInterfaces } from 'os';
import { randomBytes, createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = 4000;
const HTTP_PORT = 4000;
const HOST = '0.0.0.0';
const DATA_FILE = join(__dirname, 'data.json');

// Oda yönetimi: { odaAdi: { clientId: ws } }
const rooms = new Map();
// İstemci takibi: { ws: { id, room, username, ip, isAdmin, deviceId, latitude, longitude, lastLocationUpdate } }
const clients = new Map();
// Kanal şifre önbelleği: { odaAdi: passwordHash }
const channelPasswords = new Map();
// Yasaklı varlıklar: { IPs: Set(), deviceIds: Set(), usernames: Set() }
const bannedDeviceIds = new Set();
const bannedUsernames = new Set();
// Odalardaki aktif verici: { odaAdi: clientId }
const activeTransmitters = new Map();

let clientIdCounter = 0;

// Veri yapısı
let appData = {
  adminToken: null,
  adminTokenShown: false,
  users: [],
  channels: [],
  bannedDeviceIds: [],
  bannedUsernames: []
};

// Veriyi başlat veya yükle
async function initData() {
  if (existsSync(DATA_FILE)) {
    try {
      const content = await readFile(DATA_FILE, 'utf-8');
      appData = JSON.parse(content);

      // Eski veri yapılarını taşı
      if (!appData.bannedDeviceIds) appData.bannedDeviceIds = [];
      if (!appData.bannedUsernames) appData.bannedUsernames = [];

      // Belleğe yükle
      appData.bannedDeviceIds.forEach(id => bannedDeviceIds.add(id));
      appData.bannedUsernames.forEach(name => bannedUsernames.add(name));
      appData.channels.forEach(ch => {
        if (ch.password) {
          channelPasswords.set(ch.name, ch.password);
        }
      });

      console.log('📁 Veri data.json dosyasından yüklendi');
      console.log(`   Kanallar: ${appData.channels.length}`);
      console.log(`   Yasaklı cihazlar: ${appData.bannedDeviceIds.length}`);
      console.log(`   Yasaklı kullanıcı adları: ${appData.bannedUsernames.length}`);
    } catch (e) {
      console.error('data.json yüklenirken hata:', e);
    }
  } else {
    // İlk yönetici anahtarını oluştur
    appData.adminToken = randomBytes(24).toString('hex');

    // Varsayılan kanallar
    appData.channels = [
      { name: 'ALFA-1', password: null, createdBy: 'system' },
      { name: 'BRAVO-2', password: null, createdBy: 'system' },
      { name: 'CHARLİ-3', password: null, createdBy: 'system' },
      { name: 'DELTA-4', password: null, createdBy: 'system' },
      { name: 'EKO-5', password: null, createdBy: 'system' }
    ];

    await saveData();
    console.log('📁 Varsayılan verilerle data.json oluşturuldu');
  }

  return appData.adminToken;
}

// Veriyi diske kaydet
async function saveData() {
  try {
    appData.bannedDeviceIds = Array.from(bannedDeviceIds);
    appData.bannedUsernames = Array.from(bannedUsernames);
    await writeFile(DATA_FILE, JSON.stringify(appData, null, 2), 'utf-8');
  } catch (e) {
    console.error('data.json kaydedilirken hata:', e);
  }
}

// Şifreleme
function hashPassword(password) {
  return createHash('sha256').update(password).digest('hex');
}

// Yönetici anahtarı doğrula
function verifyAdminToken(token) {
  return token === appData.adminToken;
}

// Yerel IP adresini al
function getLocalIP() {
  const interfaces = networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// Rate limiting - Basit IP bazlı rate limiter
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 dakika
const RATE_LIMIT_MAX_REQUESTS = 100; // Dakikada 100 istek

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW;
    return true;
  }

  if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }

  record.count++;
  return true;
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.socket.remoteAddress ||
         'unknown';
}

// Input sanitization
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  // XSS önleme - HTML karakterlerini escape et
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function validateChannelName(name) {
  if (!name || typeof name !== 'string') return false;
  // Sadece harf, rakam ve tire, 2-20 karakter
  return /^[A-Z0-9-]{2,20}$/.test(name);
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  // 2-15 karakter, alfanumerik ve bazı özel karakterler
  return /^[a-zA-Z0-9ÇĞİÖŞÜçğıöşu_-]{2,15}$/.test(username);
}

// HTTP sunucusu API uç noktaları ile
const httpServer = createServer(async (req, res) => {
  const clientIP = getClientIP(req);

  // Rate limiting kontrolü
  if (!checkRateLimit(clientIP)) {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Çok fazla istek - lütfen bekleyin' }));
    return;
  }

  // Security Headers (OWASP recommendations)
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(self), microphone=(self)');
  res.removeHeader('X-Powered-By');

  // CORS - Sadece same origin için (intrabet kullanımı)
  const origin = req.headers.origin;
  if (origin && origin === `http://${req.headers.host}` || origin === `http://localhost:${PORT}` || origin === `http://127.0.0.1:${PORT}`) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token, X-Device-ID');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
  res.setHeader('Access-Control-Max-Age', '3600');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  // URL'yi ayrıştır
  const url = new URL(req.url, `http://${req.headers.host}`);

  // GÜVENLİK: Hassas dosyalara erişimi engelle
  if (url.pathname.includes('data.json') ||
      url.pathname.includes('package.json') ||
      url.pathname.includes('.env') ||
      url.pathname.includes('serve.mjs')) {
    res.statusCode = 403;
    res.end('Erişim reddedildi');
    return;
  }

  // Sadece izin verilen dosyalar sunulsun
  if (url.pathname.startsWith('/lib/')) {
    // Leaflet kütüphanesi dosyalarını sun
    const filePath = join(__dirname, url.pathname);
    try {
      const content = await readFile(filePath);
      const ext = url.pathname.split('.').pop();
      const contentType = ext === 'css' ? 'text/css' :
                         ext === 'js' ? 'text/javascript' :
                         ext === 'png' ? 'image/png' : 'application/octet-stream';
      res.setHeader('Content-Type', `${contentType}; charset=utf-8`);
      res.end(content);
      return;
    } catch (err) {
      res.statusCode = 404;
      res.end('Dosya bulunamadı');
      return;
    }
  }

  if (url.pathname !== '/' && url.pathname !== '/index.html' && !url.pathname.startsWith('/api/')) {
    res.statusCode = 404;
    res.end('Bulunamadı');
    return;
  }

  // index.html sun
  if (req.url === '/' || req.url === '/index.html') {
    try {
      const content = await readFile(join(__dirname, 'index.html'), 'utf-8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      // CSP Header ekleyelim
      res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "connect-src 'self' ws: wss:; " +
        "img-src 'self' data: https://unpkg.com https://placehold.co https://*.tile.openstreetmap.org https://*.openstreetmap.org; " +
        "media-src 'self' blob:; " +
        "object-src 'none'; " +
        "base-uri 'self';"
      );
      res.end(content);
    } catch (err) {
      res.statusCode = 500;
      res.end('Sunucu hatası');
    }
    return;
  }

  // API: Kanalları getir
  if (url.pathname === '/api/channels' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(appData.channels));
    return;
  }

  // API: Kanal oluştur (sadece yönetici)
  if (url.pathname === '/api/channels' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Yetkisiz erisim' }));
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));

      // Input validation
      if (!validateChannelName(body.name)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Gecersiz kanal adi' }));
        return;
      }

      if (body.password && typeof body.password !== 'string') {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Gecersiz sifre' }));
        return;
      }

      const channelName = body.name.toUpperCase();

      // Kanal zaten var mı kontrol et
      if (appData.channels.find(ch => ch.name === channelName)) {
        res.statusCode = 409;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Kanal zaten mevcut' }));
        return;
      }

      const channel = {
        name: channelName,
        password: body.password ? hashPassword(body.password) : null,
        createdBy: body.admin || 'admin'
      };
      appData.channels.push(channel);
      if (channel.password) {
        channelPasswords.set(channel.name, channel.password);
      }
      await saveData();

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true, channel: { name: channel.name, hasPassword: !!channel.password } }));
    } catch (e) {
      console.error('Kanal olusturma hatasi:', e);
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Gecersiz istek' }));
    }
    return;
  }

  // API: Kanal sil (sadece yönetici)
  if (url.pathname.startsWith('/api/channels/') && req.method === 'DELETE') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Yetkisiz erisim' }));
      return;
    }

    const channelName = url.pathname.split('/').pop();

    // Input validation - channel name
    if (!validateChannelName(channelName)) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Gecersiz kanal adi' }));
      return;
    }

    appData.channels = appData.channels.filter(ch => ch.name !== channelName);
    channelPasswords.delete(channelName);
    await saveData();

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API: Kanal şifresi belirle (sadece yönetici)
  if (url.pathname === '/api/channels/password' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Yetkisiz erisim' }));
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));

      // Input validation
      if (!validateChannelName(body.name)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Gecersiz kanal adi' }));
        return;
      }

      if (body.password && typeof body.password !== 'string') {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Gecersiz sifre' }));
        return;
      }

      const channel = appData.channels.find(ch => ch.name === body.name);
      if (!channel) {
        res.statusCode = 404;
        res.end('Kanal bulunamadı');
        return;
      }

      if (body.password) {
        channel.password = hashPassword(body.password);
        channelPasswords.set(channel.name, channel.password);
      } else {
        channel.password = null;
        channelPasswords.delete(channel.name);
      }
      await saveData();

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true, hasPassword: !!channel.password }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Geçersiz istek');
    }
    return;
  }

  // API: Yönetici kimlik doğrulama
  if (url.pathname === '/api/auth/admin' && req.method === 'POST') {
    try {
      const body = JSON.parse(await getBody(req));
      const valid = verifyAdminToken(body.token);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ valid }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Geçersiz istek');
    }
    return;
  }

  // API: Kullanıcıları getir (sadece yönetici)
  if (url.pathname === '/api/users' && req.method === 'GET') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Yetkisiz');
      return;
    }

    // Odalardaki çevrimiçi kullanıcıları al
    const onlineUsers = [];
    for (const [roomName, roomClients] of rooms) {
      for (const [id, ws] of Object.entries(roomClients)) {
        const client = clients.get(ws);
        if (client) {
          onlineUsers.push({
            id,
            username: client.username,
            room: roomName,
            deviceId: client.deviceId
          });
        }
      }
    }

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      online: onlineUsers,
      banned: [...appData.bannedDeviceIds, ...appData.bannedUsernames]
    }));
    return;
  }

  // API: Yasakla (sadece yönetici) - sadece cihaz ID ile
  if (url.pathname === '/api/users/ban' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Yetkisiz');
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));
      const deviceId = body.deviceId;

      if (!deviceId) {
        res.statusCode = 400;
        res.end('deviceId gerekli');
        return;
      }

      // Cihaz ID ile yasakla
      bannedDeviceIds.add(deviceId);

      // Yasaklı cihaz kullanıcılarını bağlantısını kes
      for (const [ws, client] of clients) {
        if (client.deviceId === deviceId) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Bu sunucudan yasaklandınız'
          }));
          ws.close(1008, 'Yasaklı');
        }
      }

      await saveData();
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Geçersiz istek');
    }
    return;
  }

  // API: Yasağı kaldır (sadece yönetici)
  if (url.pathname.startsWith('/api/users/ban/') && req.method === 'DELETE') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Yetkisiz');
      return;
    }

    const deviceId = url.pathname.split('/').pop();
    if (bannedDeviceIds.delete(deviceId)) {
      await saveData();
    }

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API: Sunucu istatistikleri
  if (url.pathname === '/api/stats' && req.method === 'GET') {
    const roomStats = [];
    for (const [name, roomClients] of rooms) {
      roomStats.push({
        name,
        users: Object.keys(roomClients).length,
        hasPassword: !!channelPasswords.get(name)
      });
    }

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      totalRooms: rooms.size,
      totalClients: clients.size,
      rooms: roomStats
    }));
    return;
  }

  // API: Kullanıcı konumları (GPS)
  if (url.pathname === '/api/locations' && req.method === 'GET') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Yetkisiz');
      return;
    }

    const locations = [];
    for (const [ws, client] of clients) {
      if (client.room && client.latitude && client.longitude) {
        locations.push({
          userId: client.id,
          username: client.username,
          room: client.room,
          latitude: client.latitude,
          longitude: client.longitude,
          lastUpdate: client.lastLocationUpdate
        });
      }
    }

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ locations }));
    return;
  }

  // API: Yönetici anahtarını al (hoşgeldin ekranında göstermek için)
  // Eğer token yoksa, ilk kullanıcıya oluştur ve göster. Diğer kullanıcılar ekranı görmez.
  if (url.pathname === '/api/admin-token' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');

    // Token yoksa (null veya boş string) oluştur ve ilk kullanıcıya göster
    if (!appData.adminToken || appData.adminToken === '') {
      appData.adminToken = randomBytes(24).toString('hex');
      appData.adminTokenShown = true;
      await saveData();
      res.end(JSON.stringify({ token: appData.adminToken, show: true }));
    } else if (!appData.adminTokenShown) {
      // Token var ama henüz kimseye gösterilmemiş
      appData.adminTokenShown = true;
      await saveData();
      res.end(JSON.stringify({ token: appData.adminToken, show: true }));
    } else {
      // Token zaten oluşturulmuş ve gösterilmiş, başka kullanıcılara gösterme
      res.end(JSON.stringify({ show: false }));
    }
    return;
  }

  res.statusCode = 404;
  res.end('Bulunamadı');
});

// İstek gövdesini alma yardımcısı
function getBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => resolve(data));
  });
}

// WebSocket sunucusu
const wss = new WebSocketServer({ server: httpServer, clientTracking: true });

function broadcastToRoom(room, message, excludeWs = null) {
  const roomClients = rooms.get(room);
  if (!roomClients) return;

  const messageStr = JSON.stringify(message);
  for (const [id, ws] of Object.entries(roomClients)) {
    if (ws !== excludeWs && ws.readyState === 1) {
      ws.send(messageStr);
    }
  }
}

function getRoomUsers(room) {
  const roomClients = rooms.get(room);
  if (!roomClients) return [];
  return Object.entries(roomClients).map(([id, ws]) => {
    const client = clients.get(ws);
    return { id, username: client?.username || `Kullanıcı-${id.slice(0, 4)}` };
  });
}

function getRoomUserCount(room) {
  const roomClients = rooms.get(room);
  return roomClients ? Object.keys(roomClients).length : 0;
}

wss.on('connection', (ws, req) => {
  const clientId = `client_${++clientIdCounter}`;
  clients.set(ws, { id: clientId });

  console.log(`[${new Date().toISOString()}] İstemci bağlandı: ${clientId}`);

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());
      const client = clients.get(ws);

      switch (message.type) {
        case 'join': {
          // Varsa önceki odadan ayrıl
          if (client.room) {
            const oldRoom = rooms.get(client.room);
            if (oldRoom) {
              delete oldRoom[clientId];
              broadcastToRoom(client.room, {
                type: 'user-left',
                userId: clientId
              }, ws);
            }
          }

          // Korumalı kanallar için şifre kontrolü
          const roomPassword = channelPasswords.get(message.room);
          if (roomPassword) {
            if (!message.password || hashPassword(message.password) !== roomPassword) {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Bu kanal için geçersiz şifre'
              }));
              return;
            }
          }

          // Yeni odaya katıl
          const room = message.room || 'default';
          const username = message.username || `Kullanıcı-${clientId.slice(0, 4)}`;
          client.room = room;
          client.username = username;
          client.deviceId = message.deviceId;

          // Kullanıcı adı yasaklı mı kontrol et
          if (bannedUsernames.has(username.toLowerCase())) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Bu sunucudan yasaklandınız'
            }));
            ws.close(1008, 'Yasaklı');
            console.log(`  Yasaklı kullanıcı adı reddedildi: ${username}`);
            return;
          }

          // Cihaz ID yasaklı mı kontrol et
          if (client.deviceId && bannedDeviceIds.has(client.deviceId)) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Bu sunucudan yasaklandınız'
            }));
            ws.close(1008, 'Yasaklı');
            console.log(`  Yasaklı cihaz reddedildi: ${client.deviceId}`);
            return;
          }

          // Yönetici kimlik doğrulaması
          if (message.adminToken && verifyAdminToken(message.adminToken)) {
            client.isAdmin = true;
          }

          if (!rooms.has(room)) {
            rooms.set(room, {});
          }
          rooms.get(room)[clientId] = ws;

          // Yeni istemciye mevcut kullanıcıları gönder
          const roomUsers = getRoomUsers(room);
          const existingUsers = roomUsers.filter(u => u.id !== clientId);
          const totalUserCount = roomUsers.length + 1; // +1 for self

          ws.send(JSON.stringify({
            type: 'room-joined',
            roomId: room,
            yourId: clientId,
            users: existingUsers,
            userCount: totalUserCount,
            isAdmin: client.isAdmin || false
          }));

          // Diğerlerini bilgilendir
          broadcastToRoom(room, {
            type: 'user-joined',
            userId: clientId,
            username: client.username,
            userCount: totalUserCount
          }, ws);

          console.log(`  ${clientId} odaya katıldı: ${room} (${totalUserCount} kullanıcı)`);
          break;
        }

        case 'offer':
        case 'answer':
        case 'ice-candidate': {
          // WebRTC sinyal mesajlarını aktar
          const targetWs = rooms.get(client.room)?.[message.target];
          if (targetWs && targetWs.readyState === 1) {
            targetWs.send(JSON.stringify({
              ...message,
              sender: clientId
            }));
          }
          break;
        }

        case 'speaking': {
          // PTT Mutex - aynı anda sadece bir kişi iletebilir
          const room = client.room;

          if (message.speaking) {
            // İletmeye başlıyor - başka biri zaten iletiyor mu kontrol et
            const currentTx = activeTransmitters.get(room);
            if (currentTx && currentTx !== clientId) {
              // Başka biri iletiyor, isteği reddet
              ws.send(JSON.stringify({
                type: 'tx-busy',
                transmitterId: currentTx
              }));
              break;
            }
            // İletim izni ver
            activeTransmitters.set(room, clientId);
          } else {
            // İletimi durdur - sadece mevcut verici durdurabilir
            const currentTx = activeTransmitters.get(room);
            if (currentTx === clientId) {
              activeTransmitters.delete(room);
            }
          }

          // Konuşma durumunu yay
          broadcastToRoom(room, {
            type: 'user-speaking',
            userId: clientId,
            speaking: message.speaking
          }, ws);
          break;
        }

        case 'leave': {
          if (client.room) {
            const roomData = rooms.get(client.room);
            if (roomData) {
              delete roomData[clientId];
              const count = getRoomUserCount(client.room);
              broadcastToRoom(client.room, {
                type: 'user-left',
                userId: clientId,
                userCount: count
              }, ws);
            }
            client.room = null;
          }
          break;
        }

        case 'location-update': {
          // GPS koordinat güncellemesi
          if (message.latitude !== undefined && message.longitude !== undefined) {
            client.latitude = message.latitude;
            client.longitude = message.longitude;
            client.lastLocationUpdate = Date.now();

            // Odadaki kullanıcılara yay
            if (client.room) {
              broadcastToRoom(client.room, {
                type: 'user-location-update',
                userId: clientId,
                username: client.username,
                latitude: message.latitude,
                longitude: message.longitude,
                timestamp: client.lastLocationUpdate
              }, ws);
            }
          }
          break;
        }

        case 'get-room-locations': {
          // Odadaki tüm kullanıcıların konumlarını iste
          if (client.room) {
            const locations = [];
            const roomClients = rooms.get(client.room);
            if (roomClients) {
              for (const [id, clientWs] of Object.entries(roomClients)) {
                const roomClient = clients.get(clientWs);
                if (roomClient && roomClient.latitude && roomClient.longitude) {
                  locations.push({
                    userId: id,
                    username: roomClient.username,
                    latitude: roomClient.latitude,
                    longitude: roomClient.longitude,
                    timestamp: roomClient.lastLocationUpdate
                  });
                }
              }
            }
            ws.send(JSON.stringify({
              type: 'room-locations',
              locations: locations
            }));
          }
          break;
        }

        // Yönetici WebSocket komutları
        case 'admin-auth': {
          ws.send(JSON.stringify({
            type: 'admin-auth-response',
            valid: verifyAdminToken(message.token)
          }));
          break;
        }

        case 'admin-create-channel': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Yetkisiz' }));
            break;
          }

          const channelName = message.name.toUpperCase();
          if (appData.channels.find(ch => ch.name === channelName)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Kanal zaten mevcut' }));
            break;
          }

          const channel = {
            name: channelName,
            password: message.password ? hashPassword(message.password) : null,
            createdBy: client.username
          };
          appData.channels.push(channel);
          if (channel.password) {
            channelPasswords.set(channelName, channel.password);
          }
          await saveData();

          // Tüm istemcilere yayınla
          wss.clients.forEach(c => {
            if (c.readyState === 1) {
              c.send(JSON.stringify({
                type: 'channel-created',
                channel: { ...channel, hasPassword: !!channel.password }
              }));
            }
          });
          break;
        }

        case 'admin-delete-channel': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Yetkisiz' }));
            break;
          }

          appData.channels = appData.channels.filter(ch => ch.name !== message.name);
          channelPasswords.delete(message.name);

          // Silinen kanaldaki kullanıcıları bağlantısını kes
          const roomData = rooms.get(message.name);
          if (roomData) {
            for (const [id, clientWs] of Object.entries(roomData)) {
              clientWs.send(JSON.stringify({
                type: 'channel-deleted',
                channel: message.name
              }));
            }
          }

          await saveData();

          // Tüm istemcilere yayınla
          wss.clients.forEach(c => {
            if (c.readyState === 1) {
              c.send(JSON.stringify({
                type: 'channel-deleted',
                channel: message.name
              }));
            }
          });
          break;
        }

        case 'admin-set-password': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Yetkisiz' }));
            break;
          }

          const channel = appData.channels.find(ch => ch.name === message.name);
          if (!channel) {
            ws.send(JSON.stringify({ type: 'error', message: 'Kanal bulunamadı' }));
            break;
          }

          if (message.password) {
            channel.password = hashPassword(message.password);
            channelPasswords.set(message.name, channel.password);
          } else {
            channel.password = null;
            channelPasswords.delete(message.name);
          }
          await saveData();

          // Şifre durum değişikliğini yayınla
          wss.clients.forEach(c => {
            if (c.readyState === 1) {
              c.send(JSON.stringify({
                type: 'channel-password-changed',
                channel: message.name,
                hasPassword: !!channel.password
              }));
            }
          });
          break;
        }

        case 'admin-ban-user': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Yetkisiz' }));
            break;
          }

          const username = message.username?.toLowerCase();
          if (!username) break;

          bannedUsernames.add(username);

          // Yasaklı kullanıcıyı bağlantısını kes
          for (const [clientWs, c] of clients) {
            if (c.username?.toLowerCase() === username) {
              clientWs.send(JSON.stringify({
                type: 'error',
                message: 'Bu sunucudan yasaklandınız'
              }));
              clientWs.close(1008, 'Yasaklı');
            }
          }

          await saveData();
          break;
        }

        case 'admin-unban-user': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Yetkisiz' }));
            break;
          }

          const username = message.username?.toLowerCase();
          if (username) {
            bannedUsernames.delete(username);
            await saveData();
          }
          break;
        }

        // === MESAJLAŞMA SİSTEMİ ===
        case 'chat-message': {
          // Kullanıcıdan kullanıcıya veya tüm odaya mesaj
          if (!client.room || !client.username) {
            ws.send(JSON.stringify({ type: 'error', message: 'Önce bir odaya katılın' }));
            break;
          }

          const targetId = message.target; // null = broadcast
          const content = message.content?.trim();

          if (!content) {
            ws.send(JSON.stringify({ type: 'error', message: 'Geçersiz mesaj' }));
            break;
          }

          const timestamp = Date.now();

          if (targetId) {
            // Öze mesaj - tek kullanıcıya
            const targetWs = rooms.get(client.room)?.[targetId];
            if (!targetWs) {
              ws.send(JSON.stringify({ type: 'error', message: 'Alıcı bulunamadı' }));
              break;
            }

            // Mesajı alıcıya gönder
            targetWs.send(JSON.stringify({
              type: 'chat-message',
              from: clientId,
              fromUsername: client.username,
              content: content,
              timestamp: timestamp
            }));

            // Gönderene onay
            ws.send(JSON.stringify({
              type: 'chat-sent',
              to: targetId,
              content: content,
              timestamp: timestamp
            }));
          } else {
            // Broadcast - odadaki herkese
            const roomClients = rooms.get(client.room);
            if (!roomClients) break;

            const baseMsg = {
              type: 'chat-message',
              from: clientId,
              fromUsername: client.username,
              content: content,
              timestamp: timestamp,
              broadcast: true
            };

            // Odadaki herkese gönder (kendisi hariç)
            for (const [id, targetWs] of Object.entries(roomClients)) {
              if (id !== clientId && targetWs.readyState === 1) {
                targetWs.send(JSON.stringify(baseMsg));
              }
            }

            // Gönderene onay (broadcast olarak işaretlendi)
            ws.send(JSON.stringify({
              type: 'chat-sent',
              broadcast: true,
              content: content,
              timestamp: timestamp
            }));
          }

          // Afet/acil kelime kontrolü
          const alertKeywords = ['afet', 'acil', 'yardım', 'deprem', 'sel', 'yangın', 'taşkın', 'çığ', 'heyelan', 'patlama', 'saldırı'];
          const lowerContent = content.toLowerCase();
          const hasAlertKeyword = alertKeywords.some(kw => lowerContent.includes(kw));

          if (hasAlertKeyword) {
            // Tüm odalara acil uyarı yay
            const alertMsg = {
              type: 'broadcast-alert',
              from: clientId,
              fromUsername: client.username,
              room: client.room,
              content: content,
              alertType: 'disaster',
              timestamp: Date.now()
            };

            wss.clients.forEach(c => {
              if (c.readyState === 1) {
                c.send(JSON.stringify(alertMsg));
              }
            });

            console.log(`  🚨 AFET UYARISI: ${client.username}: ${content}`);
          }
          break;
        }

        case 'sos-alert': {
          // SOS acil durum sinyali
          if (!client.room || !client.username) {
            ws.send(JSON.stringify({ type: 'error', message: 'Önce bir odaya katılın' }));
            break;
          }

          const sosData = {
            type: 'sos-alert',
            from: clientId,
            fromUsername: client.username,
            room: client.room,
            latitude: client.latitude || null,
            longitude: client.longitude || null,
            message: message.message || 'SOS - Acil Yardım Gerekiyor!',
            timestamp: Date.now()
          };

          // Tüm kullanıcılara SOS sinyali gönder
          wss.clients.forEach(c => {
            if (c.readyState === 1) {
              c.send(JSON.stringify(sosData));
            }
          });

          console.log(`  🆘 SOS SİNYALİ: ${client.username} - ${client.latitude},${client.longitude}`);

          // Gönderene onay
          ws.send(JSON.stringify({
            type: 'sos-sent',
            timestamp: Date.now()
          }));
          break;
        }

        case 'get-users': {
          // Odadaki kullanıcı listesini al
          if (client.room) {
            const users = getRoomUsers(client.room);
            ws.send(JSON.stringify({
              type: 'users-list',
              users: users,
              yourId: clientId
            }));
          }
          break;
        }
      }
    } catch (e) {
      console.error('Mesaj işlenirken hata:', e);
    }
  });

  ws.on('close', () => {
    const client = clients.get(ws);
    if (client?.room) {
      const roomData = rooms.get(client.room);
      if (roomData) {
        delete roomData[client.id];
        const count = getRoomUserCount(client.room);
        broadcastToRoom(client.room, {
          type: 'user-left',
          userId: client.id,
          userCount: count
        });
      }

      // Bu kullanıcı iletiyorsa aktif vericiyi temizle
      const currentTx = activeTransmitters.get(client.room);
      if (currentTx === client.id) {
        activeTransmitters.delete(client.room);
        broadcastToRoom(client.room, {
          type: 'tx-freed',
          userId: client.id
        });
      }
    }
    clients.delete(ws);
    console.log(`[${new Date().toISOString()}] İstemci bağlantısı kesildi: ${client?.id || clientId}`);
  });

  ws.on('error', (e) => {
    console.error(`WebSocket hatası:`, e);
  });
});

// Sunucuyu başlat
const adminToken = await initData();

// Rate limiter temizleme - her 5 dakikada bir eski kayıtları temizle
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
}, 5 * 60 * 1000);

httpServer.listen(HTTP_PORT, HOST, () => {
  console.log(`\n📡 EmercallPlus Intranet PTT Sunucusu`);
  console.log(`📡 HTTP: http://localhost:${HTTP_PORT}`);
  console.log(`📡 Ağ: http://${getLocalIP()}:${HTTP_PORT}`);
  console.log(`🔑 Yönetici Anahtarı: ${adminToken}`);
  console.log(`📍 GPS Koordinat Takip Aktif`);
  console.log(`🛡️  Güvenlik: Rate limiting, CSP, Security Headers aktif`);
  console.log(`📡 Bağlantıları kabul etmeye hazır\n`);
});
