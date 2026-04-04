#!/usr/bin/env node
/**
 * EmercallPlus Intranet PTT Sunucusu
 * GPS koordinat takip sistemi
 * Peer-to-peer ses ağ mesh için WebRTC sinyalleme
 * Kullanıcı yönetimi, kanal şifreleri, cihaz yasakları
 *
 * Production Optimized:
 * - SQLite database with better-sqlite3
 * - WebSocket compression
 * - Connection pooling and limits
 * - In-memory caching layer
 * - Message batching
 */

import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { networkInterfaces } from 'os';
import { randomBytes, createHash } from 'crypto';
import { gzip, createGzip } from 'zlib';
import { promisify } from 'util';

// Database functions - will be initialized after database is ready
let dbFunctions = null;

const gzipAsync = promisify(gzip);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ===== CONFIGURATION =====
const PORT = process.env.PORT || 4000;
const HTTP_PORT = PORT;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// Performance limits
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS || '1000');
// IP limit disabled for local + remote compatibility
const MAX_CONNECTIONS_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP || '999999');
const MESSAGE_BATCH_SIZE = parseInt(process.env.MESSAGE_BATCH_SIZE || '100');
const MESSAGE_BATCH_TIMEOUT = parseInt(process.env.MESSAGE_BATCH_TIMEOUT || '10');
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const CONNECTION_TIMEOUT = 120000; // 2 minutes
const SESSION_CLEANUP_INTERVAL = 300000; // 5 minutes

// Rate limiting
const RATE_LIMIT_WINDOW = 60000; // 1 dakika
const RATE_LIMIT_MAX_REQUESTS = 100; // Dakikada 100 istek

// ===== DATABASE =====
let db = null;
let channelPasswordsCache = new Map();
let bannedDevicesCache = new Set();
let bannedUsernamesCache = new Set();

async function initDatabase() {
  const { initDatabase: initDB, getChannels, getBannedDevices, getBannedUsernames, getChannelPassword, getSetting, setSetting, DB_PATH } = await import('./lib/database.js');
  db = initDB();

  console.log('📁 SQLite Database initialized');
  console.log(`   Path: ${DB_PATH}`);

  // Load channels into cache
  const channels = getChannels();
  for (const ch of channels) {
    const pwd = getChannelPassword(ch.name);
    if (pwd) channelPasswordsCache.set(ch.name, pwd);
  }

  // Load bans into cache
  bannedDevicesCache = getBannedDevices();
  bannedUsernamesCache = getBannedUsernames();

  // Get or create admin token
  let adminToken = getSetting('admin_token');
  if (!adminToken) {
    adminToken = randomBytes(24).toString('hex');
    setSetting('admin_token', adminToken);
    setSetting('admin_token_shown', '0');
  }

  console.log(`   Channels: ${channels.length}`);
  console.log(`   Banned devices: ${bannedDevicesCache.size}`);
  console.log(`   Banned usernames: ${bannedUsernamesCache.size}`);

  // Store database functions for global use
  const database = await import('./lib/database.js');
  dbFunctions = database;

  return adminToken;
}

// ===== IN-MEMORY STATE =====
// Room management: { roomName: { clientId: ws } }
const rooms = new Map();
// Client tracking: { ws: { id, room, username, ip, isAdmin, deviceId, latitude, longitude, lastLocationUpdate, lastHeartbeat } }
const clients = new Map();
// Active transmitters per room: { roomName: clientId }
const activeTransmitters = new Map();
// Per-IP connection count: { ip: count }
const ipConnections = new Map();
// Message batching queues: { ws: [{message, timestamp}, ...] }
const messageQueues = new Map();
// Rate limiting: { ip: { count, resetTime } }
const rateLimitMap = new Map();

let clientIdCounter = 0;

// ===== WEBSOCKET CONFIGURATION =====
const wssOptions = {
  clientTracking: true,
  maxPayload: 1024 * 1024, // 1MB max message size
  perMessageDeflate: IS_PROD ? {
    threshold: 1024, // Only compress messages > 1KB
    concurrencyLimit: 10,
    zlibDeflateOptions: {
      level: 3 // Balance between speed and compression
    }
  } : false
};

// ===== UTILITY FUNCTIONS =====

function getClientIP(req) {
  // Try to get real IP from headers (works with proxy/cloudflare)
  const forwarded = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const cfIP = req.headers['cf-connecting-ip'];

  if (forwarded) {
    // Take the first IP (original client) from the chain
    return forwarded.split(',')[0].trim();
  }

  if (realIP) {
    return realIP;
  }

  if (cfIP) {
    return cfIP;
  }

  // Fallback to socket remote address
  // Handle IPv6-mapped IPv4 addresses
  const remoteAddr = req.socket.remoteAddress;
  if (remoteAddr && remoteAddr.startsWith('::ffff:')) {
    return remoteAddr.substring(7);
  }

  return remoteAddr || 'unknown';
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
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
  return /^[A-Z0-9-]{2,20}$/.test(name);
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  return /^[a-zA-Z0-9ÇĞİÖŞÜçğıöşu_-]{2,15}$/.test(username);
}

function hashPassword(password) {
  return createHash('sha256').update(password).digest('hex');
}

function verifyAdminToken(token) {
  if (!dbFunctions) return false;
  return token === dbFunctions.getSetting('admin_token');
}

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

// ===== RATE LIMITING =====

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

// ===== CONNECTION MANAGEMENT =====

function trackConnection(ip) {
  const count = ipConnections.get(ip) || 0;
  ipConnections.set(ip, count + 1);
  return count + 1;
}

function untrackConnection(ip) {
  const count = ipConnections.get(ip) || 0;
  if (count <= 1) {
    ipConnections.delete(ip);
  } else {
    ipConnections.set(ip, count - 1);
  }
}

function canAcceptConnection(ip) {
  // Check global limit
  if (clients.size >= MAX_CONNECTIONS) {
    return false;
  }

  // Check per-IP limit
  const ipCount = ipConnections.get(ip) || 0;
  return ipCount < MAX_CONNECTIONS_PER_IP;
}

// ===== MESSAGE BATCHING =====

function queueMessage(ws, message) {
  if (!messageQueues.has(ws)) {
    messageQueues.set(ws, []);
  }

  const queue = messageQueues.get(ws);
  queue.push({ message, timestamp: Date.now() });

  if (queue.length >= MESSAGE_BATCH_SIZE) {
    flushMessageQueue(ws);
  } else {
    // Set timeout to flush pending messages
    setTimeout(() => flushMessageQueue(ws), MESSAGE_BATCH_TIMEOUT);
  }
}

function flushMessageQueue(ws) {
  const queue = messageQueues.get(ws);
  if (!queue || queue.length === 0) return;

  if (ws.readyState === 1) {
    // Send as array if multiple messages
    if (queue.length > 1) {
      ws.send(JSON.stringify({
        type: 'batch',
        messages: queue.map(item => item.message)
      }));
    } else {
      ws.send(JSON.stringify(queue[0].message));
    }
  }

  queue.length = 0;
}

// ===== BROADCASTING =====

function broadcastToRoom(room, message, excludeWs = null) {
  const roomClients = rooms.get(room);
  if (!roomClients) return;

  const messageStr = JSON.stringify(message);
  const sent = new Set();

  for (const [id, ws] of Object.entries(roomClients)) {
    if (ws !== excludeWs && ws.readyState === 1 && !sent.has(ws)) {
      ws.send(messageStr);
      sent.add(ws);
    }
  }
}

function broadcastToAll(message, excludeWs = null) {
  const messageStr = JSON.stringify(message);

  for (const [ws, client] of clients) {
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
    return {
      id,
      username: client?.username || `User-${id.slice(0, 4)}`,
      latitude: client?.latitude,
      longitude: client?.longitude
    };
  });
}

function getRoomUserCount(room) {
  const roomClients = rooms.get(room);
  return roomClients ? Object.keys(roomClients).length : 0;
}

// ===== HTTP SERVER =====

const httpServer = createServer(async (req, res) => {
  const clientIP = getClientIP(req);

  // Rate limiting
  if (!checkRateLimit(clientIP)) {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Too many requests - please wait' }));
    return;
  }

  // Security Headers (OWASP)
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(self), microphone=(self)');
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
  res.removeHeader('X-Powered-By');

  // CORS - Allow all origins for local and remote access
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token, X-Device-ID, Accept-Encoding');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
  res.setHeader('Access-Control-Max-Age', '3600');

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // Block access to sensitive files
  if (url.pathname.includes('data.json') ||
      url.pathname.includes('package.json') ||
      url.pathname.includes('.env') ||
      url.pathname.includes('serve.mjs') ||
      url.pathname.includes('.db')) {
    res.statusCode = 403;
    res.end('Forbidden');
    return;
  }

  // Serve static files from /lib/
  if (url.pathname.startsWith('/lib/')) {
    const filePath = join(__dirname, url.pathname);
    try {
      const content = await readFile(filePath);
      const ext = url.pathname.split('.').pop();
      const contentType = ext === 'css' ? 'text/css' :
                         ext === 'js' ? 'text/javascript' :
                         ext === 'png' ? 'image/png' : 'application/octet-stream';

      res.setHeader('Content-Type', `${contentType}; charset=utf-8`);
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // 1 year cache

      // Check if client accepts gzip
      const acceptEncoding = req.headers['accept-encoding'] || '';
      if (acceptEncoding.includes('gzip') && IS_PROD) {
        const compressed = await gzipAsync(content);
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Content-Length', compressed.length);
        res.end(compressed);
      } else {
        res.setHeader('Content-Length', content.length);
        res.end(content);
      }
      return;
    } catch (err) {
      res.statusCode = 404;
      res.end('Not found');
      return;
    }
  }

  // Serve index.html
  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      const indexPath = IS_PROD && existsSync(join(__dirname, 'dist', 'index.html'))
        ? join(__dirname, 'dist', 'index.html')
        : join(__dirname, 'index.html');

      const content = await readFile(indexPath, 'utf-8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', IS_PROD ? 'public, max-age=3600' : 'no-cache');

      if (acceptsGzip(req) && IS_PROD) {
        const compressed = await gzipAsync(content);
        res.setHeader('Content-Encoding', 'gzip');
        res.setHeader('Content-Length', compressed.length);
        res.end(compressed);
      } else {
        res.end(content);
      }
    } catch (err) {
      console.error('[ERROR] index.html error:', err);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'text/plain');
      res.end(`Server error: ${err.message}`);
    }
    return;
  }

  // API: Get channels
  if (url.pathname === '/api/channels' && req.method === 'GET') {
    const { getChannels } = await import('./lib/database.js');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=10');
    res.end(JSON.stringify(getChannels()));
    return;
  }

  // API: Create channel (admin only)
  if (url.pathname === '/api/channels' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));

      if (!validateChannelName(body.name)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid channel name' }));
        return;
      }

      if (body.password && typeof body.password !== 'string') {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid password' }));
        return;
      }

      const channelName = body.name.toUpperCase();
      const { createChannel, channelExists } = await import('./lib/database.js');

      if (channelExists(channelName)) {
        res.statusCode = 409;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Channel already exists' }));
        return;
      }

      const password = body.password ? hashPassword(body.password) : null;
      createChannel(channelName, password, body.admin || 'admin');

      if (password) {
        channelPasswordsCache.set(channelName, password);
      }

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        channel: { name: channelName, hasPassword: !!password }
      }));
    } catch (e) {
      console.error('Channel creation error:', e);
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
    return;
  }

  // API: Delete channel (admin only)
  if (url.pathname.startsWith('/api/channels/') && req.method === 'DELETE') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    const channelName = url.pathname.split('/').pop();

    if (!validateChannelName(channelName)) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Invalid channel name' }));
      return;
    }

    const { deleteChannel } = await import('./lib/database.js');
    deleteChannel(channelName);
    channelPasswordsCache.delete(channelName);

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API: Set channel password (admin only)
  if (url.pathname === '/api/channels/password' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));

      if (!validateChannelName(body.name)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid channel name' }));
        return;
      }

      const { setChannelPassword, getChannel } = await import('./lib/database.js');
      const channel = getChannel(body.name);

      if (!channel) {
        res.statusCode = 404;
        res.end('Channel not found');
        return;
      }

      const password = body.password ? hashPassword(body.password) : null;
      setChannelPassword(body.name, password);

      if (password) {
        channelPasswordsCache.set(body.name, password);
      } else {
        channelPasswordsCache.delete(body.name);
      }

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true, hasPassword: !!password }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Invalid request');
    }
    return;
  }

  // API: Admin authentication
  if (url.pathname === '/api/auth/admin' && req.method === 'POST') {
    try {
      const body = JSON.parse(await getBody(req));
      const valid = verifyAdminToken(body.token);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ valid }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Invalid request');
    }
    return;
  }

  // API: Get users (admin only)
  if (url.pathname === '/api/users' && req.method === 'GET') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Unauthorized');
      return;
    }

    const onlineUsers = [];
    for (const [roomName, roomClients] of rooms) {
      for (const [id, ws] of Object.entries(roomClients)) {
        const client = clients.get(ws);
        if (client) {
          onlineUsers.push({
            id,
            username: client.username,
            room: roomName,
            deviceId: client.deviceId,
            latitude: client.latitude,
            longitude: client.longitude
          });
        }
      }
    }

    const { getBans } = await import('./lib/database.js');
    const bans = getBans();

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      online: onlineUsers,
      banned: bans.map(b => `${b.type}:${b.value}`)
    }));
    return;
  }

  // API: Ban user (admin only)
  if (url.pathname === '/api/users/ban' && req.method === 'POST') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Unauthorized');
      return;
    }

    try {
      const body = JSON.parse(await getBody(req));
      const deviceId = body.deviceId;

      if (!deviceId) {
        res.statusCode = 400;
        res.end('Device ID required');
        return;
      }

      const { addBan } = await import('./lib/database.js');
      addBan('device', deviceId, 'admin');
      bannedDevicesCache.add(deviceId);

      // Disconnect banned device
      for (const [ws, client] of clients) {
        if (client.deviceId === deviceId) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'You have been banned from this server'
          }));
          ws.close(1008, 'Banned');
        }
      }

      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ success: true }));
    } catch (e) {
      res.statusCode = 400;
      res.end('Invalid request');
    }
    return;
  }

  // API: Unban user (admin only)
  if (url.pathname.startsWith('/api/users/ban/') && req.method === 'DELETE') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Unauthorized');
      return;
    }

    const deviceId = url.pathname.split('/').pop();
    const { removeBan } = await import('./lib/database.js');
    removeBan('device', deviceId);
    bannedDevicesCache.delete(deviceId);

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API: Server stats
  if (url.pathname === '/api/stats' && req.method === 'GET') {
    const roomStats = [];
    for (const [name, roomClients] of rooms) {
      roomStats.push({
        name,
        users: Object.keys(roomClients).length,
        hasPassword: !!channelPasswordsCache.get(name)
      });
    }

    const { getDatabaseStats } = await import('./lib/database.js');
    const dbStats = getDatabaseStats();

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=5');
    res.end(JSON.stringify({
      totalRooms: rooms.size,
      totalClients: clients.size,
      rooms: roomStats,
      database: dbStats,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    }));
    return;
  }

  // API: Health check
  if (url.pathname === '/health' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      clients: clients.size,
      rooms: rooms.size,
      memory: process.memoryUsage(),
      load: process.cpuUsage()
    }));
    return;
  }

  // API: Ready check
  if (url.pathname === '/ready' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      status: 'ready',
      timestamp: new Date().toISOString()
    }));
    return;
  }

  // API: Get user locations (admin only)
  if (url.pathname === '/api/locations' && req.method === 'GET') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Unauthorized');
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

  // API: Get admin token (show on first launch)
  if (url.pathname === '/api/admin-token' && req.method === 'GET') {
    const { getSetting, setSetting } = await import('./lib/database.js');
    res.setHeader('Content-Type', 'application/json');

    const token = getSetting('admin_token');
    const shown = getSetting('admin_token_shown') === '1';

    if (!token || token === '') {
      const newToken = randomBytes(24).toString('hex');
      setSetting('admin_token', newToken);
      setSetting('admin_token_shown', '1');
      res.end(JSON.stringify({ token: newToken, show: true }));
    } else if (!shown) {
      setSetting('admin_token_shown', '1');
      res.end(JSON.stringify({ token, show: true }));
    } else {
      res.end(JSON.stringify({ show: false }));
    }
    return;
  }

  // API: Metrics (Prometheus-style)
  if (url.pathname === '/metrics' && req.method === 'GET') {
    const token = req.headers['x-admin-token'];
    if (!verifyAdminToken(token)) {
      res.statusCode = 401;
      res.end('Unauthorized');
      return;
    }

    const metrics = generateMetrics();
    res.setHeader('Content-Type', 'text/plain');
    res.end(metrics);
    return;
  }

  res.statusCode = 404;
  res.end('Not found');
});

function getBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => resolve(data));
  });
}

function acceptsGzip(req) {
  const acceptEncoding = req.headers['accept-encoding'] || '';
  return acceptEncoding.includes('gzip');
}

function generateMetrics() {
  const mem = process.memoryUsage();
  const cpu = process.cpuUsage();

  let metrics = '# EmerCallPlus Metrics\n';
  metrics += `# TYPE emercall_connections gauge\n`;
  metrics += `emercall_connections ${clients.size}\n\n`;
  metrics += `# TYPE emercall_rooms gauge\n`;
  metrics += `emercall_rooms ${rooms.size}\n\n`;
  metrics += `# TYPE emercall_memory_bytes gauge\n`;
  metrics += `emercall_memory_bytes{type="heap_used"} ${mem.heapUsed}\n`;
  metrics += `emercall_memory_bytes{type="heap_total"} ${mem.heapTotal}\n`;
  metrics += `emercall_memory_bytes{type="rss"} ${mem.rss}\n\n`;
  metrics += `# TYPE emercall_uptime_seconds gauge\n`;
  metrics += `emercall_uptime_seconds ${process.uptime()}\n\n`;
  metrics += `# TYPE emercall_ip_connections gauge\n`;
  metrics += `emercall_ip_connections ${ipConnections.size}\n\n`;

  return metrics;
}

// ===== WEBSOCKET SERVER =====

const wss = new WebSocketServer({ server: httpServer, ...wssOptions });

wss.on('connection', (ws, req) => {
  const clientIP = getClientIP(req);

  // Check connection limits
  if (!canAcceptConnection(clientIP)) {
    ws.close(1008, 'Server full');
    return;
  }

  trackConnection(clientIP);

  const clientId = `client_${++clientIdCounter}`;
  clients.set(ws, {
    id: clientId,
    ip: clientIP,
    lastHeartbeat: Date.now()
  });

  if (!IS_PROD) {
    console.log(`[${new Date().toISOString()}] Client connected: ${clientId} from ${clientIP}`);
    console.log(`  Total connections: ${clients.size}/${MAX_CONNECTIONS}`);
  }

  // Send ping interval
  const pingInterval = setInterval(() => {
    if (ws.readyState === 1) {
      ws.ping();
    } else {
      clearInterval(pingInterval);
    }
  }, HEARTBEAT_INTERVAL);

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());
      const client = clients.get(ws);

      // Update heartbeat
      if (client) {
        client.lastHeartbeat = Date.now();
      }

      switch (message.type) {
        case 'join': {
          // Leave previous room
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

          // Check room password
          const roomPassword = channelPasswordsCache.get(message.room);
          if (roomPassword) {
            if (!message.password || hashPassword(message.password) !== roomPassword) {
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid password for this channel'
              }));
              return;
            }
          }

          // Join new room
          const room = message.room || 'default';
          const username = message.username || `User-${clientId.slice(0, 4)}`;

          // Validate username
          if (!validateUsername(username)) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Invalid username'
            }));
            return;
          }

          client.room = room;
          client.username = username;
          client.deviceId = message.deviceId;

          // Check bans
          if (bannedUsernamesCache.has(username.toLowerCase())) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'You have been banned from this server'
            }));
            ws.close(1008, 'Banned');
            return;
          }

          if (client.deviceId && bannedDevicesCache.has(client.deviceId)) {
            ws.send(JSON.stringify({
              type: 'error',
              message: 'You have been banned from this server'
            }));
            ws.close(1008, 'Banned');
            return;
          }

          // Admin authentication
          if (message.adminToken && verifyAdminToken(message.adminToken)) {
            client.isAdmin = true;
          }

          if (!rooms.has(room)) {
            rooms.set(room, {});
          }
          rooms.get(room)[clientId] = ws;

          // Send existing users to new client
          const roomUsers = getRoomUsers(room);
          const existingUsers = roomUsers.filter(u => u.id !== clientId);
          const totalUserCount = roomUsers.length + 1;

          ws.send(JSON.stringify({
            type: 'room-joined',
            roomId: room,
            yourId: clientId,
            users: existingUsers,
            userCount: totalUserCount,
            isAdmin: client.isAdmin || false
          }));

          // Notify others
          broadcastToRoom(room, {
            type: 'user-joined',
            userId: clientId,
            username: client.username,
            userCount: totalUserCount
          }, ws);

          if (!IS_PROD) {
            console.log(`  ${clientId} joined room: ${room} (${totalUserCount} users)`);
          }
          break;
        }

        case 'offer':
        case 'answer':
        case 'ice-candidate': {
          // WebRTC signaling
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
          // PTT Mutex - only one transmitter at a time
          const room = client.room;

          if (message.speaking) {
            const currentTx = activeTransmitters.get(room);
            if (currentTx && currentTx !== clientId) {
              ws.send(JSON.stringify({
                type: 'tx-busy',
                transmitterId: currentTx
              }));
              break;
            }
            activeTransmitters.set(room, clientId);
          } else {
            const currentTx = activeTransmitters.get(room);
            if (currentTx === clientId) {
              activeTransmitters.delete(room);
            }
          }

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
          // GPS coordinate update (throttled to 1s minimum)
          const now = Date.now();
          if (client.lastLocationUpdate && now - client.lastLocationUpdate < 1000) {
            break; // Skip if updated less than 1 second ago
          }

          if (message.latitude !== undefined && message.longitude !== undefined) {
            client.latitude = message.latitude;
            client.longitude = message.longitude;
            client.lastLocationUpdate = now;

            if (client.room) {
              broadcastToRoom(client.room, {
                type: 'user-location-update',
                userId: clientId,
                username: client.username,
                latitude: message.latitude,
                longitude: message.longitude,
                timestamp: now
              }, ws);
            }
          }
          break;
        }

        case 'get-room-locations': {
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

        case 'admin-auth': {
          ws.send(JSON.stringify({
            type: 'admin-auth-response',
            valid: verifyAdminToken(message.token)
          }));
          break;
        }

        case 'admin-create-channel': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
            break;
          }

          const channelName = message.name.toUpperCase();
          const { createChannel, channelExists } = await import('./lib/database.js');

          if (channelExists(channelName)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Channel already exists' }));
            break;
          }

          const password = message.password ? hashPassword(message.password) : null;
          createChannel(channelName, password, client.username);

          if (password) {
            channelPasswordsCache.set(channelName, password);
          }

          broadcastToAll({
            type: 'channel-created',
            channel: { name: channelName, hasPassword: !!password }
          });
          break;
        }

        case 'admin-delete-channel': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
            break;
          }

          const { deleteChannel } = await import('./lib/database.js');
          deleteChannel(message.name);
          channelPasswordsCache.delete(message.name);

          const roomData = rooms.get(message.name);
          if (roomData) {
            for (const [id, clientWs] of Object.entries(roomData)) {
              clientWs.send(JSON.stringify({
                type: 'channel-deleted',
                channel: message.name
              }));
            }
          }

          broadcastToAll({
            type: 'channel-deleted',
            channel: message.name
          });
          break;
        }

        case 'admin-set-password': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
            break;
          }

          const { setChannelPassword } = await import('./lib/database.js');
          const password = message.password ? hashPassword(message.password) : null;
          setChannelPassword(message.name, password);

          if (password) {
            channelPasswordsCache.set(message.name, password);
          } else {
            channelPasswordsCache.delete(message.name);
          }

          broadcastToAll({
            type: 'channel-password-changed',
            channel: message.name,
            hasPassword: !!password
          });
          break;
        }

        case 'admin-ban-user': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
            break;
          }

          const username = message.username?.toLowerCase();
          if (!username) break;

          const { addBan } = await import('./lib/database.js');
          addBan('username', username, client.username);
          bannedUsernamesCache.add(username);

          for (const [clientWs, c] of clients) {
            if (c.username?.toLowerCase() === username) {
              clientWs.send(JSON.stringify({
                type: 'error',
                message: 'You have been banned from this server'
              }));
              clientWs.close(1008, 'Banned');
            }
          }
          break;
        }

        case 'admin-unban-user': {
          if (!client.isAdmin) {
            ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }));
            break;
          }

          const username = message.username?.toLowerCase();
          if (username) {
            const { removeBan } = await import('./lib/database.js');
            removeBan('username', username);
            bannedUsernamesCache.delete(username);
          }
          break;
        }

        case 'chat-message': {
          if (!client.room || !client.username) {
            ws.send(JSON.stringify({ type: 'error', message: 'Join a room first' }));
            break;
          }

          const targetId = message.target;
          const content = message.content?.trim();

          if (!content) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid message' }));
            break;
          }

          const timestamp = Date.now();

          if (targetId) {
            // Private message
            const targetWs = rooms.get(client.room)?.[targetId];
            if (!targetWs) {
              ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found' }));
              break;
            }

            targetWs.send(JSON.stringify({
              type: 'chat-message',
              from: clientId,
              fromUsername: client.username,
              content: content,
              timestamp: timestamp
            }));

            ws.send(JSON.stringify({
              type: 'chat-sent',
              to: targetId,
              content: content,
              timestamp: timestamp
            }));
          } else {
            // Broadcast to room
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

            for (const [id, targetWs] of Object.entries(roomClients)) {
              if (id !== clientId && targetWs.readyState === 1) {
                targetWs.send(JSON.stringify(baseMsg));
              }
            }

            ws.send(JSON.stringify({
              type: 'chat-sent',
              broadcast: true,
              content: content,
              timestamp: timestamp
            }));
          }

          // Disaster alert keywords
          const alertKeywords = ['afet', 'acil', 'yardım', 'deprem', 'sel', 'yangın', 'taşkın', 'çığ', 'heyelan', 'patlama', 'saldırı'];
          const lowerContent = content.toLowerCase();
          const hasAlertKeyword = alertKeywords.some(kw => lowerContent.includes(kw));

          if (hasAlertKeyword) {
            const alertMsg = {
              type: 'broadcast-alert',
              from: clientId,
              fromUsername: client.username,
              room: client.room,
              content: content,
              alertType: 'disaster',
              timestamp: Date.now()
            };

            broadcastToAll(alertMsg);
            console.log(`  🚨 DISASTER ALERT: ${client.username}: ${content}`);
          }
          break;
        }

        case 'sos-alert': {
          if (!client.room || !client.username) {
            ws.send(JSON.stringify({ type: 'error', message: 'Join a room first' }));
            break;
          }

          const sosData = {
            type: 'sos-alert',
            from: clientId,
            fromUsername: client.username,
            room: client.room,
            latitude: client.latitude || null,
            longitude: client.longitude || null,
            message: message.message || 'SOS - Emergency Assistance Required!',
            timestamp: Date.now()
          };

          broadcastToAll(sosData);
          console.log(`  🆘 SOS ALERT: ${client.username} - ${client.latitude},${client.longitude}`);

          ws.send(JSON.stringify({
            type: 'sos-sent',
            timestamp: Date.now()
          }));
          break;
        }

        case 'get-users': {
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

        case 'pong': {
          // Heartbeat response
          if (client) {
            client.lastHeartbeat = Date.now();
          }
          break;
        }
      }
    } catch (e) {
      console.error('Message processing error:', e);
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

      // Clear transmitter if this user was transmitting
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
    untrackConnection(clientIP);
    messageQueues.delete(ws);

    if (!IS_PROD) {
      console.log(`[${new Date().toISOString()}] Client disconnected: ${client?.id || clientId}`);
    }
  });

  ws.on('error', (e) => {
    console.error(`WebSocket error:`, e);
  });

  ws.on('pong', () => {
    const client = clients.get(ws);
    if (client) {
      client.lastHeartbeat = Date.now();
    }
  });
});

// ===== MAINTENANCE TASKS =====

// Cleanup stale connections
function cleanupStaleConnections() {
  const now = Date.now();
  let cleaned = 0;

  for (const [ws, client] of clients) {
    if (now - client.lastHeartbeat > CONNECTION_TIMEOUT) {
      ws.terminate();
      cleaned++;
    }
  }

  // Clean up rate limiter
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(ip);
    }
  }

  // Clean up database sessions
  const sessionsCleaned = dbFunctions ? dbFunctions.cleanupOldSessions(CONNECTION_TIMEOUT) : 0;

  if (!IS_PROD && cleaned > 0) {
    console.log(`🧹 Cleaned up ${cleaned} stale connections, ${sessionsCleaned} old sessions`);
  }
}

// Start maintenance interval
setInterval(cleanupStaleConnections, SESSION_CLEANUP_INTERVAL);

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('\n🛑 Shutting down gracefully...');

  // Close WebSocket server
  wss.close(() => {
    console.log('✅ WebSocket server closed');
  });

  // Close HTTP server
  httpServer.close(() => {
    console.log('✅ HTTP server closed');
  });

  // Close database
  if (dbFunctions && dbFunctions.closeDatabase) {
    dbFunctions.closeDatabase();
    console.log('✅ Database closed');
  }

  process.exit(0);
}

// ===== START SERVER =====

async function start() {
  console.log('\n🔧 Initializing EmerCallPlus Emergency PTT Server...\n');

  // Initialize database
  const adminToken = await initDatabase();

  httpServer.listen(HTTP_PORT, HOST, () => {
    console.log(`\n📡 EmerCallPlus Emergency PTT Server`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`📡 HTTP Server: http://localhost:${HTTP_PORT}`);
    console.log(`📡 Network: http://${getLocalIP()}:${HTTP_PORT}`);
    console.log(`🔑 Admin Token: ${adminToken}`);
    console.log(`📍 GPS Tracking: Active`);
    console.log(`🛡️  Security: Rate limiting, CSP, Security headers`);
    console.log(`💾 Database: SQLite with WAL mode`);
    console.log(`🗜️  Compression: ${IS_PROD ? 'Enabled' : 'Disabled'}`);
    console.log(`📊 Performance limits: ${MAX_CONNECTIONS} connections, ${MAX_CONNECTIONS_PER_IP} per IP`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`✅ Ready to accept connections\n`);
  });
}

start().catch(console.error);
