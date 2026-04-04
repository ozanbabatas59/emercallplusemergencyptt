/**
 * SQLite Database Layer for EmerCallPlus
 * Provides high-performance, synchronous database operations
 */

import Database from 'better-sqlite3';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, mkdirSync, readFileSync, renameSync } from 'fs';
import { randomBytes } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || join(process.cwd(), 'emercall.db');

// Ensure database directory exists
const dbDir = dirname(DB_PATH);
if (!existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true });
}

let db = null;

/**
 * Initialize database connection and create tables
 */
export function initDatabase() {
  db = new Database(DB_PATH, {
    verbose: process.env.NODE_ENV === 'development' ? console.log : null
  });

  // Enable WAL mode for better concurrent performance
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('cache_size = -64000'); // 64MB cache
  db.pragma('temp_store = MEMORY');
  db.pragma('mmap_size = 30000000000'); // 30GB mmap

  createTables();
  migrateData();

  return db;
}

/**
 * Create database tables with indexes
 */
function createTables() {
  // Settings table - stores admin token and configuration
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_settings_updated ON settings(updated_at);
  `);

  // Channels table
  db.exec(`
    CREATE TABLE IF NOT EXISTS channels (
      name TEXT PRIMARY KEY,
      password TEXT,
      created_by TEXT NOT NULL DEFAULT 'system',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_channels_created ON channels(created_at);
  `);

  // Bans table - device IDs and usernames
  db.exec(`
    CREATE TABLE IF NOT EXISTS bans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      created_by TEXT,
      created_at INTEGER NOT NULL,
      UNIQUE(type, value)
    );
    CREATE INDEX IF NOT EXISTS idx_bans_type ON bans(type);
    CREATE INDEX IF NOT EXISTS idx_bans_value ON bans(value);
  `);

  // User sessions table - for active user tracking
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      device_id TEXT,
      room TEXT,
      ip TEXT,
      is_admin INTEGER DEFAULT 0,
      last_seen INTEGER NOT NULL,
      latitude REAL,
      longitude REAL,
      location_updated_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_room ON user_sessions(room);
    CREATE INDEX IF NOT EXISTS idx_sessions_device ON user_sessions(device_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON user_sessions(last_seen);
  `);

  // Audit log for admin actions
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      actor TEXT,
      target TEXT,
      details TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
  `);
}

/**
 * Migrate data from old data.json file
 */
function migrateData() {
  const dataFile = join(process.cwd(), 'data.json');

  // Check if already migrated
  const migrated = getSetting('migration_complete');
  if (migrated) {
    console.log('✅ Database already migrated from data.json');
    return;
  }

  if (!existsSync(dataFile)) {
    // First time setup - create default admin token and channels
    const adminToken = randomBytes(24).toString('hex');

    setSetting('admin_token', adminToken);
    setSetting('admin_token_shown', '0');

    // Create default channels
    const defaultChannels = ['ALFA-1', 'BRAVO-2', 'CHARLİ-3', 'DELTA-4', 'EKO-5'];
    const insertChannel = db.prepare(
      'INSERT OR IGNORE INTO channels (name, created_by, created_at, updated_at) VALUES (?, ?, ?, ?)'
    );
    const now = Date.now();

    for (const name of defaultChannels) {
      insertChannel.run(name, 'system', now, now);
    }

    setSetting('migration_complete', '1');
    console.log('✅ Database initialized with default data');
    return;
  }

  // Migrate from existing data.json
  try {
    const content = readFileSync(dataFile, 'utf-8');
    const data = JSON.parse(content);

    // Migrate admin token
    if (data.adminToken) {
      setSetting('admin_token', data.adminToken);
      setSetting('admin_token_shown', data.adminTokenShown ? '1' : '0');
    }

    // Migrate channels
    if (data.channels && Array.isArray(data.channels)) {
      const insertChannel = db.prepare(
        'INSERT OR REPLACE INTO channels (name, password, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
      );
      const now = Date.now();

      for (const ch of data.channels) {
        insertChannel.run(ch.name, ch.password || null, ch.createdBy || 'system', now, now);
      }
    }

    // Migrate bans
    if (data.bannedDeviceIds && Array.isArray(data.bannedDeviceIds)) {
      const insertBan = db.prepare(
        'INSERT OR IGNORE INTO bans (type, value, created_at) VALUES (?, ?, ?)'
      );
      const now = Date.now();

      for (const deviceId of data.bannedDeviceIds) {
        insertBan.run('device', deviceId, now);
      }
    }

    if (data.bannedUsernames && Array.isArray(data.bannedUsernames)) {
      const insertBan = db.prepare(
        'INSERT OR IGNORE INTO bans (type, value, created_at) VALUES (?, ?, ?)'
      );
      const now = Date.now();

      for (const username of data.bannedUsernames) {
        insertBan.run('username', username.toLowerCase(), now);
      }
    }

    setSetting('migration_complete', '1');
    console.log('✅ Migrated data from data.json to SQLite');

    // Backup old file
    const backupFile = dataFile + '.backup';
    renameSync(dataFile, backupFile);
    console.log('📦 Backed up data.json to data.json.backup');

  } catch (e) {
    console.error('❌ Migration error:', e);
  }
}

// ===== SETTINGS =====

export function getSetting(key) {
  const stmt = db.prepare('SELECT value FROM settings WHERE key = ?');
  const result = stmt.get(key);
  return result ? result.value : null;
}

export function setSetting(key, value) {
  const stmt = db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
  `);
  const now = Date.now();
  stmt.run(key, String(value), now, String(value), now);
}

export function getAllSettings() {
  const stmt = db.prepare('SELECT key, value FROM settings');
  const rows = stmt.all();
  const settings = {};
  for (const row of rows) {
    settings[row.key] = row.value;
  }
  return settings;
}

// ===== CHANNELS =====

export function getChannels() {
  const stmt = db.prepare(`
    SELECT name,
           password IS NOT NULL as has_password,
           created_by,
           created_at,
           updated_at
    FROM channels
    ORDER BY name
  `);
  return stmt.all();
}

export function getChannel(name) {
  const stmt = db.prepare('SELECT * FROM channels WHERE name = ?');
  return stmt.get(name);
}

export function getChannelPassword(name) {
  const stmt = db.prepare('SELECT password FROM channels WHERE name = ?');
  const result = stmt.get(name);
  return result ? result.password : null;
}

export function createChannel(name, password = null, createdBy = 'admin') {
  const stmt = db.prepare(`
    INSERT INTO channels (name, password, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  const now = Date.now();
  stmt.run(name, password, createdBy, now, now);

  logAudit('channel_created', createdBy, name, { password: !!password });
}

export function deleteChannel(name) {
  const stmt = db.prepare('DELETE FROM channels WHERE name = ?');
  stmt.run(name);
  logAudit('channel_deleted', null, name);
}

export function setChannelPassword(name, password) {
  const stmt = db.prepare(`
    UPDATE channels
    SET password = ?, updated_at = ?
    WHERE name = ?
  `);
  const now = Date.now();
  stmt.run(password, now, name);
  logAudit('channel_password_updated', null, name, { hasPassword: !!password });
}

export function channelExists(name) {
  const stmt = db.prepare('SELECT 1 FROM channels WHERE name = ?');
  return !!stmt.get(name);
}

// ===== BANS =====

export function getBans() {
  const stmt = db.prepare('SELECT type, value, created_by, created_at FROM bans ORDER BY created_at DESC');
  return stmt.all();
}

export function getBannedDevices() {
  const stmt = db.prepare("SELECT value FROM bans WHERE type = 'device'");
  const rows = stmt.all();
  return new Set(rows.map(r => r.value));
}

export function getBannedUsernames() {
  const stmt = db.prepare("SELECT value FROM bans WHERE type = 'username'");
  const rows = stmt.all();
  return new Set(rows.map(r => r.value));
}

export function addBan(type, value, createdBy = null) {
  const stmt = db.prepare(`
    INSERT OR IGNORE INTO bans (type, value, created_by, created_at)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(type, value, createdBy, Date.now());
  logAudit('ban_added', createdBy, value, { type });
}

export function removeBan(type, value) {
  const stmt = db.prepare('DELETE FROM bans WHERE type = ? AND value = ?');
  stmt.run(type, value);
  logAudit('ban_removed', null, value, { type });
}

export function isBannedDevice(deviceId) {
  if (!deviceId) return false;
  const stmt = db.prepare("SELECT 1 FROM bans WHERE type = 'device' AND value = ?");
  return !!stmt.get(deviceId);
}

export function isBannedUsername(username) {
  if (!username) return false;
  const stmt = db.prepare("SELECT 1 FROM bans WHERE type = 'username' AND value = ?");
  return !!stmt.get(username.toLowerCase());
}

// ===== USER SESSIONS =====

export function createSession(sessionId, username, deviceId, room, ip, isAdmin = false) {
  const stmt = db.prepare(`
    INSERT INTO user_sessions (session_id, username, device_id, room, ip, is_admin, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(sessionId, username, deviceId, room, ip, isAdmin ? 1 : 0, Date.now());
}

export function updateSession(sessionId, updates) {
  const fields = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbKey = key === 'isAdmin' ? 'is_admin' : key;
    fields.push(`${dbKey} = ?`);
    values.push(value);
  }

  if (fields.length === 0) return;

  fields.push('last_seen = ?');
  values.push(Date.now());
  values.push(sessionId);

  const stmt = db.prepare(`UPDATE user_sessions SET ${fields.join(', ')} WHERE session_id = ?`);
  stmt.run(...values);
}

export function getSession(sessionId) {
  const stmt = db.prepare('SELECT * FROM user_sessions WHERE session_id = ?');
  const session = stmt.get(sessionId);
  if (session) {
    session.isAdmin = !!session.is_admin;
  }
  return session;
}

export function deleteSession(sessionId) {
  const stmt = db.prepare('DELETE FROM user_sessions WHERE session_id = ?');
  stmt.run(sessionId);
}

export function getSessionsByRoom(room) {
  const stmt = db.prepare(`
    SELECT session_id, username, device_id, latitude, longitude, location_updated_at, is_admin
    FROM user_sessions
    WHERE room = ? AND last_seen > ?
    ORDER BY username
  `);
  const threshold = Date.now() - 60000; // Active within last minute
  return stmt.all(room, threshold);
}

export function cleanupOldSessions(maxAge = 3600000) { // 1 hour default
  const stmt = db.prepare('DELETE FROM user_sessions WHERE last_seen < ?');
  const result = stmt.run(Date.now() - maxAge);
  return result.changes;
}

// ===== AUDIT LOG =====

export function logAudit(action, actor, target, details = null) {
  const stmt = db.prepare(`
    INSERT INTO audit_log (action, actor, target, details, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(action, actor, target, details ? JSON.stringify(details) : null, Date.now());
}

export function getAuditLog(limit = 100) {
  const stmt = db.prepare(`
    SELECT action, actor, target, details, created_at
    FROM audit_log
    ORDER BY created_at DESC
    LIMIT ?
  `);
  return stmt.all(limit);
}

// ===== MAINTENANCE =====

export function getDatabaseStats() {
  const stats = {
    channels: db.prepare('SELECT COUNT(*) as count FROM channels').get().count,
    bans: db.prepare('SELECT COUNT(*) as count FROM bans').get().count,
    sessions: db.prepare('SELECT COUNT(*) as count FROM user_sessions').get().count,
    auditEntries: db.prepare('SELECT COUNT(*) as count FROM audit_log').get().count,
    pageSize: db.pragma('page_size', { simple: true }),
    pageCount: db.pragma('page_count', { simple: true }),
    walSize: null
  };

  try {
    const walPath = DB_PATH + '-wal';
    const { statSync } = require('fs');
    stats.walSize = existsSync(walPath) ? statSync(walPath).size : 0;
  } catch (e) {
    // Ignore
  }

  return stats;
}

export function optimizeDatabase() {
  db.pragma('optimize');
  db.exec('VACUUM');
  db.exec('ANALYZE');
}

export function closeDatabase() {
  if (db) {
    db.pragma('wal_checkpoint(TRUNCATE)');
    db.close();
    db = null;
  }
}

// Export database instance for direct queries if needed
export function getDatabase() {
  return db;
}

export { DB_PATH };
