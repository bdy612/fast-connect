/**
 * Fast Connect accounts backend (Google Apps Script web app).
 *
 * The only thing that reads or writes users_db.json in Google Drive. The website and the
 * desktop app both talk to this script; neither of them holds a Google key.
 * Setup steps: see SETUP.md next to this file.
 *
 * users_db.json:
 *   { "users": { "<username>": { "password_hash": "...", "real_name": "...", "user_number": 1 } },
 *     "friendships": { "<username>": ["<friend>", ...] },
 *     "next_user_number": 2 }
 *
 * password_hash is "pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>". Accounts created by old
 * versions of the desktop app have a plain SHA-256 hex hash; it is upgraded at their next login.
 */

const FOLDER_ID = '1EFpfHNYcP9qqSQ0AS-pvyka4_9xGLj86';
const USERS_FILE = 'users_db.json';

const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;
const ADMIN_SESSION_MINUTES = 30;
const TICKET_SECONDS = 120;

const MAX_FAILED_LOGINS = 10;      // per username
const MAX_FAILED_ADMIN = 5;
const LOCKOUT_SECONDS = 15 * 60;
const MAX_REQUEST_CHARS = 8000;
const MIN_ADMIN_PASSWORD = 12;

// FastAI: every account has its own daily allowance; the total is a safety net in case someone
// creates many accounts. Costs per request are in AI_KINDS below.
const AI_DAILY_UNITS_PER_USER = 100;
const AI_DAILY_UNITS_TOTAL = 2000;
const AI_MAX_REQUEST_CHARS = 25 * 1024 * 1024;   // room for a ~15 MB video
const AI_MAX_HISTORY = 40;                        // chat turns sent with each message
const AI_USAGE_FILE = 'ai_usage.json';
const AI_SYSTEM_PROMPT = 'You are an AI called FastAI, Speak as one';
const AI_CHAT_MODELS = ['gemini-3.5-flash-lite', 'gemini-3.6-flash', 'gemini-3.8-flash', 'gemini-3.1-pro-preview'];
const AI_KINDS = {
  chat: { units: 1, models: AI_CHAT_MODELS },
  image: { units: 2, models: AI_CHAT_MODELS },            // describe an image
  voice: { units: 3, models: ['lyria-3.5'] },
  imageGen: { units: 5, models: ['nano-banana-pro-preview'] },
  video: { units: 5, models: ['gemini-omni-1.1-flash'] },
};
const AI_MEDIA_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'video/mp4', 'video/quicktime',
  'video/x-msvideo', 'video/x-matroska', 'video/webm'];

const BAD_LOGIN = 'Incorrect username or password.';

function doPost(e) {
  let req;
  try {
    const body = e.postData.contents;
    // Only FastAI requests may be large (they can carry an image or a short video)
    if (body.length > AI_MAX_REQUEST_CHARS) return reply({ ok: false, error: 'Request too large.' });
    req = JSON.parse(body);
    if (!req || typeof req !== 'object' || Array.isArray(req)) throw new Error('not an object');
    if (req.action !== 'ai' && body.length > MAX_REQUEST_CHARS) return reply({ ok: false, error: 'Request too large.' });
  } catch (err) {
    return reply({ ok: false, error: 'Bad request.' });
  }

  try {
    getSecret();   // create it up front, never while another lock is held
    switch (req.action) {
      case 'signup': return reply(withLock(() => signup(req)));
      case 'login': return reply(login(req));
      case 'me': return reply(me(req));
      case 'deleteAccount': return reply(withLock(() => deleteAccount(req)));
      case 'friends': return reply(friends(req));
      case 'friendAdd': return reply(withLock(() => friendAdd(req)));
      case 'chatTicket': return reply(chatTicket(req));
      case 'verifyTicket': return reply(verifyTicket(req));
      case 'adminLogin': return reply(adminLogin(req));
      case 'adminList': return reply(adminList(req));
      case 'adminDelete': return reply(withLock(() => adminDelete(req)));
      case 'ai': return reply(ai(req));
      default: return reply({ ok: false, error: 'Unknown action.' });
    }
  } catch (err) {
    console.error(err && err.stack || err);   // visible in the Apps Script "Executions" log only
    return reply({ ok: false, error: 'Server error. Please try again.' });
  }
}

// Lets you open the web app URL in a browser to check it is deployed
function doGet() {
  return reply({ ok: true, service: 'Fast Connect accounts' });
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

function signup(req) {
  const username = text(req.username, 64).trim();
  const realName = cleanName(req.real_name);
  const password = text(req.password, 200);

  if (!username || !realName || !password) return fail('Please fill in all fields.');
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return fail('Username must be 3-32 characters: letters, numbers, _ . or -');
  }
  if (/^guest/i.test(username)) return fail('Usernames starting with "Guest" are reserved.');
  if (password.length < 6) return fail('Password must be at least 6 characters.');
  if (password.length > 128) return fail('Password must be at most 128 characters.');

  const db = loadDb();
  const names = Object.keys(db.users);
  const lower = username.toLowerCase();
  if (names.some(n => n.toLowerCase() === lower)) return fail('Username already taken. Choose another.');

  const user = {
    password_hash: hashPassword(password),
    real_name: realName,
    user_number: db.next_user_number,
  };
  setOwn(db.users, username, user);
  db.next_user_number += 1;
  saveDb(db);
  return { ok: true, token: sessionToken(username, user), user: publicUser(username, user) };
}

function login(req) {
  const username = text(req.username, 64).trim();
  const password = text(req.password, 200);
  if (!username || !password) return fail('Please fill in all fields.');

  const lockKey = 'login:' + username.toLowerCase();
  if (isLocked(lockKey, MAX_FAILED_LOGINS)) return fail('Too many failed attempts. Try again in 15 minutes.');

  const db = loadDb();
  const user = getUser(db, username);
  // Same answer for "no such user" and "wrong password", so usernames can't be probed here
  if (!user || password.length > 128 || !checkPassword(password, user.password_hash)) {
    recordFailure(lockKey);
    return fail(BAD_LOGIN);
  }
  clearFailures(lockKey);

  if (needsRehash(user.password_hash)) {
    withLock(() => {
      const fresh = loadDb();
      const current = getUser(fresh, username);
      if (current && current.password_hash === user.password_hash) {
        current.password_hash = hashPassword(password);
        saveDb(fresh);
      }
      return null;
    });
  }
  return { ok: true, token: sessionToken(username, user), user: publicUser(username, user) };
}

function me(req) {
  const session = requireSession(req, loadDb());
  if (session.error) return session;
  return { ok: true, user: publicUser(session.username, session.user) };
}

function deleteAccount(req) {
  const db = loadDb();
  const session = requireSession(req, db);
  if (session.error) return session;

  const lockKey = 'login:' + session.username.toLowerCase();
  if (isLocked(lockKey, MAX_FAILED_LOGINS)) return fail('Too many failed attempts. Try again in 15 minutes.');
  if (!checkPassword(text(req.password, 200), session.user.password_hash)) {
    recordFailure(lockKey);
    return fail('Incorrect password.');
  }
  removeUser(db, session.username);
  saveDb(db);
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Friends (each user can only change their own list; a friendship counts when both agree)
// ---------------------------------------------------------------------------

function friends(req) {
  const db = loadDb();
  const session = requireSession(req, db);
  if (session.error) return session;
  return { ok: true, friends: mutualFriends(db, session.username) };
}

function friendAdd(req) {
  const db = loadDb();
  const session = requireSession(req, db);
  if (session.error) return session;

  const friend = text(req.friend, 64);
  if (friend === session.username || !getUser(db, friend)) return fail('That user does not exist.');

  const list = ownList(db, session.username);
  if (list.indexOf(friend) === -1) {
    list.push(friend);
    saveDb(db);
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Chat tickets: proof of identity for a chat server, without giving it the session token.
// "bind" ties the ticket to one encrypted connection, so it can't be reused anywhere else.
// ---------------------------------------------------------------------------

function chatTicket(req) {
  const session = requireSession(req, loadDb());
  if (session.error) return session;
  const bind = text(req.bind, 128);
  if (!/^[0-9a-f]{64}$/.test(bind)) return fail('Bad request.');
  const ticket = signToken({
    t: 'c', u: session.username, n: session.user.user_number, b: bind,
    id: Utilities.getUuid(), exp: now() + TICKET_SECONDS,
  });
  return { ok: true, ticket: ticket };
}

function verifyTicket(req) {
  const ticket = readToken(text(req.ticket, 2000), 'c');
  if (!ticket) return fail('Invalid or expired ticket.');

  const cache = CacheService.getScriptCache();
  if (cache.get('ticket:' + ticket.id)) return fail('Ticket already used.');
  cache.put('ticket:' + ticket.id, '1', TICKET_SECONDS + 60);

  const db = loadDb();
  const user = getUser(db, ticket.u);
  if (!user || user.user_number !== ticket.n) return fail('Invalid or expired ticket.');
  return {
    ok: true, username: ticket.u, real_name: user.real_name || '', user_number: user.user_number,
    bind: ticket.b, friends: mutualFriends(db, ticket.u),
  };
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

function adminLogin(req) {
  const expected = PropertiesService.getScriptProperties().getProperty('ADMIN_PASSWORD');
  if (!expected) return fail('The admin password has not been set up yet (see SETUP.md).');
  if (expected.length < MIN_ADMIN_PASSWORD) {
    return fail('The admin password is too short. Set one with at least ' + MIN_ADMIN_PASSWORD + ' characters.');
  }
  if (isLocked('admin', MAX_FAILED_ADMIN)) return fail('Too many wrong passwords. Admin is locked for 15 minutes.');

  const secret = getSecret();
  const given = hmacSha256Hex(secret, 'admin:' + text(req.password, 200));
  if (!safeEqual(given, hmacSha256Hex(secret, 'admin:' + expected))) {
    recordFailure('admin');
    return fail('Wrong admin password.');
  }
  clearFailures('admin');
  return { ok: true, token: signToken({ t: 'a', exp: now() + ADMIN_SESSION_MINUTES * 60 }) };
}

function requireAdmin(req) {
  return readToken(text(req.token, 2000), 'a') ? null : { ok: false, error: 'Admin session expired. Unlock again.', expired: true };
}

function adminList(req) {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const db = loadDb();
  const users = Object.keys(db.users)
    .map(name => publicUser(name, db.users[name]))
    .sort((a, b) => (a.user_number || 0) - (b.user_number || 0));
  return { ok: true, users: users };
}

function adminDelete(req) {
  const denied = requireAdmin(req);
  if (denied) return denied;
  const username = text(req.username, 64);
  const db = loadDb();
  if (!getUser(db, username)) return fail('That account no longer exists.');
  removeUser(db, username);
  saveDb(db);
  return { ok: true };
}

// ---------------------------------------------------------------------------
// FastAI: the app's Gemini requests come through here, so the Gemini key (the GEMINI_API_KEY
// script property) never leaves Google, and each account has its own daily limit.
// ---------------------------------------------------------------------------

function ai(req) {
  const session = requireSession(req, loadDb());
  if (session.error) return session;

  const kind = has(AI_KINDS, req.kind) ? AI_KINDS[req.kind] : null;
  if (!kind) return fail('Unknown FastAI request.');
  const model = text(req.model, 100);
  if (kind.models.indexOf(model) === -1) return fail('That FastAI model is not available.');
  const contents = cleanContents(req.contents);
  if (!contents) return fail('Bad FastAI request.');

  const key = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!key) return fail('FastAI is not set up on the server yet.');

  // Charge first (so parallel requests can't overspend), refund if Gemini fails
  const charged = withLock(() => changeUsage(session.username, kind.units));
  if (!charged.ok) return charged;

  let result;
  try {
    result = callGemini(key, model, contents, req.kind);
  } catch (err) {
    console.error(err && err.stack || err);
    result = fail('FastAI could not be reached. Please try again.');
  }
  if (!result.ok) {
    withLock(() => changeUsage(session.username, -kind.units));
    return result;
  }
  result.units_left = charged.left;
  return result;
}

/** Rebuild the chat contents from scratch, keeping only plain text and allowed media. */
function cleanContents(contents) {
  if (!Array.isArray(contents) || contents.length < 1 || contents.length > AI_MAX_HISTORY) return null;
  const clean = [];
  for (const turn of contents) {
    if (!isPlainObject(turn) || (turn.role !== 'user' && turn.role !== 'model')) return null;
    if (!Array.isArray(turn.parts) || turn.parts.length < 1 || turn.parts.length > 10) return null;
    const parts = [];
    for (const part of turn.parts) {
      if (isPlainObject(part) && typeof part.text === 'string') {
        parts.push({ text: part.text });
      } else if (isPlainObject(part) && isPlainObject(part.inlineData)
          && AI_MEDIA_TYPES.indexOf(part.inlineData.mimeType) !== -1
          && typeof part.inlineData.data === 'string' && /^[A-Za-z0-9+/=]+$/.test(part.inlineData.data)) {
        parts.push({ inlineData: { mimeType: part.inlineData.mimeType, data: part.inlineData.data } });
      } else {
        return null;
      }
    }
    clean.push({ role: turn.role, parts: parts });
  }
  return clean[clean.length - 1].role === 'user' ? clean : null;
}

function callGemini(key, model, contents, kind) {
  const body = { contents: contents };
  if (kind === 'chat' || kind === 'image' || kind === 'video') {
    body.systemInstruction = { parts: [{ text: AI_SYSTEM_PROMPT }] };
  }
  if (kind === 'imageGen') body.generationConfig = { responseModalities: ['TEXT', 'IMAGE'] };
  if (kind === 'voice') body.generationConfig = { responseMimeType: 'audio/mp3' };

  const response = UrlFetchApp.fetch(
    'https://generativelanguage.googleapis.com/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(body),
      headers: { 'x-goog-api-key': key },   // a header, so the key never appears in a URL or log
      muteHttpExceptions: true,
    });
  let data;
  try {
    data = JSON.parse(response.getContentText());
  } catch (err) {
    data = {};
  }
  if (response.getResponseCode() !== 200) {
    const message = data.error && data.error.message ? String(data.error.message).slice(0, 300)
      : 'HTTP ' + response.getResponseCode();
    return fail('FastAI error: ' + message);
  }

  const candidate = data.candidates && data.candidates[0];
  const parts = candidate && candidate.content && Array.isArray(candidate.content.parts) ? candidate.content.parts : [];
  const answer = parts.filter(p => typeof p.text === 'string').map(p => p.text).join('');
  const media = parts.filter(p => p.inlineData && typeof p.inlineData.data === 'string')
    .map(p => ({ mimeType: String(p.inlineData.mimeType || ''), data: p.inlineData.data }));
  if (!answer && !media.length) {
    const blocked = data.promptFeedback && data.promptFeedback.blockReason;
    return fail('FastAI returned an empty answer' + (blocked ? ' (blocked: ' + blocked + ')' : '') + '.');
  }
  return { ok: true, text: answer, media: media };
}

function today() {
  return Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
}

/** Add (or with a negative number, refund) units for today. Call while holding the lock. */
function changeUsage(username, units) {
  const file = folderFile(AI_USAGE_FILE);
  let usage = file ? JSON.parse(file.getBlob().getDataAsString('UTF-8')) : {};
  if (!isPlainObject(usage) || usage.day !== today() || !isPlainObject(usage.users)) {
    usage = { day: today(), total: 0, users: {} };
  }
  const used = has(usage.users, username) ? Number(usage.users[username]) || 0 : 0;
  if (units > 0 && used + units > AI_DAILY_UNITS_PER_USER) {
    return fail("You've used today's FastAI limit (" + AI_DAILY_UNITS_PER_USER + '). It resets at midnight.');
  }
  if (units > 0 && (Number(usage.total) || 0) + units > AI_DAILY_UNITS_TOTAL) {
    return fail('FastAI is very busy today. Please try again tomorrow.');
  }
  setOwn(usage.users, username, Math.max(0, used + units));
  usage.total = Math.max(0, (Number(usage.total) || 0) + units);
  writeFolderFile(AI_USAGE_FILE, JSON.stringify(usage));
  return { ok: true, left: AI_DAILY_UNITS_PER_USER - Math.max(0, used + units) };
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

function folderFile(name) {
  const files = DriveApp.getFolderById(FOLDER_ID).getFilesByName(name);
  return files.hasNext() ? files.next() : null;
}

function writeFolderFile(name, content) {
  const file = folderFile(name);
  if (file) {
    file.setContent(content);
  } else {
    DriveApp.getFolderById(FOLDER_ID).createFile(name, content, 'application/json');
  }
}

function usersFile() {
  const files = DriveApp.getFolderById(FOLDER_ID).getFilesByName(USERS_FILE);
  return files.hasNext() ? files.next() : null;
}

function loadDb() {
  const file = usersFile();
  const db = file ? JSON.parse(file.getBlob().getDataAsString('UTF-8')) : {};
  if (!isPlainObject(db.users)) db.users = {};
  if (!isPlainObject(db.friendships)) db.friendships = {};
  db.next_user_number = Number(db.next_user_number) || 1;
  return db;
}

function saveDb(db) {
  const content = JSON.stringify(db, null, 4);
  const file = usersFile();
  if (file) {
    file.setContent(content);
  } else {
    DriveApp.getFolderById(FOLDER_ID).createFile(USERS_FILE, content, 'application/json');
  }
}

function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** Set a key as the object's own property, even for names like "__proto__". */
function setOwn(obj, key, value) {
  Object.defineProperty(obj, key, { value: value, enumerable: true, writable: true, configurable: true });
}

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/** Look a user up safely: names like "constructor" must not match built-in object properties. */
function getUser(db, username) {
  const user = has(db.users, username) ? db.users[username] : null;
  return isPlainObject(user) ? user : null;
}

function ownList(db, username) {
  if (!has(db.friendships, username) || !Array.isArray(db.friendships[username])) setOwn(db.friendships, username, []);
  return db.friendships[username];
}

function mutualFriends(db, username) {
  const result = {};
  const mine = has(db.friendships, username) && Array.isArray(db.friendships[username]) ? db.friendships[username] : [];
  mine.forEach(friend => {
    const theirs = has(db.friendships, friend) && Array.isArray(db.friendships[friend]) ? db.friendships[friend] : [];
    const user = getUser(db, friend);
    if (user && theirs.indexOf(username) !== -1) {
      setOwn(result, friend, { real_name: user.real_name || '' });
    }
  });
  return result;
}

function removeUser(db, username) {
  delete db.users[username];
  if (has(db.friendships, username)) delete db.friendships[username];
  Object.keys(db.friendships).forEach(name => {
    const list = db.friendships[name];
    if (Array.isArray(list)) setOwn(db.friendships, name, list.filter(f => f !== username));
  });
}

function publicUser(username, user) {
  // Never send the password hash to anyone
  return { username: username, real_name: user.real_name || '', user_number: user.user_number || null };
}

// ---------------------------------------------------------------------------
// Sessions and tokens (signed with a secret that only this script knows)
// ---------------------------------------------------------------------------

function getSecret() {
  const props = PropertiesService.getScriptProperties();
  let secret = props.getProperty('SESSION_SECRET');
  if (!secret) {
    secret = withLock(() => {
      let s = props.getProperty('SESSION_SECRET');
      if (!s) {
        s = sha256Hex(Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid());
        props.setProperty('SESSION_SECRET', s);
      }
      return s;
    });
    if (typeof secret !== 'string') throw new Error('could not create the session secret');
  }
  return secret;
}

function signToken(payload) {
  const body = bytesToHex(utf8Bytes(JSON.stringify(payload)));
  return body + '.' + hmacSha256Hex(getSecret(), body);
}

/** Returns the token's payload if the signature, type and expiry are all good; otherwise null. */
function readToken(token, type) {
  const parts = token.split('.');
  if (parts.length !== 2 || !/^[0-9a-f]+$/.test(parts[0]) || parts[0].length % 2) return null;
  if (!safeEqual(parts[1], hmacSha256Hex(getSecret(), parts[0]))) return null;
  let payload;
  try {
    payload = JSON.parse(utf8String(hexToBytes(parts[0])));
  } catch (err) {
    return null;
  }
  if (!payload || payload.t !== type || !(payload.exp > now())) return null;
  return payload;
}

function sessionToken(username, user) {
  return signToken({ t: 's', u: username, n: user.user_number, exp: now() + SESSION_DAYS * 86400 });
}

function requireSession(req, db) {
  const payload = readToken(text(req.token, 2000), 's');
  const user = payload ? getUser(db, payload.u) : null;
  // The user number check stops an old token working for a re-created account of the same name
  if (!user || user.user_number !== payload.n) {
    return { ok: false, error: 'Your session has expired. Please log in again.', expired: true };
  }
  return { username: payload.u, user: user };
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

function hashPassword(password) {
  const salt = sha256Hex(Utilities.getUuid() + Utilities.getUuid()).slice(0, 32);
  return 'pbkdf2_sha256$' + PBKDF2_ITERATIONS + '$' + salt + '$' +
    pbkdf2Sha256Hex(utf8Bytes(password), hexToBytes(salt), PBKDF2_ITERATIONS);
}

function checkPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length === 4 && parts[0] === 'pbkdf2_sha256') {
    const iterations = Number(parts[1]);
    if (!(iterations >= 1000 && iterations <= 2000000) || !/^[0-9a-f]+$/.test(parts[2])) return false;
    return safeEqual(pbkdf2Sha256Hex(utf8Bytes(password), hexToBytes(parts[2]), iterations), parts[3]);
  }
  // Legacy: unsalted SHA-256 from old desktop app versions
  return /^[0-9a-f]{64}$/.test(stored) && safeEqual(sha256Hex(password), stored);
}

function needsRehash(stored) {
  const parts = String(stored).split('$');
  return parts[0] !== 'pbkdf2_sha256' || Number(parts[1]) < PBKDF2_ITERATIONS;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function fail(message) {
  return { ok: false, error: message };
}

function now() {
  return Math.floor(Date.now() / 1000);
}

/** Accept only strings, and refuse oversized values. */
function text(value, max) {
  if (typeof value !== 'string') return '';
  return value.length > max ? '' : value;
}

function cleanName(value) {
  return text(value, 200).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 64);
}

/** Compare two strings without stopping at the first difference. */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Run fn while holding the script lock, so two writes can't overwrite each other. */
function withLock(fn) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(20000)) return fail('The server is busy. Please try again.');
  try {
    return fn();
  } finally {
    lock.releaseLock();
  }
}

function isLocked(key, max) {
  return Number(CacheService.getScriptCache().get('fail:' + key) || 0) >= max;
}

function recordFailure(key) {
  const cache = CacheService.getScriptCache();
  cache.put('fail:' + key, String(Number(cache.get('fail:' + key) || 0) + 1), LOCKOUT_SECONDS);
}

function clearFailures(key) {
  CacheService.getScriptCache().remove('fail:' + key);
}

function reply(data) {
  return ContentService.createTextOutput(JSON.stringify(data)).setMimeType(ContentService.MimeType.JSON);
}

// ---------------------------------------------------------------------------
// SHA-256, HMAC and PBKDF2 in plain JavaScript (Apps Script has no slow password hash built in)
// ---------------------------------------------------------------------------

const SHA_K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const SHA_IV = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const SHA_W = new Int32Array(64);

/** One SHA-256 compression: state (8 words) + block (16 words) -> out (8 words). */
function shaCompress(state, block, out) {
  const w = SHA_W;
  let i;
  for (i = 0; i < 16; i++) w[i] = block[i];
  for (i = 16; i < 64; i++) {
    const x = w[i - 15], y = w[i - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
  }
  let a = state[0], b = state[1], c = state[2], d = state[3];
  let e = state[4], f = state[5], g = state[6], h = state[7];
  for (i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  out[0] = (state[0] + a) | 0; out[1] = (state[1] + b) | 0; out[2] = (state[2] + c) | 0; out[3] = (state[3] + d) | 0;
  out[4] = (state[4] + e) | 0; out[5] = (state[5] + f) | 0; out[6] = (state[6] + g) | 0; out[7] = (state[7] + h) | 0;
}

/** Hash bytes, continuing from `state` after `prefixBytes` bytes were already hashed. Returns 8 words. */
function shaFinish(state, bytes, prefixBytes) {
  const padded = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const length = prefixBytes + bytes.length;
  padded[padded.length - 5] = Math.floor(length / 0x20000000);
  padded[padded.length - 4] = (length * 8) >>> 24;
  padded[padded.length - 3] = (length * 8) >>> 16;
  padded[padded.length - 2] = (length * 8) >>> 8;
  padded[padded.length - 1] = length * 8;

  const current = new Int32Array(state);
  const block = new Int32Array(16);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const p = offset + i * 4;
      block[i] = (padded[p] << 24) | (padded[p + 1] << 16) | (padded[p + 2] << 8) | padded[p + 3];
    }
    shaCompress(current, block, current);
  }
  return current;
}

function wordsToBytes(words) {
  const bytes = new Uint8Array(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    bytes[i * 4] = words[i] >>> 24;
    bytes[i * 4 + 1] = words[i] >>> 16;
    bytes[i * 4 + 2] = words[i] >>> 8;
    bytes[i * 4 + 3] = words[i];
  }
  return bytes;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return hex;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function utf8Bytes(str) {
  const encoded = unescape(encodeURIComponent(str));
  const bytes = new Uint8Array(encoded.length);
  for (let i = 0; i < encoded.length; i++) bytes[i] = encoded.charCodeAt(i);
  return bytes;
}

function utf8String(bytes) {
  let encoded = '';
  for (let i = 0; i < bytes.length; i++) encoded += String.fromCharCode(bytes[i]);
  return decodeURIComponent(escape(encoded));
}

function sha256Hex(str) {
  return bytesToHex(wordsToBytes(shaFinish(SHA_IV, utf8Bytes(str), 0)));
}

/** The SHA-256 states after hashing the HMAC inner and outer key pads. */
function hmacStates(keyBytes) {
  if (keyBytes.length > 64) keyBytes = wordsToBytes(shaFinish(SHA_IV, keyBytes, 0));
  const inner = new Int32Array(8), outer = new Int32Array(8);
  const ipad = new Int32Array(16), opad = new Int32Array(16);
  for (let i = 0; i < 16; i++) {
    let word = 0;
    for (let j = 0; j < 4; j++) word = (word << 8) | (keyBytes[i * 4 + j] || 0);
    ipad[i] = word ^ 0x36363636;
    opad[i] = word ^ 0x5c5c5c5c;
  }
  shaCompress(SHA_IV, ipad, inner);
  shaCompress(SHA_IV, opad, outer);
  return { inner: inner, outer: outer };
}

function hmacWords(states, messageBytes) {
  const innerHash = wordsToBytes(shaFinish(states.inner, messageBytes, 64));
  return shaFinish(states.outer, innerHash, 64);
}

function hmacSha256Hex(key, message) {
  return bytesToHex(wordsToBytes(hmacWords(hmacStates(utf8Bytes(key)), utf8Bytes(message))));
}

/** PBKDF2-HMAC-SHA256 with a 32-byte result, as hex. Matches Python's hashlib.pbkdf2_hmac. */
function pbkdf2Sha256Hex(passwordBytes, saltBytes, iterations) {
  const states = hmacStates(passwordBytes);
  const first = new Uint8Array(saltBytes.length + 4);
  first.set(saltBytes);
  first[saltBytes.length + 3] = 1;

  const u = hmacWords(states, first);
  const result = new Int32Array(u);
  // Every later round hashes exactly 32 bytes after a 64-byte pad: one fixed-layout block each
  const block = new Int32Array(16);
  block[8] = 0x80000000 | 0;
  block[15] = (64 + 32) * 8;
  const tmp = new Int32Array(8);
  for (let i = 1; i < iterations; i++) {
    block.set(u);
    shaCompress(states.inner, block, tmp);
    block.set(tmp);
    shaCompress(states.outer, block, u);
    for (let j = 0; j < 8; j++) result[j] ^= u[j];
  }
  return bytesToHex(wordsToBytes(result));
}

// ---------------------------------------------------------------------------
// Run this once from the editor (Run -> selfTest). It asks for the Google Drive permission
// and checks that everything works. Read the result under "Execution log".
// ---------------------------------------------------------------------------
function selfTest() {
  const vector = pbkdf2Sha256Hex(utf8Bytes('password'), utf8Bytes('salt'), 4096);
  console.log('Hash check: ' + (vector === 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a' ? 'OK' : 'FAILED'));

  const start = Date.now();
  hashPassword('timing test');
  console.log('One password hash takes ' + (Date.now() - start) + ' ms (under 3000 is fine)');

  const db = loadDb();
  console.log('Google Drive: OK, ' + Object.keys(db.users).length + ' accounts in ' + USERS_FILE);

  const admin = PropertiesService.getScriptProperties().getProperty('ADMIN_PASSWORD');
  console.log('Admin password: ' + (!admin ? 'NOT SET (add the ADMIN_PASSWORD script property)'
    : admin.length < MIN_ADMIN_PASSWORD ? 'TOO SHORT (use at least ' + MIN_ADMIN_PASSWORD + ' characters)' : 'set'));
  getSecret();
  console.log('Session secret: ready');
  console.log('Gemini key for FastAI: ' + (PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY')
    ? 'set' : 'NOT SET (add the GEMINI_API_KEY script property)'));
  UrlFetchApp.fetch('https://generativelanguage.googleapis.com/', { muteHttpExceptions: true });
  console.log('Internet access for FastAI: OK');
}
