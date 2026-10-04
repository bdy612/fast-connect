// Tests for Code.gs, run with Node against fake Google services:   node test_backend.js
// (Code.gs itself runs on Google Apps Script; this file is never deployed.)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

const drive = {};                // fake Google Drive folder: file name -> content
let cache = {};
const props = { ADMIN_PASSWORD: 'correct horse battery', GEMINI_API_KEY: 'test-gemini-key' };
let geminiCalls = [];
let geminiReply = null;          // what the fake Gemini answers next (null = echo)

const fakeFile = name => ({
  getBlob: () => ({ getDataAsString: () => drive[name] }),
  setContent: c => { drive[name] = c; },
});
const ctx = {
  console: { log: () => {}, error: (...a) => console.error('  [script error]', ...a) },
  DriveApp: {
    getFolderById: () => ({
      getFilesByName: name => {
        let done = !(name in drive);
        return { hasNext: () => !done, next: () => { done = true; return fakeFile(name); } };
      },
      createFile: (name, content) => { drive[name] = content; },
    }),
  },
  Utilities: {
    getUuid: () => crypto.randomUUID(),
    formatDate: () => fakeDay,
  },
  Session: { getScriptTimeZone: () => 'Etc/UTC' },
  UrlFetchApp: {
    fetch: (url, options) => {
      geminiCalls.push({ url, options, body: options && options.payload ? JSON.parse(options.payload) : null });
      const reply = geminiReply || { code: 200, json: { candidates: [{ content: { parts: [{ text: 'echo' }] } }] } };
      return { getResponseCode: () => reply.code, getContentText: () => JSON.stringify(reply.json) };
    },
  },
  PropertiesService: {
    getScriptProperties: () => ({
      getProperty: k => (k in props ? props[k] : null),
      setProperty: (k, v) => { props[k] = v; },
    }),
  },
  CacheService: {
    getScriptCache: () => ({
      get: k => (k in cache ? cache[k] : null),
      put: (k, v) => { cache[k] = v; },
      remove: k => { delete cache[k]; },
    }),
  },
  LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  ContentService: { MimeType: { JSON: 'json' }, createTextOutput: s => ({ setMimeType: () => s }) },
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'Code.gs'), 'utf8'), ctx);
// Fewer rounds so the suite is quick; the full-strength hash is checked separately below
vm.runInContext('var TEST_ITERATIONS = 2000;', ctx);
const source = fs.readFileSync(path.join(__dirname, 'Code.gs'), 'utf8')
  .replace('const PBKDF2_ITERATIONS = 100000;', 'const PBKDF2_ITERATIONS = 2000;');
const fast = vm.createContext({ ...ctx });
vm.runInContext(source, fast);

const call = (body, context = fast) => JSON.parse(context.doPost({ postData: { contents: JSON.stringify(body) } }));
const db = () => JSON.parse(drive['users_db.json']);
let fakeDay = '2026-10-04';

let passed = 0, failed = 0;
function check(name, condition, detail) {
  if (condition) { passed++; } else { failed++; console.log('FAIL: ' + name, detail !== undefined ? JSON.stringify(detail) : ''); }
}

// --- Crypto against Node's own implementations -------------------------------------------
for (const [pw, salt, iters] of [['password', 'salt', 1], ['password', 'salt', 4096], ['pässwörd ✓', 'x'.repeat(70), 1000], ['p'.repeat(100), 's', 257]]) {
  const want = crypto.pbkdf2Sync(pw, salt, iters, 32, 'sha256').toString('hex');
  const got = vm.runInContext(`pbkdf2Sha256Hex(utf8Bytes(${JSON.stringify(pw)}), utf8Bytes(${JSON.stringify(salt)}), ${iters})`, ctx);
  check(`pbkdf2 ${iters} rounds`, got === want);
}
for (const msg of ['', 'abc', 'é✓', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(1000)]) {
  check(`sha256 len ${msg.length}`, vm.runInContext(`sha256Hex(${JSON.stringify(msg)})`, ctx) === crypto.createHash('sha256').update(msg, 'utf8').digest('hex'));
  for (const key of ['k', 'key'.repeat(40)]) {
    check(`hmac len ${msg.length}`, vm.runInContext(`hmacSha256Hex(${JSON.stringify(key)}, ${JSON.stringify(msg)})`, ctx) === crypto.createHmac('sha256', key).update(msg, 'utf8').digest('hex'));
  }
}
const t0 = Date.now();
vm.runInContext('hashPassword("timing")', ctx);
const fullHashMs = Date.now() - t0;

// --- Accounts ------------------------------------------------------------------------------
const legacyHash = crypto.createHash('sha256').update('pässwörd1', 'utf8').digest('hex');
drive['users_db.json'] = JSON.stringify({
  users: { old_user: { password_hash: legacyHash, real_name: 'Old', user_number: 1 } },
  friendships: {}, next_user_number: 2,
});

let r = call({ action: 'login', username: 'old_user', password: 'pässwörd1' });
check('login with an account made by the old desktop app', r.ok && r.token && r.user.user_number === 1, r);
check('legacy hash upgraded to salted pbkdf2', db().users.old_user.password_hash.startsWith('pbkdf2_sha256$2000$'));
check('login still works after the upgrade', call({ action: 'login', username: 'old_user', password: 'pässwörd1' }).ok);
const oldToken = r.token;

r = call({ action: 'login', username: 'old_user', password: 'wrong' });
const r2 = call({ action: 'login', username: 'nobody_here', password: 'wrong' });
check('wrong password and unknown user give the same answer', !r.ok && !r2.ok && r.error === r2.error, [r, r2]);
check('no token on failed login', !r.token);

r = call({ action: 'signup', username: 'web_user', real_name: ' Web\u0007 User ', password: 'secret123' });
check('signup', r.ok && r.token && r.user.user_number === 2 && r.user.real_name === 'Web User', r);
const webToken = r.token;
check('signup stores a salted hash, never the password', /^pbkdf2_sha256\$2000\$[0-9a-f]{32}\$[0-9a-f]{64}$/.test(db().users.web_user.password_hash));
check('two users with the same password get different hashes',
  call({ action: 'signup', username: 'twin', real_name: 'T', password: 'secret123' }).ok && db().users.twin.password_hash !== db().users.web_user.password_hash);
check('password hash never returned', !JSON.stringify(r).includes('pbkdf2'));

check('duplicate username', !call({ action: 'signup', username: 'web_user', real_name: 'X', password: 'secret123' }).ok);
check('duplicate username, different case', !call({ action: 'signup', username: 'WEB_User', real_name: 'X', password: 'secret123' }).ok);
check('bad username characters', !call({ action: 'signup', username: 'a b', real_name: 'X', password: 'secret123' }).ok);
check('html in username', !call({ action: 'signup', username: '<script>', real_name: 'X', password: 'secret123' }).ok);
check('short password', !call({ action: 'signup', username: 'shorty', real_name: 'X', password: '123' }).ok);
check('huge password', !call({ action: 'signup', username: 'huge', real_name: 'X', password: 'x'.repeat(129) }).ok);
check('reserved guest name', !call({ action: 'signup', username: 'Guest_1234', real_name: 'X', password: 'secret123' }).ok);
for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
  check(`login as "${name}" fails cleanly`, call({ action: 'login', username: name, password: 'x' }).error === 'Incorrect username or password.');
}
r = call({ action: 'signup', username: 'constructor', real_name: 'C', password: 'secret123' });
check('a username that is also a JavaScript built-in still works', r.ok && call({ action: 'login', username: 'constructor', password: 'secret123' }).ok, r);
r = call({ action: 'signup', username: '__proto__', real_name: 'P', password: 'secret123' });
check('"__proto__" as a username is stored like any other', r.ok && Object.keys(db().users).includes('__proto__') && call({ action: 'me', token: r.token }).ok, r);
check('non-string fields rejected', !call({ action: 'login', username: { a: 1 }, password: ['x'] }).ok);
check('non-object body rejected', call([1, 2]).error === 'Bad request.');
check('oversized request rejected', call({ action: 'login', username: 'a', password: 'b', pad: 'x'.repeat(9000) }).error === 'Request too large.');
check('unknown action', call({ action: 'dropEverything' }).error === 'Unknown action.');

// --- Sessions ------------------------------------------------------------------------------
check('me with a valid token', call({ action: 'me', token: webToken }).user.username === 'web_user');
check('me without a token', call({ action: 'me' }).expired === true);
const tampered = webToken.slice(0, 10) + (webToken[10] === 'a' ? 'b' : 'a') + webToken.slice(11);
check('tampered token rejected', call({ action: 'me', token: tampered }).expired === true);
const forgedBody = Buffer.from(JSON.stringify({ t: 's', u: 'old_user', n: 1, exp: 9999999999 })).toString('hex');
check('forged token rejected', call({ action: 'me', token: forgedBody + '.' + '0'.repeat(64) }).expired === true);
check('forged token signed with a guessed secret rejected',
  call({ action: 'me', token: forgedBody + '.' + crypto.createHmac('sha256', '').update(forgedBody).digest('hex') }).expired === true);

// --- Friends -------------------------------------------------------------------------------
check('add friend (one side)', call({ action: 'friendAdd', token: webToken, friend: 'old_user' }).ok);
check('one-sided friendship is not shown', Object.keys(call({ action: 'friends', token: webToken }).friends).length === 0);
check('other side adds', call({ action: 'friendAdd', token: oldToken, friend: 'web_user' }).ok);
r = call({ action: 'friends', token: webToken });
check('mutual friendship is shown with real name', r.friends.old_user && r.friends.old_user.real_name === 'Old', r);
check('cannot friend yourself', !call({ action: 'friendAdd', token: webToken, friend: 'web_user' }).ok);
check('cannot friend a missing user', !call({ action: 'friendAdd', token: webToken, friend: 'ghost' }).ok);
check('cannot edit friends without a session', !call({ action: 'friendAdd', token: 'x.y', friend: 'old_user' }).ok);

// --- Chat tickets --------------------------------------------------------------------------
const bind = 'ab'.repeat(32);
r = call({ action: 'chatTicket', token: webToken, bind });
check('chat ticket issued', r.ok && r.ticket);
const ticket = r.ticket;
check('ticket is not a session token', call({ action: 'me', token: ticket }).expired === true);
check('session token is not a ticket', !call({ action: 'verifyTicket', ticket: webToken }).ok);
r = call({ action: 'verifyTicket', ticket });
check('ticket verifies with identity, binding and friends', r.ok && r.username === 'web_user' && r.bind === bind && r.friends.old_user, r);
check('ticket cannot be used twice', call({ action: 'verifyTicket', ticket }).error === 'Ticket already used.');
check('bad binding refused', !call({ action: 'chatTicket', token: webToken, bind: 'zz' }).ok);

// --- Admin ---------------------------------------------------------------------------------
check('admin list without a token', call({ action: 'adminList' }).expired === true);
check('admin list with a user token', call({ action: 'adminList', token: webToken }).expired === true);
check('wrong admin password', call({ action: 'adminLogin', password: 'guess' }).error === 'Wrong admin password.');
r = call({ action: 'adminLogin', password: 'correct horse battery' });
check('admin login', r.ok && r.token);
const adminToken = r.token;
check('admin token is not a user session', call({ action: 'me', token: adminToken }).expired === true);
r = call({ action: 'adminList', token: adminToken });
check('admin list', r.ok && r.users.length === 5 && r.users[0].username === 'old_user' && !JSON.stringify(r).includes('password'), r);
check('admin delete', call({ action: 'adminDelete', token: adminToken, username: 'web_user' }).ok);
check('deleted account cannot log in', !call({ action: 'login', username: 'web_user', password: 'secret123' }).ok);
check('deleted account token is dead', call({ action: 'me', token: webToken }).expired === true);
check('deleted account removed from friends lists', !JSON.stringify(db().friendships).includes('web_user'));
r = call({ action: 'signup', username: 'web_user', real_name: 'Impostor', password: 'another1' });
check('old token does not work for a re-created account of the same name', r.ok && call({ action: 'me', token: webToken }).expired === true);

for (let i = 0; i < 5; i++) call({ action: 'adminLogin', password: 'guess' + i });
check('admin locked after 5 wrong passwords, even with the right one', /locked/.test(call({ action: 'adminLogin', password: 'correct horse battery' }).error));
cache = {};
props.ADMIN_PASSWORD = 'short';
check('short admin password refused', /too short/.test(call({ action: 'adminLogin', password: 'short' }).error));
delete props.ADMIN_PASSWORD;
check('admin disabled until a password is set', /not been set up/.test(call({ action: 'adminLogin', password: '' }).error));

// --- Delete own account, lockouts, sign-up limit ----------------------------------------------
check('delete account needs the password', call({ action: 'deleteAccount', token: oldToken, password: 'nope' }).error === 'Incorrect password.');
check('delete own account', call({ action: 'deleteAccount', token: oldToken, password: 'pässwörd1' }).ok && !db().users.old_user);

for (let i = 0; i < 10; i++) call({ action: 'login', username: 'twin', password: 'bad' });
check('login locked after 10 failures, even with the right password', /Too many/.test(call({ action: 'login', username: 'twin', password: 'secret123' }).error));
cache = {};
check('login works again after the lockout ends', call({ action: 'login', username: 'twin', password: 'secret123' }).ok);

let made = 0;
for (let i = 0; i < 40; i++) if (call({ action: 'signup', username: 'bulk' + i, real_name: 'B', password: 'secret123' }).ok) made++;
check('no cap on sign-ups', made === 40, made);


// --- FastAI proxy ----------------------------------------------------------------------------
cache = {};
r = call({ action: 'login', username: 'twin', password: 'secret123' });
const aiToken = r.token;
const chat = (extra = {}) => call({ action: 'ai', token: aiToken, kind: 'chat', model: 'gemini-3.5-flash-lite',
  contents: [{ role: 'user', parts: [{ text: 'hello' }] }], ...extra });

geminiCalls = [];
r = chat();
check('chat goes through', r.ok && r.text === 'echo' && r.units_left === 99, r);
const sent = geminiCalls[0];
check('key sent in a header, never in the URL', sent.options.headers['x-goog-api-key'] === 'test-gemini-key' && !sent.url.includes('test-gemini-key'));
check('right model and system prompt', sent.url.includes('/models/gemini-3.5-flash-lite:generateContent') && sent.body.systemInstruction);
check('key never returned to the user', !JSON.stringify(r).includes('test-gemini-key'));

check('no AI without a session', call({ action: 'ai', kind: 'chat', model: 'gemini-3.5-flash-lite', contents: [{ role: 'user', parts: [{ text: 'x' }] }] }).expired === true);
check('unknown model refused', /not available/.test(chat({ model: 'gemini-ultra-expensive' }).error));
check('model for the wrong kind refused', /not available/.test(chat({ kind: 'imageGen' }).error));
check('unknown kind refused', /Unknown FastAI/.test(chat({ kind: 'everything' }).error));
check('extra fields are stripped before Gemini sees them', (geminiCalls = [], chat({ contents: [{ role: 'user', parts: [{ text: 'hi', tools: 'x' }], evil: 1 }] }), JSON.stringify(geminiCalls[0].body.contents) === '[{"role":"user","parts":[{"text":"hi"}]}]'));
check('bad media type refused', /Bad FastAI/.test(chat({ contents: [{ role: 'user', parts: [{ inlineData: { mimeType: 'application/x-msdownload', data: 'AAAA' } }] }] }).error));
check('history must end with the user', /Bad FastAI/.test(chat({ contents: [{ role: 'model', parts: [{ text: 'x' }] }] }).error));
check('too much history refused', /Bad FastAI/.test(chat({ contents: Array.from({ length: 41 }, () => ({ role: 'user', parts: [{ text: 'x' }] })) }).error));

r = call({ action: 'ai', token: aiToken, kind: 'image', model: 'gemini-3.6-flash', contents: [{ role: 'user', parts: [{ inlineData: { mimeType: 'image/png', data: 'iVBORw0KGgo=' } }, { text: 'what is this' }] }] });
check('image description costs 2', r.ok && r.units_left === 96, r);

geminiReply = { code: 200, json: { candidates: [{ content: { parts: [{ text: 'here' }, { inlineData: { mimeType: 'image/png', data: 'iVBORw0KGgo=' } }] } }] } };
r = call({ action: 'ai', token: aiToken, kind: 'imageGen', model: 'nano-banana-pro-preview', contents: [{ role: 'user', parts: [{ text: 'a cat' }] }] });
check('generated image returned', r.ok && r.media.length === 1 && r.media[0].mimeType === 'image/png' && r.units_left === 91, r);

geminiReply = { code: 429, json: { error: { message: 'Resource exhausted' } } };
r = chat();
check('Gemini error passed on and not charged', !r.ok && /Resource exhausted/.test(r.error), r);
geminiReply = null;
check('refund worked', chat().units_left === 90);

const usage = () => JSON.parse(drive['ai_usage.json']);
check('usage kept in its own file, not in users_db.json', usage().users.twin === 10 && !drive['users_db.json'].includes('units'));

for (let i = 0; i < 90; i++) chat();
r = chat();
check('daily limit per user enforced', !r.ok && /today's FastAI limit \(100\)/.test(r.error), r);

r = call({ action: 'login', username: 'bulk1', password: 'secret123' });
check('other users are not affected by one user\'s limit', call({ action: 'ai', token: r.token, kind: 'chat', model: 'gemini-3.5-flash-lite', contents: [{ role: 'user', parts: [{ text: 'x' }] }] }).ok);

fakeDay = '2026-10-05';
check('limit resets the next day', chat().units_left === 99);

const big = { action: 'ai', token: aiToken, kind: 'chat', model: 'gemini-3.5-flash-lite', contents: [{ role: 'user', parts: [{ text: 'x'.repeat(20000) }] }] };
check('AI requests may be bigger than other requests', call(big).ok);
check('other requests are still limited to 8000 characters', call({ action: 'login', username: 'x'.repeat(9000), password: 'y' }).error === 'Request too large.');

let usageNow = usage();
usageNow.total = 1999;
drive['ai_usage.json'] = JSON.stringify(usageNow);
check('total daily safety net enforced', /very busy/.test(call({ ...big, kind: 'video', model: 'gemini-omni-1.1-flash' }).error));

delete props.GEMINI_API_KEY;
check('FastAI off until the key is set', /not set up/.test(chat().error));

console.log(`${passed} passed, ${failed} failed. One full-strength password hash took ${fullHashMs} ms here.`);
process.exit(failed ? 1 : 0);
