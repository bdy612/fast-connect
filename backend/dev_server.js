// Local test server:   node dev_server.js   then open http://localhost:8765
//
// Serves the website and runs the real Code.gs against a throwaway in-memory "Drive" file, so
// sign-up, login and the admin page can be tried without touching Google or the real accounts.
// The desktop app can use it too: set FASTCONNECT_API_URL=http://127.0.0.1:8765/api
// Nothing here is deployed; the test admin password below only exists on this local server.

const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

const PORT = Number(process.env.PORT || 8765);
const SITE = path.join(__dirname, '..');
const TEST_ADMIN_PASSWORD = process.env.DEV_ADMIN_PASSWORD || 'local-test-admin-only';

const drive = {};   // fake Drive folder: file name -> content
const cache = {};
const props = { ADMIN_PASSWORD: TEST_ADMIN_PASSWORD, GEMINI_API_KEY: 'local-fake-key' };
const fakeFile = name => ({ getBlob: () => ({ getDataAsString: () => drive[name] }), setContent: c => { drive[name] = c; } });
const ctx = vm.createContext({
  console,
  DriveApp: {
    getFolderById: () => ({
      getFilesByName: name => {
        let done = !(name in drive);
        return { hasNext: () => !done, next: () => { done = true; return fakeFile(name); } };
      },
      createFile: (name, content) => { drive[name] = content; },
    }),
  },
  Utilities: { getUuid: () => crypto.randomUUID(), formatDate: () => new Date().toISOString().slice(0, 10) },
  Session: { getScriptTimeZone: () => 'Etc/UTC' },
  // Fake Gemini: answers every FastAI request without calling Google
  UrlFetchApp: {
    fetch: (url, options) => {
      const body = JSON.parse(options.payload);
      const last = body.contents[body.contents.length - 1].parts.map(p => p.text || '[file]').join(' ');
      const reply = { candidates: [{ content: { parts: [{ text: `(test server, ${url.split('/models/')[1].split(':')[0]}) You said: ${last}` }] } }] };
      return { getResponseCode: () => 200, getContentText: () => JSON.stringify(reply) };
    },
  },
  PropertiesService: {
    getScriptProperties: () => ({ getProperty: k => (k in props ? props[k] : null), setProperty: (k, v) => { props[k] = v; } }),
  },
  CacheService: {
    getScriptCache: () => ({ get: k => (k in cache ? cache[k] : null), put: (k, v) => { cache[k] = v; }, remove: k => { delete cache[k]; } }),
  },
  LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
  ContentService: { MimeType: { JSON: 'json' }, createTextOutput: s => ({ setMimeType: () => s }) },
});
vm.runInContext(fs.readFileSync(path.join(__dirname, 'Code.gs'), 'utf8'), ctx);

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.json': 'application/json' };

http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/api') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(req.method === 'POST' ? ctx.doPost({ postData: { contents: body } }) : ctx.doGet());
    });
    return;
  }

  // The website's config.js, pointed at this server instead of Google
  if (url.pathname === '/config.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript' });
    res.end(`const ACCOUNTS_API_URL = 'http://localhost:${PORT}/api';\n`);
    return;
  }

  const target = path.normalize(path.join(SITE, url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname)));
  if (!target.startsWith(SITE + path.sep) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(target)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(target).pipe(res);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Fast Connect test site: http://localhost:${PORT}  (accounts are temporary and vanish when this stops)`);
});
