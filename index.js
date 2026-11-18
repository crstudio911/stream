const crypto = require('crypto');
const express = require('express');
const X = require('./extract');
const B = require('./browser');

const SETTINGS = {
  STREAM_KEY: ''
};

const PORT = Number(process.env.SERVER_PORT) || Number(process.env.PORT) || 3000;
const KEY = String(process.env.STREAM_KEY || SETTINGS.STREAM_KEY || '');
const MAX_JOBS = Math.max(1, Math.min(6, Number(process.env.MAX_JOBS) || 2));
const MAX_WAITING = Math.max(2, Math.min(30, Number(process.env.MAX_WAITING) || 8));
const LINK_SKEW_MS = 60 * 1000;
const NONCE_RE = /^[0-9a-f]{32}$/;
const PACK_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const UID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ROUTES = new Set(['/health', '/find']);
const ERRORS = new Set(['invalid_url', 'blocked_host', 'page_unreachable', 'no_video', 'drm_protected', 'unsupported_format', 'busy', 'timeout']);

if (KEY.length < 32) {
  console.error('STREAM_KEY must be at least 32 characters');
  process.exit(1);
}

const linkKey = crypto.createHash('sha256').update('pop-link:' + KEY).digest();
const nonces = new Map();
const running = new Map();
let active = 0;
const queue = [];

function lock(obj, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', linkKey, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64');
}

function unlock(text, aad) {
  const b = Buffer.from(text, 'base64');
  if (b.length < 29) throw new Error('bad');
  const d = crypto.createDecipheriv('aes-256-gcm', linkKey, b.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(b.subarray(b.length - 16));
  const raw = Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
  return JSON.parse(raw.toString());
}

function slot() {
  if (active < MAX_JOBS) {
    active++;
    return Promise.resolve();
  }
  if (queue.length >= MAX_WAITING) return Promise.reject(X.fail('busy'));
  return new Promise((resolve) => queue.push(resolve));
}

function release() {
  const next = queue.shift();
  if (next) next();
  else active = Math.max(0, active - 1);
}

function withTimeout(p, ms) {
  let t;
  return Promise.race([p, new Promise((_, rej) => (t = setTimeout(() => rej(X.fail('timeout')), ms)))]).finally(() => clearTimeout(t));
}

function view(c) {
  const out = { url: c.url, kind: c.kind === 'webm' ? 'webm' : c.kind, referer: c.referer || '', via: c.via, size: c.size || 0 };
  if (c.variants && c.variants.length) out.variants = c.variants.map((v) => ({ url: v.url, height: v.height, bandwidth: v.bandwidth }));
  if (c.encrypted) out.encrypted = true;
  return out;
}

async function find(url, level, wait) {
  await X.assertPublic(url);
  let title = '';
  let drm = false;
  let dash = false;
  let method = 'static';
  let found = [];
  try {
    const s = await X.staticFind(url, { frames: level >= 2 ? 4 : 2 });
    found = s.found;
    title = s.title;
  } catch (e) {
    if (level < 2 || e.code === 'blocked_host' || e.code === 'invalid_url') throw e;
  }
  let r = await X.settle(found, level, level >= 2 ? 6 : 3);
  drm = drm || r.drm;
  dash = dash || r.dash;
  if (!r.items.length && level >= 2) {
    method = 'browser';
    const b = await B.findInBrowser(url, { budget: wait || (level >= 3 ? 35 : 20), deep: level >= 3 });
    title = title || b.title;
    drm = drm || b.drm;
    dash = dash || b.dash;
    r = await X.settle(b.items, level, 6);
    drm = drm || r.drm;
    dash = dash || r.dash;
  }
  if (!r.items.length) {
    if (drm) throw X.fail('drm_protected');
    if (dash) throw X.fail('unsupported_format');
    throw X.fail('no_video');
  }
  return { items: r.items.map(view), title: String(title || '').slice(0, 160), method, drm };
}

const app = express();
app.disable('x-powered-by');
app.disable('etag');
app.set('trust proxy', false);

function deny(req, res) {
  req.socket.destroy();
}

app.use((req, res, next) => {
  if (req.method !== 'POST' || !ROUTES.has(req.path) || Object.keys(req.query).length) return deny(req, res);
  const type = String(req.get('content-type') || '').toLowerCase();
  if (!type.startsWith('application/json')) return deny(req, res);
  const t = Number(req.get('x-link-time'));
  const n = String(req.get('x-link-nonce') || '');
  if (!Number.isFinite(t) || Math.abs(Date.now() - t) > LINK_SKEW_MS || !NONCE_RE.test(n) || nonces.has(n)) return deny(req, res);
  req.linkTime = t;
  req.linkNonce = n;
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});

app.use(express.json({ limit: '32kb', strict: true }));

app.use((err, req, res, next) => {
  deny(req, res);
});

app.use((req, res, next) => {
  const pack = req.body && req.body.d;
  if (typeof pack !== 'string' || !PACK_RE.test(pack)) return deny(req, res);
  let body;
  try {
    body = unlock(pack, req.path + '.' + req.linkTime + '.' + req.linkNonce);
  } catch (e) {
    return deny(req, res);
  }
  if (!body || typeof body !== 'object' || typeof body.uid !== 'string' || !UID_RE.test(body.uid)) return deny(req, res);
  nonces.set(req.linkNonce, Date.now());
  req.body = body;
  const aad = 'res.' + req.linkNonce;
  const send = res.json.bind(res);
  res.json = (obj) => send({ d: lock(obj, aad) });
  next();
});

app.post('/health', (req, res) => {
  res.json({ ok: true, browser: B.available(), active, waiting: queue.length });
});

app.post('/find', async (req, res) => {
  const b = req.body;
  const url = typeof b.url === 'string' ? b.url.trim() : '';
  const level = [1, 2, 3].includes(b.level) ? b.level : 1;
  const wait = Number.isInteger(b.wait) && b.wait >= 5 && b.wait <= 60 ? b.wait : 0;
  if (!url || url.length > 1500) return res.status(400).json({ ok: false, error: 'invalid_url' });
  if (running.has(b.uid)) return res.status(429).json({ ok: false, error: 'busy' });
  running.set(b.uid, Date.now());
  let got = false;
  try {
    await slot();
    got = true;
    const limit = level >= 2 ? (wait || (level >= 3 ? 35 : 20)) * 1000 + 40000 : 45000;
    const r = await withTimeout(find(url, level, wait), limit);
    res.json(Object.assign({ ok: true }, r));
  } catch (e) {
    let code = e && ERRORS.has(e.code) ? e.code : 'no_video';
    if (e && e.code === 'browser_unavailable') code = 'no_video';
    const status = code === 'busy' ? 429 : code === 'timeout' ? 504 : 400;
    res.status(status).json({ ok: false, error: code, browser: B.available() });
  } finally {
    if (got) release();
    running.delete(b.uid);
  }
});

app.use((req, res) => {
  deny(req, res);
});

setInterval(() => {
  const now = Date.now();
  for (const [n, at] of nonces) if (now - at > LINK_SKEW_MS * 2) nonces.delete(n);
  for (const [u, at] of running) if (now - at > 180000) running.delete(u);
}, 30000).unref();

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('POP stream server ready on port ' + PORT + (B.available() ? ' (browser levels on)' : ' (browser levels off: install playwright-core and Chromium)'));
});
server.headersTimeout = 15000;
server.requestTimeout = 150000;
server.keepAliveTimeout = 5000;

async function stop() {
  await B.shutdown();
  process.exit(0);
}
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
process.on('unhandledRejection', () => {});
process.on('uncaughtException', (e) => {
  console.error('error', e && e.message);
});
