// Admin endpoint to manage per-brief passwords stored in KV at brief:pw:<slug>.
// public/middleware.js reads those keys to gate /clients/<slug>.
//
// Auth: either send the master password (env CLIENTS_MASTER_PW) in the
// "x-admin-pw" header (used by scripts/brief-pw.js), or have a valid master
// session cookie (fc_sess with scope "*", set by /api/unlock — used by the
// /clients admin UI). Disabled with 503 until CLIENTS_MASTER_PW is configured,
// so it is never an open write endpoint. Runs server-side where the KV
// credentials are real, so no secrets ever leave Vercel.
//
//   GET  /api/brief-pw?slug=sb-7f3a91     -> { slug, set: true|false }   (never returns the password)
//   POST /api/brief-pw  { slug, password } -> sets the brief password
//   POST /api/brief-pw  { slug, clear:true } -> removes it (brief becomes admin-only)
const crypto = require('crypto');

function creds() {
  var e = process.env;
  return {
    url: e.KV_REST_API_URL || e.UPSTASH_REDIS_REST_URL || e.STORAGE_KV_REST_API_URL || e.STORAGE_REST_API_URL || e.REDIS_REST_API_URL || '',
    token: e.KV_REST_API_TOKEN || e.UPSTASH_REDIS_REST_TOKEN || e.STORAGE_KV_REST_API_TOKEN || e.STORAGE_REST_API_TOKEN || e.REDIS_REST_API_TOKEN || ''
  };
}
function readBody(req) {
  return new Promise(function (resolve) {
    var d = '';
    req.on('data', function (c) { d += c; });
    req.on('end', function () { try { resolve(JSON.parse(d || '{}')); } catch (e) { resolve({}); } });
    req.on('error', function () { resolve({}); });
  });
}
function redis(url, token, cmd) {
  return fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
}
function safeEqual(a, b) {
  var ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ab, bb); } catch (e) { return false; }
}
function readCookie(req, name) {
  var h = (req.headers && req.headers.cookie) || '';
  var m = h.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}
// True only for a valid master session cookie (fc_sess, scope "*").
function hasMasterCookie(req, master) {
  var token = readCookie(req, 'fc_sess');
  if (!token || token.indexOf('.') < 0) return false;
  var i = token.indexOf('.'), p = token.slice(0, i), sig = token.slice(i + 1);
  var expect = crypto.createHmac('sha256', 'fcb1:' + master).update(p).digest('base64url');
  if (sig.length !== expect.length) return false;
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return false; } catch (e) { return false; }
  var payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch (e) { return false; }
  return !!payload && payload.s === '*' && typeof payload.e === 'number' && payload.e >= Math.floor(Date.now() / 1000);
}
var SLUG = /^[a-z0-9-]{1,64}$/;

module.exports = async function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  var master = process.env.CLIENTS_MASTER_PW || '';
  if (!master) { res.status(503).json({ error: 'admin_disabled' }); return; }

  var supplied = req.headers['x-admin-pw'];
  var authed = (typeof supplied === 'string' && safeEqual(supplied, master)) || hasMasterCookie(req, master);
  if (!authed) { res.status(401).json({ error: 'unauthorized' }); return; }

  var c = creds();
  if (!c.url || !c.token) { res.status(503).json({ error: 'storage_not_configured' }); return; }

  if (req.method === 'GET') {
    var slug = '';
    try { slug = new URL(req.url, 'http://x').searchParams.get('slug') || ''; } catch (e) {}
    if (!SLUG.test(slug)) { res.status(400).json({ error: 'bad_slug' }); return; }
    try {
      var r = await redis(c.url, c.token, ['GET', 'brief:pw:' + slug]);
      var j = await r.json();
      res.status(200).json({ slug: slug, set: !!(j && j.result) });
    } catch (e) { res.status(502).json({ error: 'read_exception', detail: String(e).slice(0, 200) }); }
    return;
  }

  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }

  var body = await readBody(req);
  var slug = String(body.slug || '');
  if (!SLUG.test(slug)) { res.status(400).json({ error: 'bad_slug' }); return; }

  try {
    if (body.clear === true) {
      await redis(c.url, c.token, ['DEL', 'brief:pw:' + slug]);
      res.status(200).json({ ok: true, cleared: true });
      return;
    }
    var pw = String(body.password || '');
    if (pw.length < 4) { res.status(400).json({ error: 'password_too_short' }); return; }
    var w = await redis(c.url, c.token, ['SET', 'brief:pw:' + slug, pw]);
    if (!w.ok) { var t = await w.text(); res.status(502).json({ error: 'write_failed', detail: t.slice(0, 200) }); return; }
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'write_exception', detail: String(e).slice(0, 200) });
  }
};
