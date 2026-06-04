// Validates a brief password (or the master password) and, on success, sets a
// signed httpOnly session cookie (fc_sess) that public/middleware.js trusts.
//   POST /api/unlock  { slug, password }  ->  { ok:true, scope:"*"|<slug> }  + Set-Cookie
// The master password grants scope "*" (opens everything). A correct brief
// password (KV brief:pw:<slug>) grants scope <slug> only.
const crypto = require('crypto');

const COOKIE = 'fc_sess';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const SLUG = /^[a-z0-9-]{1,64}$/;
const RESERVED = { index: 1, 'client-brief-template': 1 };

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
function sign(scope, master) {
  var payload = { s: scope, e: Math.floor(Date.now() / 1000) + MAX_AGE };
  var p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  var sig = crypto.createHmac('sha256', 'fcb1:' + master).update(p).digest('base64url');
  return p + '.' + sig;
}
function setCookie(res, token) {
  res.setHeader('Set-Cookie', COOKIE + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + MAX_AGE);
}

module.exports = async function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  var master = process.env.CLIENTS_MASTER_PW || '';
  if (!master) { res.status(503).json({ error: 'protection_disabled' }); return; }

  var body = await readBody(req);
  var slug = String(body.slug || '');
  var password = String(body.password || '');
  if (!password) { res.status(400).json({ error: 'no_password' }); return; }

  // Master password opens everything.
  if (safeEqual(password, master)) {
    setCookie(res, sign('*', master));
    res.status(200).json({ ok: true, scope: '*' });
    return;
  }

  // Otherwise it must match this specific brief's password in KV.
  if (!SLUG.test(slug) || RESERVED[slug]) { res.status(401).json({ error: 'wrong' }); return; }
  var c = creds();
  if (!c.url || !c.token) { res.status(503).json({ error: 'storage_not_configured' }); return; }
  try {
    var r = await redis(c.url, c.token, ['GET', 'brief:pw:' + slug]);
    var j = await r.json();
    var stored = j && typeof j.result === 'string' ? j.result : '';
    if (stored && safeEqual(password, stored)) {
      setCookie(res, sign(slug, master));
      res.status(200).json({ ok: true, scope: slug });
      return;
    }
    res.status(401).json({ error: 'wrong' });
  } catch (e) {
    res.status(502).json({ error: 'read_exception', detail: String(e).slice(0, 200) });
  }
};
