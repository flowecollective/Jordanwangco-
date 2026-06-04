// Saves a client's "Your Voice" answers to the connected Vercel KV (Upstash Redis) store.
// No secrets in the repo: credentials come from env vars injected when the store is connected.
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
var SLUG = /^[a-z0-9-]{1,64}$/;
module.exports = async function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  var c = creds();
  if (!c.url || !c.token) { res.status(503).json({ error: 'storage_not_configured' }); return; }
  var body = await readBody(req);
  var slug = String(body.slug || '');
  if (!SLUG.test(slug)) { res.status(400).json({ error: 'bad_slug' }); return; }
  var answers = (body.answers && typeof body.answers === 'object') ? body.answers : {};
  var value = JSON.stringify({ answers: answers, updatedAt: new Date().toISOString() });
  try {
    var r = await redis(c.url, c.token, ['SET', 'brief:answers:' + slug, value]);
    if (!r.ok) { var t = await r.text(); res.status(502).json({ error: 'write_failed', detail: t.slice(0, 200) }); return; }
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'write_exception', detail: String(e).slice(0, 200) });
  }
};
