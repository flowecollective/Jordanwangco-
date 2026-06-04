// Loads a client's saved "Your Voice" answers from the connected Vercel KV (Upstash Redis) store.
function creds() {
  var e = process.env;
  return {
    url: e.KV_REST_API_URL || e.UPSTASH_REDIS_REST_URL || e.STORAGE_KV_REST_API_URL || e.STORAGE_REST_API_URL || e.REDIS_REST_API_URL || '',
    token: e.KV_REST_API_TOKEN || e.UPSTASH_REDIS_REST_TOKEN || e.STORAGE_KV_REST_API_TOKEN || e.STORAGE_REST_API_TOKEN || e.REDIS_REST_API_TOKEN || ''
  };
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
  var c = creds();
  if (!c.url || !c.token) { res.status(503).json({ error: 'storage_not_configured' }); return; }
  var slug = '';
  try { slug = new URL(req.url, 'http://x').searchParams.get('slug') || ''; } catch (e) {}
  if (!SLUG.test(slug)) { res.status(400).json({ error: 'bad_slug' }); return; }
  try {
    var r = await redis(c.url, c.token, ['GET', 'brief:answers:' + slug]);
    if (!r.ok) { res.status(502).json({ error: 'read_failed' }); return; }
    var j = await r.json();
    var data = null;
    if (j && j.result) { try { data = JSON.parse(j.result); } catch (e) {} }
    res.status(200).json({ slug: slug, data: data });
  } catch (e) {
    res.status(502).json({ error: 'read_exception', detail: String(e).slice(0, 200) });
  }
};
