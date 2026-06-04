// Per-brief password protection for /clients/*.
//
// OFF BY DEFAULT: if CLIENTS_MASTER_PW is not set, every request passes through
// untouched, so deploying this can never break or lock out the live briefs.
//
// When CLIENTS_MASTER_PW is set, protection turns on:
//   - the master password (env CLIENTS_MASTER_PW) opens any brief (for you, the
//     stylist) and is the fail-safe key even if KV is empty or unreachable,
//   - each brief also opens with its own password stored in KV at
//     "brief:pw:<slug>" (set it without a redeploy; see scripts/brief-pw.js),
//   - the /clients index and the template are admin-only (master password),
//   - a brief with no KV password configured is admin-only (fails closed).
//
// Basic Auth: the browser shows a native password prompt. The realm is the brief
// slug, so credentials cached for one brief are not reused on another. KV is only
// read when a non-master password is actually supplied, so first visits and your
// own master logins never touch KV.

import { next } from '@vercel/functions';

export const config = {
  runtime: 'nodejs',
  matcher: ['/clients', '/clients/:path*'],
};

function kvCreds() {
  var e = process.env;
  return {
    url: e.KV_REST_API_URL || e.UPSTASH_REDIS_REST_URL || e.STORAGE_KV_REST_API_URL || e.STORAGE_REST_API_URL || e.REDIS_REST_API_URL || '',
    token: e.KV_REST_API_TOKEN || e.UPSTASH_REDIS_REST_TOKEN || e.STORAGE_KV_REST_API_TOKEN || e.STORAGE_REST_API_TOKEN || e.REDIS_REST_API_TOKEN || '',
  };
}

async function kvGet(key) {
  var c = kvCreds();
  if (!c.url || !c.token) return null;
  try {
    var r = await fetch(c.url, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
      body: JSON.stringify(['GET', key]),
    });
    if (!r.ok) return null;
    var j = await r.json();
    return j && typeof j.result === 'string' ? j.result : null;
  } catch (e) {
    return null;
  }
}

export default async function middleware(request) {
  const master = process.env.CLIENTS_MASTER_PW;
  if (!master) return next(); // protection disabled until a master password is configured

  const pathname = new URL(request.url).pathname;
  const rest = pathname.replace(/^\/clients\/?/, '').replace(/\/+$/, '');
  const slug = rest.split('/')[0];

  const adminOnly = !slug || slug === 'index' || slug === 'client-brief-template';
  const supplied = basicPassword(request);

  // No credentials yet -> prompt immediately, no KV read.
  if (supplied !== null) {
    if (supplied === master) return next(); // your master key, always works, never hits KV
    if (!adminOnly) {
      const briefPw = await kvGet('brief:pw:' + slug); // only read KV when a non-master pw is tried
      if (briefPw && supplied === briefPw) return next();
    }
  }

  const realm = adminOnly ? 'Client briefs' : slug;
  return new Response('This page is private. A password is required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="' + realm + '", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}

function basicPassword(request) {
  const header = request.headers.get('authorization') || '';
  const sp = header.indexOf(' ');
  const scheme = sp === -1 ? header : header.slice(0, sp);
  const encoded = sp === -1 ? '' : header.slice(sp + 1);
  if (scheme !== 'Basic' || !encoded) return null;
  let decoded;
  try { decoded = Buffer.from(encoded, 'base64').toString('utf8'); }
  catch (e) { return null; }
  const i = decoded.indexOf(':');
  return i === -1 ? '' : decoded.slice(i + 1);
}
