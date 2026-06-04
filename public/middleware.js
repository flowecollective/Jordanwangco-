// Per-brief password protection for /clients/*.
//
// OFF BY DEFAULT: if CLIENTS_MASTER_PW is not set, every request passes through
// untouched, so deploying this can never break or lock out the live briefs.
//
// When CLIENTS_MASTER_PW is set, protection turns on:
//   - the master password opens any brief (for you, the stylist),
//   - each brief also opens with its own env var PW_<slug>, where the slug's
//     non-alphanumeric characters become "_"  (e.g. sb-7f3a91 -> PW_sb_7f3a91),
//   - the /clients index and the template are admin-only (master password),
//   - a brief with no PW_<slug> configured is admin-only (fails closed).
//
// Basic Auth: the browser shows a native password prompt. The realm is the brief
// slug, so credentials cached for one brief are not reused on another.

import { next } from '@vercel/functions';

export const config = {
  runtime: 'nodejs',
  matcher: ['/clients', '/clients/:path*'],
};

export default function middleware(request) {
  const master = process.env.CLIENTS_MASTER_PW;
  if (!master) return next(); // protection disabled until a master password is configured

  const pathname = new URL(request.url).pathname;
  const rest = pathname.replace(/^\/clients\/?/, '').replace(/\/+$/, '');
  const slug = rest.split('/')[0];

  const adminOnly = !slug || slug === 'index' || slug === 'client-brief-template';
  const envKey = 'PW_' + slug.replace(/[^a-zA-Z0-9]/g, '_');
  const briefPw = adminOnly ? '' : (process.env[envKey] || '');

  const supplied = basicPassword(request);
  if (supplied !== null && (supplied === master || (briefPw && supplied === briefPw))) {
    return next(); // authorized -> continue to the page
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
