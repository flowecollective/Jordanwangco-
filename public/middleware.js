// Password protection for /clients/* with a custom login page (no native
// browser username/password popup) and a signed session cookie.
//
// OFF BY DEFAULT: if CLIENTS_MASTER_PW is not set, every request passes through
// untouched, so deploying this can never lock out the live briefs.
//
// When CLIENTS_MASTER_PW is set:
//   - the master password (env) opens any brief + the /clients hub and template,
//   - each brief also opens with its own password stored in KV at brief:pw:<slug>
//     (set it without a redeploy via /api/brief-pw or scripts/brief-pw.js),
//   - unlocking sets an httpOnly, signed cookie (fc_sess) scoped to that brief
//     (or "*" for the master), so a client who unlocks one brief can't open
//     another, and credentials are never re-prompted for 30 days.
//
// Unauthorized requests get a small on-brand password page (POSTs to /api/unlock).

import { next } from '@vercel/functions';
import crypto from 'node:crypto';

export const config = {
  runtime: 'nodejs',
  matcher: ['/clients', '/clients/:path*'],
};

const COOKIE = 'fc_sess';
const RESERVED = { index: 1, 'client-brief-template': 1 };

function secretFrom(master) { return 'fcb1:' + master; }
function nowSec() { return Math.floor(Date.now() / 1000); }

function verifyToken(token, master) {
  if (!token || token.indexOf('.') < 0) return null;
  const i = token.indexOf('.');
  const p = token.slice(0, i), sig = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', secretFrom(master)).update(p).digest('base64url');
  if (sig.length !== expect.length) return null;
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null; } catch (e) { return null; }
  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!payload || typeof payload.e !== 'number' || payload.e < nowSec()) return null;
  return payload;
}

function readCookie(request, name) {
  const h = request.headers.get('cookie') || '';
  const m = h.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

export default function middleware(request) {
  const master = process.env.CLIENTS_MASTER_PW;
  if (!master) return next(); // protection disabled until a master password is configured

  const pathname = new URL(request.url).pathname;
  const rest = pathname.replace(/^\/clients\/?/, '').replace(/\/+$/, '');
  const slug = rest.split('/')[0];
  const adminOnly = !slug || RESERVED[slug];

  const payload = verifyToken(readCookie(request, COOKIE), master);
  if (payload) {
    if (payload.s === '*') return next();                  // master: opens everything
    if (!adminOnly && payload.s === slug) return next();   // brief session: opens its own brief
  }

  return new Response(loginPage(slug, adminOnly), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function loginPage(slug, adminOnly) {
  const heading = adminOnly ? 'Private hub' : 'A private brief';
  const sub = adminOnly
    ? 'Enter your password to continue.'
    : 'This page was prepared just for you. Enter the password from your stylist to open it.';
  const safeSlug = String(slug || '').replace(/[^a-z0-9-]/g, '');
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<meta name="color-scheme" content="dark"><meta name="robots" content="noindex, nofollow">' +
    '<meta name="referrer" content="no-referrer"><title>Private</title>' +
    '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@300;400;500;600&family=Instrument+Serif&display=swap" rel="stylesheet">' +
    '<style>' +
    ':root{color-scheme:dark;--paper:#1E1611;--bone:#F3ECDE;--soft:rgba(243,236,222,.72);--wheat:#D8C09A;--faint:rgba(243,236,222,.45);--line:rgba(243,236,222,.18);--line-strong:rgba(243,236,222,.42);}' +
    '*{margin:0;padding:0;box-sizing:border-box;}' +
    'body{background:var(--paper);color:var(--bone);font-family:"Hanken Grotesk",sans-serif;-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px;}' +
    'body::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.05;background-image:url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'120\' height=\'120\'%3E%3Cfilter id=\'n\'%3E%3CfeTurbulence type=\'fractalNoise\' baseFrequency=\'.9\' numOctaves=\'2\'/%3E%3C/filter%3E%3Crect width=\'100%25\' height=\'100%25\' filter=\'url(%23n)\'/%3E%3C/svg%3E");}' +
    '.card{position:relative;z-index:2;width:100%;max-width:360px;text-align:center;}' +
    '.kick{font-family:monospace;font-size:11px;letter-spacing:.32em;text-transform:uppercase;color:var(--wheat);}' +
    'h1{font-family:"Instrument Serif",serif;font-weight:400;font-size:34px;line-height:1.1;margin-top:14px;}' +
    'p.sub{font-size:13.5px;color:var(--soft);margin-top:12px;line-height:1.6;}' +
    'form{margin-top:26px;}' +
    'input{width:100%;background:rgba(243,236,222,.04);border:1px solid var(--line-strong);border-radius:6px;color:var(--bone);font-family:inherit;font-size:16px;padding:13px 15px;text-align:center;letter-spacing:.02em;}' +
    'input::placeholder{color:var(--faint);}input:focus{outline:none;border-color:var(--wheat);}' +
    'button{width:100%;margin-top:12px;background:var(--wheat);color:#211a13;border:none;border-radius:6px;font-family:inherit;font-size:14px;font-weight:600;letter-spacing:.04em;padding:13px;cursor:pointer;transition:opacity .15s;}' +
    'button:hover{opacity:.9;}button:disabled{opacity:.5;cursor:default;}' +
    '.err{min-height:18px;margin-top:14px;font-size:12.5px;color:#E5A3A3;letter-spacing:.02em;}' +
    '.lock{font-size:11px;color:var(--faint);margin-top:22px;letter-spacing:.06em;}' +
    '</style></head><body><div class="card">' +
    '<div class="kick">// Jordan Wang</div>' +
    '<h1>' + heading + '</h1>' +
    '<p class="sub">' + sub + '</p>' +
    '<form id="f" autocomplete="off">' +
    '<input id="pw" type="password" placeholder="Password" autofocus autocomplete="current-password" aria-label="Password">' +
    '<button id="b" type="submit">Open</button>' +
    '<div class="err" id="e" role="alert"></div>' +
    '</form>' +
    '<div class="lock">Private and unlisted</div>' +
    '</div><script>(function(){' +
    'var SLUG="' + safeSlug + '";' +
    'var f=document.getElementById("f"),pw=document.getElementById("pw"),b=document.getElementById("b"),e=document.getElementById("e");' +
    'f.addEventListener("submit",function(ev){ev.preventDefault();var v=pw.value;if(!v){return;}b.disabled=true;e.textContent="";' +
    'fetch("/api/unlock",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({slug:SLUG,password:v})})' +
    '.then(function(r){return r.json().then(function(j){return{ok:r.ok&&j&&j.ok};});})' +
    '.then(function(o){if(o.ok){location.reload();}else{e.textContent="That password didn\'t work. Try again.";b.disabled=false;pw.select();}})' +
    '.catch(function(){e.textContent="Something went wrong. Try again.";b.disabled=false;});});' +
    '})();</script></body></html>';
}
