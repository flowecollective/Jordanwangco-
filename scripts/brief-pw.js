#!/usr/bin/env node
// Set, read, or clear a per-brief password (stored in KV at brief:pw:<slug>,
// read by public/middleware.js to gate /clients/<slug>). No redeploy needed.
//
// This talks to the deployed admin endpoint /api/brief-pw, authenticated with
// the master password, so you never need the KV credentials locally.
//
//   export CLIENTS_MASTER_PW='your-master-password'   # or pass --pw=...
//   node scripts/brief-pw.js set   sb-7f3a91 "their-password"
//   node scripts/brief-pw.js get   sb-7f3a91
//   node scripts/brief-pw.js clear sb-7f3a91
//
// Base URL defaults to the production site; override with --url=... or BRIEF_BASE_URL.

const DEFAULT_BASE = 'https://www.jordanwangco.com';

const argv = process.argv.slice(2);
const flags = {};
const pos = [];
for (const a of argv) {
  const m = a.match(/^--([a-z]+)=(.*)$/);
  if (m) flags[m[1]] = m[2]; else pos.push(a);
}
const [cmd, slug, pw] = pos;

const base = (flags.url || process.env.BRIEF_BASE_URL || DEFAULT_BASE).replace(/\/+$/, '');
const master = flags.pw || process.env.CLIENTS_MASTER_PW || '';
const SLUG = /^[a-z0-9-]{1,64}$/;

function die(msg) { console.error(msg); process.exit(1); }
if (!master) die('Missing master password. Set CLIENTS_MASTER_PW or pass --pw=...');
if (!cmd || !['set', 'get', 'clear'].includes(cmd)) die('Usage: node scripts/brief-pw.js <set|get|clear> <slug> [password] [--url=...] [--pw=...]');
if (!slug || !SLUG.test(slug)) die('Bad slug. Use lowercase letters, digits, and hyphens (e.g. sb-7f3a91).');
if (cmd === 'set' && !pw) die('set needs a password: node scripts/brief-pw.js set ' + slug + ' "the-password"');

async function call(method, body) {
  const url = base + '/api/brief-pw' + (method === 'GET' ? '?slug=' + encodeURIComponent(slug) : '');
  const res = await fetch(url, {
    method,
    headers: Object.assign({ 'x-admin-pw': master }, body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let j; try { j = JSON.parse(text); } catch (e) { j = { raw: text }; }
  if (!res.ok) die('Request failed (' + res.status + '): ' + (j.error || text).toString().slice(0, 200));
  return j;
}

(async () => {
  if (cmd === 'set') { await call('POST', { slug, password: pw }); console.log('Set password for ' + slug + '.'); }
  else if (cmd === 'clear') { await call('POST', { slug, clear: true }); console.log('Cleared password for ' + slug + ' (now admin-only).'); }
  else { const j = await call('GET'); console.log(slug + ': ' + (j.set ? 'password is set' : 'no password (admin-only)')); }
})().catch((err) => die(String(err)));
