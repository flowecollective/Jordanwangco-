#!/usr/bin/env node
// Set, read, or clear a per-brief password in the Upstash KV store.
// Passwords are stored at key  brief:pw:<slug>  and read by public/middleware.js.
// No redeploy needed: changes take effect on the next request.
//
// Credentials come from the same env vars the app uses. The easiest way to load
// them locally is to pull them from Vercel first:
//
//   cd Jordanwangco- && vercel env pull .env.local   # one time / when they change
//   node scripts/brief-pw.js set   sb-7f3a91 "their-password"
//   node scripts/brief-pw.js get   sb-7f3a91
//   node scripts/brief-pw.js clear sb-7f3a91
//
// (If you don't use vercel env pull, export KV_REST_API_URL and
//  KV_REST_API_TOKEN in your shell before running.)

const fs = require('fs');
const path = require('path');

// Load .env.local / .env if present (so `vercel env pull` just works).
for (const f of ['.env.local', '.env']) {
  const p = path.join(process.cwd(), f);
  if (!fs.existsSync(p)) continue;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  }
}

const e = process.env;
const URL_ = e.KV_REST_API_URL || e.UPSTASH_REDIS_REST_URL || e.STORAGE_KV_REST_API_URL || e.STORAGE_REST_API_URL || e.REDIS_REST_API_URL || '';
const TOKEN = e.KV_REST_API_TOKEN || e.UPSTASH_REDIS_REST_TOKEN || e.STORAGE_KV_REST_API_TOKEN || e.STORAGE_REST_API_TOKEN || e.REDIS_REST_API_TOKEN || '';

const SLUG = /^[a-z0-9-]{1,64}$/;
const [cmd, slug, pw] = process.argv.slice(2);

function die(msg) { console.error(msg); process.exit(1); }
if (!URL_ || !TOKEN) die('Missing KV credentials. Run `vercel env pull .env.local` or export KV_REST_API_URL / KV_REST_API_TOKEN.');
if (!cmd || !['set', 'get', 'clear'].includes(cmd)) die('Usage: node scripts/brief-pw.js <set|get|clear> <slug> [password]');
if (!slug || !SLUG.test(slug)) die('Bad slug. Use lowercase letters, digits, and hyphens (e.g. sb-7f3a91).');
if (cmd === 'set' && !pw) die('set needs a password: node scripts/brief-pw.js set ' + slug + ' "the-password"');

async function redis(args) {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  if (!r.ok) die('KV request failed: ' + r.status + ' ' + (await r.text()).slice(0, 200));
  return r.json();
}

(async () => {
  const key = 'brief:pw:' + slug;
  if (cmd === 'set') {
    await redis(['SET', key, pw]);
    console.log('Set password for ' + slug + '.');
  } else if (cmd === 'get') {
    const j = await redis(['GET', key]);
    console.log(j && j.result ? slug + ': ' + j.result : 'No password set for ' + slug + ' (brief is admin-only).');
  } else if (cmd === 'clear') {
    await redis(['DEL', key]);
    console.log('Cleared password for ' + slug + ' (now admin-only).');
  }
})().catch((err) => die(String(err)));
