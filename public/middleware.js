export const config = { runtime: 'nodejs', matcher: ['/clients', '/clients/:path*'] };
export default function middleware(request) {
  const TEST_PW = 'pwtest123';
  const h = request.headers.get('authorization') || '';
  let pass = null;
  if (h.startsWith('Basic ')) {
    try { const d = Buffer.from(h.slice(6), 'base64').toString('utf8'); const i = d.indexOf(':'); pass = i === -1 ? '' : d.slice(i + 1); } catch (e) { pass = null; }
  }
  if (pass === TEST_PW) return; // PASS-THROUGH via undefined
  return new Response('TEST auth required', { status: 401, headers: { 'WWW-Authenticate': 'Basic realm="test"', 'content-type': 'text/plain' } });
}
