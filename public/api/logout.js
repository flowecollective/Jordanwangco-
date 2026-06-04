// Clears the fc_sess session cookie. POST or GET /api/logout
module.exports = function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Set-Cookie', 'fc_sess=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  res.status(200).json({ ok: true });
};
