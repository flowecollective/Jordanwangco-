module.exports = (req, res) => {
  res.status(200).json({ ok: true, where: 'public/api/ping2' });
};
