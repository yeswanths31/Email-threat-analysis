module.exports = function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Please sign in." });
  if (req.session.userRole !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
};
