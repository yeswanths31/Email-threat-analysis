const express = require("express");
const path = require("path");
const fs = require("fs/promises");
const requireAdmin = require("../middleware/admin");
const router = express.Router();
const USERS_FILE = path.join(__dirname, "..", "data", "users.json");
const SCANS_FILE = path.join(__dirname, "..", "data", "scans.json");
async function read(file) { try { return JSON.parse(await fs.readFile(file, "utf8")); } catch { return []; } }
router.use(requireAdmin);
router.get("/overview", async (req, res) => {
  const [users, scans] = await Promise.all([read(USERS_FILE), read(SCANS_FILE)]);
  const ordered = scans.slice().sort((a,b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  res.json({
    stats: { users: users.length, scans: scans.length, highRisk: scans.filter(s => s.result && s.result.level === "High").length, urlScans: scans.filter(s => s.type === "url").length },
    users: users.map(u => ({ id:u.id, name:u.name, email:u.email, role:(u.role === "admin" || (String(process.env.ADMIN_EMAIL || "").trim().toLowerCase() && u.email === String(process.env.ADMIN_EMAIL || "").trim().toLowerCase()) ? "admin" : "user"), createdAt:u.createdAt })),
    recent: ordered.slice(0,30).map(s => ({ id:s.id, type:s.type || "email", userEmail:(users.find(u=>u.id===s.userId)||{}).email || "Unknown", subject:s.subject || "URL analysis", level:s.result?.level || "Unknown", score:s.result?.score ?? 0, createdAt:s.createdAt }))
  });
});
module.exports = router;
