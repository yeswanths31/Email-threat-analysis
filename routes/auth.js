const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs/promises");

const router = express.Router();
const USERS_FILE = path.join(__dirname, "..", "data", "users.json");
async function readUsers() { try { return JSON.parse(await fs.readFile(USERS_FILE, "utf8")); } catch { return []; } }
async function writeUsers(users) { await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf8"); }
function configuredAdminEmail() { return String(process.env.ADMIN_EMAIL || "").trim().toLowerCase(); }
function roleFor(user) { return user.role === "admin" || (!!configuredAdminEmail() && user.email === configuredAdminEmail()) ? "admin" : "user"; }

async function verifyPassword(password, passwordHash) {
  if (String(passwordHash || "").startsWith("pbkdf2$")) {
    const parts = passwordHash.split("$");
    const iterations = Number(parts[1]);
    const salt = Buffer.from(parts[2], "hex");
    const expected = Buffer.from(parts[3], "hex");
    if (!Number.isInteger(iterations) || iterations < 100000 || !salt.length || !expected.length) return false;
    const actual = await new Promise((resolve, reject) => crypto.pbkdf2(password, salt, iterations, expected.length, "sha256", (err, key) => err ? reject(err) : resolve(key)));
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }
  return bcrypt.compare(password, passwordHash);
}

router.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || name.length > 60) return res.status(400).json({ error: "Name must be 2–60 characters." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Password must be 8–128 characters." });
    const users = await readUsers();
    if (users.some(u => u.email === email)) return res.status(409).json({ error: "An account with this email already exists." });
    const user = { id: crypto.randomUUID(), name, email, passwordHash: await bcrypt.hash(password, 12), role: "user", createdAt: new Date().toISOString() };
    users.push(user); await writeUsers(users);
    req.session.userId = user.id; req.session.userName = user.name; req.session.userRole = "user";
    res.status(201).json({ message: "Account created.", user: { id: user.id, name: user.name, email: user.email, role: "user" } });
  } catch (err) { console.error("Registration error:", err); res.status(500).json({ error: "Could not create account." }); }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const requestedRole = req.body.role === "admin" ? "admin" : "user";
    const users = await readUsers();
    const user = users.find(u => u.email === email);
    if (!user || !(await verifyPassword(password, user.passwordHash))) return res.status(401).json({ error: "Email or password is incorrect." });
    const actualRole = roleFor(user);
    if (actualRole !== requestedRole) return res.status(403).json({ error: requestedRole === "admin" ? "This account does not have administrator access." : "This is an administrator account. Choose Admin login." });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Could not start a secure session." });
      req.session.userId = user.id; req.session.userName = user.name; req.session.userRole = actualRole;
      res.json({ message: "Logged in.", user: { id: user.id, name: user.name, email: user.email, role: actualRole } });
    });
  } catch (err) { console.error("Login error:", err); res.status(500).json({ error: "Could not log in." }); }
});

router.post("/logout", (req, res) => {
  req.session.destroy(() => { res.clearCookie("eta.sid", { httpOnly: true, sameSite: "lax" }); res.json({ message: "Logged out." }); });
});
module.exports = router;
