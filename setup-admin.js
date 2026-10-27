const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const USERS_FILE = path.join(__dirname, "data", "users.json");

function hiddenPrompt(label) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || !process.stdin.setRawMode) {
      const readline = require("readline");
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(label + " (input may be visible in this terminal): ", value => { rl.close(); resolve(value); });
      return;
    }
    process.stdout.write(label);
    let value = "";
    const onData = chunk => {
      const key = chunk.toString("utf8");
      if (key === "\u0003") { process.stdin.setRawMode(false); process.stdin.pause(); reject(new Error("Cancelled.")); return; }
      if (key === "\r" || key === "\n") {
        process.stdin.removeListener("data", onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stdout.write("\n"); resolve(value); return;
      }
      if (key === "\u007f" || key === "\b") { value = value.slice(0, -1); return; }
      if (key >= " " && key.length === 1) value += key;
    };
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on("data", onData);
  });
}

(async () => {
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.error("Set ADMIN_EMAIL first, for example: set ADMIN_EMAIL=you@example.com");
    process.exitCode = 1; return;
  }
  const name = String(process.env.ADMIN_NAME || "MailGuard Admin").trim().slice(0, 60) || "MailGuard Admin";
  const password = await hiddenPrompt("Enter the admin password (minimum 8 characters): ");
  if (password.length < 8 || password.length > 128) { console.error("Password must be 8–128 characters."); process.exitCode = 1; return; }
  await fs.mkdir(path.dirname(USERS_FILE), { recursive: true });
  let users = [];
  try { users = JSON.parse(await fs.readFile(USERS_FILE, "utf8")); } catch {}
  const now = new Date().toISOString();
  const existing = users.find(u => String(u.email || "").toLowerCase() === email);
  const account = {
    id: existing?.id || crypto.randomUUID(),
    name: existing?.name || name,
    email,
    passwordHash: await bcrypt.hash(password, 12),
    role: "admin",
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
  if (existing) Object.assign(existing, account);
  else users.push(account);
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
  console.log("Admin account configured successfully. Password saved as a bcrypt hash.");
  console.log("Select Admin login on the sign-in page to open the admin dashboard.");
})().catch(err => { console.error("Could not configure admin account:", err.message); process.exitCode = 1; });
