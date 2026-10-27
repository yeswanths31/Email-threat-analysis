const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs/promises");

const authRoutes = require("./routes/auth");
const analysisRoutes = require("./routes/analysis");
const adminRoutes = require("./routes/admin");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");

async function ensureDataFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  for (const name of ["users.json", "scans.json"]) {
    const file = path.join(DATA_DIR, name);
    try { await fs.access(file); }
    catch { await fs.writeFile(file, "[]", "utf8"); }
  }
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

app.use(session({
  name: "eta.sid",
  secret: process.env.SESSION_SECRET || "local-development-secret-change-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 4
  }
}));

app.use("/api/auth", authRoutes);
app.use("/api/analysis", analysisRoutes);
app.use("/api/admin", adminRoutes);

app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/dashboard.html");
  return res.redirect("/login.html");
});

// Gate protected HTML pages before static serving so direct URL visits also require login.
app.use((req, res, next) => {
  const publicPages = ["/login.html", "/register.html"];
  const isHtmlPage = req.path.endsWith(".html");
  if (isHtmlPage && !publicPages.includes(req.path) && !req.session.userId) {
    return res.redirect("/login.html");
  }
  if (req.path === "/admin.html" && req.session.userRole !== "admin") {
    return res.status(403).send("Admin access required. Sign in with the configured admin account.");
  }
  if (isHtmlPage && publicPages.includes(req.path) && req.session.userId) {
    return res.redirect("/dashboard.html");
  }
  next();
});

app.use(express.static(path.join(__dirname, "public"), {
  index: false,
  dotfiles: "deny"
}));

app.get("/api/session", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: { id: req.session.userId, name: req.session.userName, role: req.session.userRole || "user" } });
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "API endpoint not found." });
  res.status(404).send("Page not found.");
});

ensureDataFiles().then(() => {
  app.listen(PORT, () => console.log(`Email Threat Analyzer running at http://localhost:${PORT}`));
}).catch(err => {
  console.error("Could not initialize data files:", err);
  process.exit(1);
});