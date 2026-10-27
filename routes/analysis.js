const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");
const path = require("path");
const fs = require("fs/promises");
const requireAuth = require("../middleware/auth");
const { analyzeEmail } = require("../services/threatDetector");
const { parseEmail } = require("../services/emailParser");
const { analyzeUrls } = require("../services/urlAnalyzer");

const router = express.Router();
const SCANS_FILE = path.join(__dirname, "..", "data", "scans.json");
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== ".eml") return cb(new Error("Only .eml files are accepted."));
    cb(null, true);
  }
});

async function readScans() {
  try { return JSON.parse(await fs.readFile(SCANS_FILE, "utf8")); }
  catch { return []; }
}
async function writeScans(scans) {
  await fs.writeFile(SCANS_FILE, JSON.stringify(scans, null, 2), "utf8");
}

router.use(requireAuth);

router.get("/stats", async (req, res) => {
  const scans = (await readScans()).filter(s => s.userId === req.session.userId);
  res.json({
    total: scans.length,
    highRisk: scans.filter(s => s.result.level === "High").length,
    suspiciousLinks: scans.reduce((n, s) => n + s.result.urls.filter(u => u.findings.length).length, 0),
    recent: scans.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 5).map(s => ({
      id: s.id, subject: s.subject || "(No subject)", level: s.result.level, score: s.result.score, createdAt: s.createdAt
    }))
  });
});

router.post("/url-scan", async (req, res) => {
  try {
    const input = String(req.body.url || "").trim().slice(0, 2048);
    if (!input) return res.status(400).json({ error: "Enter a URL to analyze." });
    if (!/^https?:\/\//i.test(input)) return res.status(400).json({ error: "Enter a full URL beginning with http:// or https://." });
    let parsed; try { parsed = new URL(input); } catch { return res.status(400).json({ error: "That URL is not valid." }); }
    if (!parsed.hostname || !parsed.hostname.includes(".")) return res.status(400).json({ error: "Enter a valid public-looking domain name." });
    const urls = analyzeUrls(input);
    const findings = urls.flatMap(u => u.findings.map(message => ({ title: message, detail: `URL pattern warning for ${u.domain || u.url}` })));
    const risk = urls.some(u => u.risk === "suspicious") ? "High" : urls.some(u => u.risk === "review") ? "Medium" : "Low";
    const score = risk === "High" ? 80 : risk === "Medium" ? 45 : 10;
    const result = { level: risk, score, category: "Standalone URL analysis", findings, urls, recommendations: risk === "Low" ? ["No obvious structural warning was detected; this does not prove the URL is safe."] : ["Do not enter passwords or payment details on this page.", "Verify the domain through an official source before opening the link."] };
    const scan = { id: crypto.randomUUID(), userId: req.session.userId, type: "url", subject: `URL: ${input}`, sender: "", url: input, result, createdAt: new Date().toISOString() };
    const scans = await readScans(); scans.push(scan); await writeScans(scans);
    res.status(201).json({ scan });
  } catch (err) { console.error("URL scan error:", err); res.status(500).json({ error: "Could not analyze this URL." }); }
});

router.post("/scan", async (req, res) => {
  try {
    const subject = String(req.body.subject || "").slice(0, 300);
    const sender = String(req.body.sender || "").slice(0, 300);
    const replyTo = String(req.body.replyTo || "").slice(0, 300);
    const body = String(req.body.body || "");
    if (!body.trim()) return res.status(400).json({ error: "Enter the email body before analyzing." });
    if (body.length > 50000) return res.status(413).json({ error: "Email body must be 50,000 characters or fewer." });

    const result = analyzeEmail({ subject, sender, replyTo, body });
    const scan = {
      id: crypto.randomUUID(),
      userId: req.session.userId,
      subject,
      sender,
      replyTo,
      body: body.slice(0, 50000),
      result,
      createdAt: new Date().toISOString()
    };
    const scans = await readScans();
    scans.push(scan);
    await writeScans(scans);
    res.status(201).json({ scan: { id: scan.id, subject, sender, replyTo, result, createdAt: scan.createdAt } });
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: "Could not analyze this email." });
  }
});

router.post("/upload", upload.single("emailFile"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Choose an .eml file to upload." });
    const raw = req.file.buffer.toString("utf8");
    if (raw.includes("\u0000")) return res.status(400).json({ error: "The file does not appear to be a readable text email." });
    const parsed = parseEmail(raw);
    if (!parsed.body.trim() && !parsed.subject) return res.status(400).json({ error: "Could not find readable email content in this file." });

    const result = analyzeEmail({ subject: parsed.subject, sender: parsed.from, replyTo: parsed.replyTo, body: parsed.body, authenticationResults: parsed.authenticationResults });
    const scan = {
      id: crypto.randomUUID(),
      userId: req.session.userId,
      subject: parsed.subject,
      sender: parsed.from,
      replyTo: parsed.replyTo,
      body: parsed.body.slice(0, 50000),
      result,
      createdAt: new Date().toISOString(),
      sourceFile: req.file.originalname.slice(0, 150)
    };
    const scans = await readScans();
    scans.push(scan);
    await writeScans(scans);
    res.status(201).json({ scan: { id: scan.id, subject: scan.subject, sender: scan.sender, replyTo: scan.replyTo, result, createdAt: scan.createdAt } });
  } catch (err) {
    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "The .eml file must be 1 MB or smaller." });
    if (err.message === "Only .eml files are accepted.") return res.status(400).json({ error: err.message });
    console.error("Upload error:", err);
    res.status(500).json({ error: "Could not process the email file." });
  }
});

router.get("/history", async (req, res) => {
  const scans = (await readScans()).filter(s => s.userId === req.session.userId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map(s => ({ id: s.id, subject: s.subject, sender: s.sender, result: s.result, createdAt: s.createdAt }));
  res.json({ scans });
});

router.get("/report/:id", async (req, res) => {
  const scan = (await readScans()).find(s => s.id === req.params.id && s.userId === req.session.userId);
  if (!scan) return res.status(404).json({ error: "Report not found." });
  res.json({ scan });
});

router.get("/report/:id/download", async (req, res) => {
  const scan = (await readScans()).find(s => s.id === req.params.id && s.userId === req.session.userId);
  if (!scan) return res.status(404).json({ error: "Report not found." });
  const safeName = `email-threat-report-${scan.id}.json`;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
  res.send(JSON.stringify({
    reportId: scan.id, subject: scan.subject, sender: scan.sender,
    analyzedAt: scan.createdAt, result: scan.result,
    note: "Heuristic screening only. Not a guarantee of safety or maliciousness."
  }, null, 2));
});

router.get("/report/:id/download.pdf", async (req, res) => {
  const scan = (await readScans()).find(s => s.id === req.params.id && s.userId === req.session.userId);
  if (!scan) return res.status(404).json({ error: "Report not found." });

  const result = scan.result || {};
  const safeId = String(scan.id).replace(/[^a-zA-Z0-9_-]/g, "");
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="threat-analysis-report-${safeId}.pdf"`);
  const doc = new PDFDocument({ size: "A4", margin: 48, info: { Title: "Threat Analysis Report", Author: "Email Threat Analyzer" } });
  doc.pipe(res);

  const clean = value => String(value == null || value === "" ? "Not provided" : value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .replace(/[\u{1F000}-\u{1FAFF}]/gu, "[symbol]");
  const heading = title => { doc.moveDown(0.7).font("Helvetica-Bold").fontSize(13).fillColor("#17324d").text(title); doc.moveDown(0.25); doc.font("Helvetica").fontSize(10).fillColor("#202938"); };
  const line = (label, value) => doc.font("Helvetica-Bold").text(`${label}: `, { continued: true }).font("Helvetica").text(clean(value));
  const bullet = value => doc.text(`• ${clean(value)}`, { indent: 12, hanging: 3, lineGap: 3 });

  doc.font("Helvetica-Bold").fontSize(22).fillColor("#17324d").text("THREAT ANALYSIS REPORT");
  doc.moveDown(0.25).font("Helvetica").fontSize(9).fillColor("#667085").text("Email Threat Analyzer | Automated security screening");
  doc.moveDown(0.8).roundedRect(48, doc.y, 499, 98, 8).fillAndStroke("#f2f6fb", "#d6e0ec");
  const cardY = doc.y + 13;
  doc.fillColor("#202938").font("Helvetica-Bold").fontSize(12).text(`Risk level: ${clean(result.level || "Unknown")}`, 62, cardY);
  doc.font("Helvetica-Bold").fontSize(18).text(`Risk score: ${Number(result.score) || 0}/100`, 62, cardY + 25);
  doc.font("Helvetica").fontSize(9).fillColor("#667085").text(clean(result.category || "Threat analysis"), 62, cardY + 52, { width: 465 });
  doc.y = cardY + 96;

  heading("Analysis details");
  line("Subject / URL", scan.subject || scan.url);
  line("Sender", scan.sender || "Not applicable for standalone URL scans");
  line("Analysis date", new Date(scan.createdAt || Date.now()).toLocaleString());
  line("Detection engine", result.engine || "Heuristic pattern analysis");

  heading("Findings and explanations");
  const findings = Array.isArray(result.findings) ? result.findings : [];
  if (!findings.length) bullet("No configured warning rules matched. This does not prove the message or URL is safe.");
  findings.forEach(f => {
    const title = f.category || f.title || "Finding";
    const detail = f.explanation || f.detail || "A warning pattern was detected.";
    bullet(`${title}: ${detail}${Number.isFinite(Number(f.points)) && f.points ? ` (risk points: +${Number(f.points)})` : ""}`);
  });

  heading("URLs reviewed");
  const urls = Array.isArray(result.urls) ? result.urls : (scan.url ? [{ url: scan.url, domain: "", findings: [] }] : []);
  if (!urls.length) bullet("No URLs were extracted from the supplied email content.");
  urls.forEach(u => {
    const notes = Array.isArray(u.findings) && u.findings.length ? u.findings.join("; ") : "No obvious structural warning recorded";
    bullet(`${u.url || "URL"}${u.domain ? ` (domain: ${u.domain})` : ""} — ${notes}`);
  });

  heading("Recommended actions");
  const recommendations = Array.isArray(result.recommendations) ? result.recommendations : [];
  if (!recommendations.length) bullet("Verify suspicious messages or domains through an official channel before taking action.");
  recommendations.forEach(bullet);

  heading("Important limitations");
  doc.font("Helvetica").fontSize(9).fillColor("#596579").text(clean(result.disclaimer || "This report is based on heuristic checks and URL structure patterns. It does not guarantee that a message or URL is safe or malicious, and it may miss new or targeted threats."), { lineGap: 3 });
  doc.moveDown(0.5).font("Helvetica-Bold").fontSize(9).fillColor("#17324d").text("Safety note");
  doc.font("Helvetica").fontSize(9).fillColor("#596579").text("Do not enter passwords, payment details, or verification codes on suspicious sites. Confirm requests through a known, trusted contact method.", { lineGap: 3 });
  doc.moveDown(1).font("Helvetica").fontSize(8).fillColor("#7a8494").text(`Report ID: ${safeId} | Generated by Email Threat Analyzer`, { align: "center" });
  doc.end();
});

router.delete("/history/:id", async (req, res) => {
  const scans = await readScans();
  const next = scans.filter(s => !(s.id === req.params.id && s.userId === req.session.userId));
  if (next.length === scans.length) return res.status(404).json({ error: "Scan not found." });
  await writeScans(next);
  res.json({ message: "Scan deleted." });
});

module.exports = router;