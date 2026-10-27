function safeText(value) { return String(value || "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c])); }
function setupCommon() {
  if (localStorage.getItem("eta-theme") === "dark") document.body.classList.add("dark");
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => btn.addEventListener("click", () => { document.body.classList.toggle("dark"); localStorage.setItem("eta-theme", document.body.classList.contains("dark") ? "dark" : "light"); }));
  document.querySelectorAll("[data-logout]").forEach(btn => btn.addEventListener("click", async () => { await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login.html"; }));
}
function renderReport(scan) {
  const r = scan.result;
  const findings = r.findings.length ? r.findings.map(f => `<div class="finding"><div class="finding-icon">!</div><div><strong>${safeText(f.category)}</strong><p>${safeText(f.explanation)}</p><span class="points">Risk points: +${f.points}</span></div></div>`).join("") : '<div class="empty-state">No configured warning rules matched this message. This does not mean it is safe.</div>';
  const urls = r.urls.length ? r.urls.map(u => `<div class="url-item"><code>${safeText(u.url)}</code><p>Domain: ${safeText(u.domain || "Unparsed")} · ${safeText(u.findings.length ? u.findings.join("; ") : "No obvious structural warning found")}</p></div>`).join("") : '<p class="muted">No URLs detected in the supplied text.</p>';
  const recommendations = r.recommendations.map(x => `<li>${safeText(x)}</li>`).join("");
  document.getElementById("reportContent").innerHTML = `
    <section class="panel report-hero"><div class="score-circle"><div><div class="score-number">${r.score}</div><div class="score-caption">RISK SCORE / 100</div></div></div><div class="report-summary"><span class="risk-chip ${r.level.toLowerCase()}">${safeText(r.level)} risk</span><h2>${safeText(r.category)}</h2><p class="muted">${safeText(scan.subject || "(No subject)")}</p><div class="report-meta">Sender: ${safeText(scan.sender || "Not supplied")}<br>Analyzed: ${new Date(scan.createdAt).toLocaleString()}<br>Engine: ${safeText(r.engine)}</div><div class="report-actions"><a class="btn primary" href="/api/analysis/report/${encodeURIComponent(scan.id)}/download.pdf">↓ Download PDF report</a><button class="btn secondary" type="button" id="downloadHtmlReport">Download HTML (optional)</button><a class="btn secondary" href="/analyzer.html">＋ Analyze another</a></div></div></section>
    <section class="panel"><div class="report-section-title"><span class="guidance-icon">⌕</span><h3>Why this score?</h3></div><div class="finding-list">${findings}</div></section>
    <section class="panel"><div class="report-section-title"><span class="guidance-icon">↗</span><h3>Extracted URLs</h3></div>${urls}</section>
    <section class="panel"><div class="report-section-title"><span class="guidance-icon">✓</span><h3>Recommended next steps</h3></div><ol class="recommendations">${recommendations}</ol></section>
    <section class="panel"><strong>Detection limitations</strong><p class="muted" style="font-size:11px;margin-top:8px;line-height:1.7">${safeText(r.disclaimer)}</p></section>`;
}

function downloadHtmlReport(scan) {
  const r = scan.result;
  const esc = value => safeText(value);
  const findings = r.findings.length
    ? `<ul>${r.findings.map(f => `<li><strong>${esc(f.category)}</strong>: ${esc(f.explanation)} (risk points: +${Number(f.points) || 0})</li>`).join("")}</ul>`
    : "<p>No configured warning rules matched. This does not prove the email is safe.</p>";
  const urls = r.urls.length
    ? `<ul>${r.urls.map(u => `<li><code>${esc(u.url)}</code> — ${esc(u.findings.length ? u.findings.join("; ") : "No obvious structural warning found")}</li>`).join("")}</ul>`
    : "<p>No URLs detected.</p>";
  const recommendations = `<ul>${r.recommendations.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Email Threat Analysis Report</title><style>body{font:16px/1.6 Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#172033}h1,h2{color:#172033}.score{font-size:30px;font-weight:bold}.meta,.disclaimer{color:#596579}.panel{border:1px solid #d9dfeb;border-radius:12px;padding:20px;margin:18px 0;overflow-wrap:anywhere}code{white-space:pre-wrap;overflow-wrap:anywhere}li{margin:8px 0}@media print{body{margin:0}.panel{break-inside:avoid}}</style></head><body><h1>Email Threat Analyzer — Report</h1><section class="panel"><div class="score">Risk score: ${Number(r.score) || 0}/100</div><h2>${esc(r.level)} risk — ${esc(r.category)}</h2><p><strong>Subject:</strong> ${esc(scan.subject || "(No subject)")}</p><p><strong>Sender:</strong> ${esc(scan.sender || "Not supplied")}</p><p><strong>Analyzed:</strong> ${esc(new Date(scan.createdAt).toLocaleString())}</p><p><strong>Detection engine:</strong> ${esc(r.engine)}</p></section><section class="panel"><h2>Why this score?</h2>${findings}</section><section class="panel"><h2>Extracted URLs</h2>${urls}</section><section class="panel"><h2>Recommended next steps</h2>${recommendations}</section><section class="panel disclaimer"><h2>Limitations</h2>${esc(r.disclaimer)}<p>This is an automated screening result, not a guarantee of safety or maliciousness.</p></section></body></html>`;
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `email-threat-report-${String(scan.id).replace(/[^a-zA-Z0-9_-]/g, "")}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

document.addEventListener("DOMContentLoaded", async () => {
  setupCommon();
  const id = new URLSearchParams(location.search).get("id");
  if (!id) { document.getElementById("reportContent").innerHTML = '<section class="panel"><p class="muted">No report ID provided. Open a report from scan history.</p><a class="btn primary" href="/history.html">Go to history</a></section>'; return; }
  try {
    const res = await fetch(`/api/analysis/report/${encodeURIComponent(id)}`);
    if (res.status === 401) { location.href = "/login.html"; return; }
    const data = await res.json(); if (!res.ok) throw new Error(data.error || "Could not load report.");
    renderReport(data.scan);
    const downloadButton = document.getElementById("downloadHtmlReport");
    if (downloadButton) downloadButton.addEventListener("click", () => downloadHtmlReport(data.scan));
  } catch (err) { document.getElementById("reportContent").innerHTML = `<section class="panel"><p>${safeText(err.message)}</p></section>`; }
});