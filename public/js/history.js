function safeText(value) { return String(value || "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c])); }
function setupCommon() {
  if (localStorage.getItem("eta-theme") === "dark") document.body.classList.add("dark");
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => btn.addEventListener("click", () => { document.body.classList.toggle("dark"); localStorage.setItem("eta-theme", document.body.classList.contains("dark") ? "dark" : "light"); }));
  document.querySelectorAll("[data-logout]").forEach(btn => btn.addEventListener("click", async () => { await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login.html"; }));
}
let scans = [];
function renderHistory() {
  const query = document.getElementById("historySearch").value.toLowerCase();
  const filtered = scans.filter(s => `${s.subject} ${s.sender}`.toLowerCase().includes(query));
  const rows = document.getElementById("historyRows");
  if (!filtered.length) { rows.innerHTML = '<tr><td colspan="5" class="empty-state">No matching scans found.</td></tr>'; return; }
  rows.innerHTML = filtered.map(s => `<tr><td><div class="table-subject">${safeText(s.subject || "(No subject)")}</div><div class="table-secondary">${safeText(s.sender || "Sender not supplied")}</div></td><td><span class="risk-chip ${s.result.level.toLowerCase()}">${safeText(s.result.level)}</span></td><td>${s.result.score}/100</td><td>${new Date(s.createdAt).toLocaleDateString()}</td><td><div class="table-actions"><a class="small-action" href="/report.html?id=${encodeURIComponent(s.id)}">View</a><button class="small-action delete" data-delete="${safeText(s.id)}">Delete</button></div></td></tr>`).join("");
  rows.querySelectorAll("[data-delete]").forEach(btn => btn.addEventListener("click", async () => {
    if (!confirm("Delete this scan report?")) return;
    const res = await fetch(`/api/analysis/history/${encodeURIComponent(btn.dataset.delete)}`, { method: "DELETE" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { document.getElementById("historyMessage").textContent = data.error || "Could not delete scan."; return; }
    scans = scans.filter(s => s.id !== btn.dataset.delete); renderHistory();
    document.getElementById("historyMessage").className = "form-message success"; document.getElementById("historyMessage").textContent = "Scan deleted.";
  }));
}
document.addEventListener("DOMContentLoaded", async () => {
  setupCommon();
  document.getElementById("historySearch").addEventListener("input", renderHistory);
  try {
    const res = await fetch("/api/analysis/history");
    if (res.status === 401) { location.href = "/login.html"; return; }
    const data = await res.json(); if (!res.ok) throw new Error(data.error || "Could not load history.");
    scans = data.scans; renderHistory();
  } catch (err) { document.getElementById("historyRows").innerHTML = `<tr><td colspan="5" class="empty-state">${safeText(err.message)}</td></tr>`; }
});