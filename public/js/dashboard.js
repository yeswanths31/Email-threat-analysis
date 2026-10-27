async function getJSON(url) {
  const res = await fetch(url);
  if (res.status === 401) { location.href = "/login.html"; throw new Error("Please sign in."); }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}
function safeText(value) { return String(value || "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c])); }
function fmtDate(value) { return new Date(value).toLocaleString(); }
document.addEventListener("DOMContentLoaded", async () => {
  setupCommon();
  fetch("/api/session").then(r=>r.json()).then(d=>{if(d.user?.role==="admin"){const n=document.getElementById("adminNav");if(n)n.hidden=false}}).catch(()=>{});
  try {
    const [session, stats] = await Promise.all([getJSON("/api/session"), getJSON("/api/analysis/stats")]);
    document.getElementById("userName").textContent = session.user.name;
    document.getElementById("avatar").textContent = session.user.name.slice(0,1).toUpperCase();
    document.getElementById("totalScans").textContent = stats.total;
    document.getElementById("highRisk").textContent = stats.highRisk;
    document.getElementById("suspiciousLinks").textContent = stats.suspiciousLinks;
    const root = document.getElementById("recentScans");
    if (!stats.recent.length) root.innerHTML = '<div class="empty-state">No scans yet. Start by analyzing an email.</div>';
    else root.innerHTML = stats.recent.map(s => `<div class="recent-item"><div class="mail-symbol">✉</div><div class="recent-details"><strong>${safeText(s.subject)}</strong><small>${fmtDate(s.createdAt)} · Score ${s.score}/100</small></div><span class="risk-chip ${s.level.toLowerCase()}">${safeText(s.level)}</span><a class="text-link" href="/report.html?id=${encodeURIComponent(s.id)}">Open</a></div>`).join("");
  } catch (err) { document.getElementById("recentScans").innerHTML = `<div class="empty-state">${safeText(err.message)}</div>`; }
});
function setupCommon() {
  const saved = localStorage.getItem("eta-theme");
  if (saved === "dark") document.body.classList.add("dark");
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => btn.addEventListener("click", () => {
    document.body.classList.toggle("dark"); localStorage.setItem("eta-theme", document.body.classList.contains("dark") ? "dark" : "light");
  }));
  document.querySelectorAll("[data-logout]").forEach(btn => btn.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login.html";
  }));
}