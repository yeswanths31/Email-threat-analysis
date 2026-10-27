function setupCommon() {
  if (localStorage.getItem("eta-theme") === "dark") document.body.classList.add("dark");
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => btn.addEventListener("click", () => {
    document.body.classList.toggle("dark"); localStorage.setItem("eta-theme", document.body.classList.contains("dark") ? "dark" : "light");
  }));
  document.querySelectorAll("[data-logout]").forEach(btn => btn.addEventListener("click", async () => { await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login.html"; }));
  fetch("/api/session").then(r => r.json()).then(d => { if (d.user?.role === "admin") { const n = document.getElementById("adminNav"); if (n) n.hidden = false; } }).catch(() => {});
}
async function showResult(response, messageEl) {
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) { location.href = "/login.html"; return; }
  if (!response.ok) throw new Error(data.error || "Analysis failed.");
  messageEl.className = "form-message success"; messageEl.textContent = "Analysis complete. Opening your report…";
  location.href = `/report.html?id=${encodeURIComponent(data.scan.id)}`;
}
document.addEventListener("DOMContentLoaded", () => {
  setupCommon();
  const scanForm = document.getElementById("scanForm"), scanMessage = document.getElementById("scanMessage");
  const bodyInput = document.getElementById("body"), fileInput = document.getElementById("emailFile"), dropZone = document.getElementById("dropZone");
  const count = document.getElementById("charCount"), selectedFile = document.getElementById("selectedFile");
  bodyInput.addEventListener("input", () => { count.textContent = `${bodyInput.value.length.toLocaleString()} / 50,000`; });
  scanForm.addEventListener("reset", () => setTimeout(() => { count.textContent = "0 / 50,000"; scanMessage.textContent = ""; }, 0));
  document.querySelectorAll("[data-sample]").forEach(btn => btn.addEventListener("click", () => {
    const suspicious = btn.dataset.sample === "phishing";
    document.getElementById("subject").value = suspicious ? "URGENT: Your mailbox will be suspended" : "Meeting notes for Thursday";
    document.getElementById("sender").value = suspicious ? "it-support@example-security-check.com" : "colleague@example.com";
    document.getElementById("replyTo").value = suspicious ? "verify-account@external-mail.example" : "colleague@example.com";
    bodyInput.value = suspicious
      ? "Dear user,\n\nYour mailbox will be suspended in 30 minutes. Verify your account immediately to avoid losing access. Open https://example.com/account/verify and enter your password and one-time code.\n\nIT Support\n\nThis is a demonstration sample, not a real message."
      : "Hello team,\n\nPlease find the agenda for Thursday's meeting below. We will review project milestones and agree on next steps. No action is required before the meeting.\n\nThanks,\nAlex\n\nThis is a demonstration sample, not a real message.";
    count.textContent = `${bodyInput.value.length.toLocaleString()} / 50,000`;
    scanMessage.className = "form-message"; scanMessage.textContent = "Sample loaded. Review it, then select Analyze email.";
    bodyInput.focus();
  }));
  document.getElementById("pasteButton").addEventListener("click", async () => {
    try {
      if (!navigator.clipboard?.readText) throw new Error("Clipboard access is unavailable in this browser. Use Ctrl+V in the email body.");
      const pasted = await navigator.clipboard.readText();
      if (!pasted) throw new Error("Your clipboard is empty.");
      bodyInput.value = pasted.slice(0, 50000); count.textContent = `${bodyInput.value.length.toLocaleString()} / 50,000`;
      scanMessage.className = "form-message success"; scanMessage.textContent = "Clipboard text pasted into the email body.";
    } catch (err) { scanMessage.className = "form-message"; scanMessage.textContent = err.message || "Could not read clipboard. Use Ctrl+V instead."; }
  });
  fileInput.addEventListener("change", () => { selectedFile.textContent = fileInput.files?.[0]?.name || "No file selected"; if (fileInput.files?.[0]) dropZone.classList.add("has-file"); else dropZone.classList.remove("has-file"); });
  if (dropZone) {
    ["dragenter", "dragover"].forEach(ev => dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add("dragging"); }));
    ["dragleave", "drop"].forEach(ev => dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove("dragging"); }));
    dropZone.addEventListener("drop", e => { const f = e.dataTransfer?.files?.[0]; if (!f) return; if (!f.name.toLowerCase().endsWith(".eml")) { document.getElementById("uploadMessage").textContent = "Only .eml files are accepted."; return; } const dt = new DataTransfer(); dt.items.add(f); fileInput.files = dt.files; fileInput.dispatchEvent(new Event("change")); });
  }
  scanForm.addEventListener("submit", async e => {
    e.preventDefault();
    if (!bodyInput.value.trim()) { scanMessage.textContent = "Paste an email body or load a sample first."; bodyInput.focus(); return; }
    const button = document.getElementById("scanButton"); button.disabled = true; button.innerHTML = '<span class="button-spinner"></span> Inspecting message…';
    scanMessage.className = "form-message"; scanMessage.textContent = "Checking content, sender clues and URL structure. Please wait…";
    try {
      const response = await fetch("/api/analysis/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subject: document.getElementById("subject").value, sender: document.getElementById("sender").value, replyTo: document.getElementById("replyTo").value, body: bodyInput.value }) });
      await showResult(response, scanMessage);
    } catch (err) { scanMessage.className = "form-message error"; scanMessage.textContent = err.message; }
    finally { button.disabled = false; button.innerHTML = '<span>⌕</span> Analyze email <b>→</b>'; }
  });
  document.getElementById("uploadForm").addEventListener("submit", async e => {
    e.preventDefault();
    const button = document.getElementById("uploadButton"), msg = document.getElementById("uploadMessage");
    if (!fileInput.files?.[0]) { msg.className = "form-message error"; msg.textContent = "Choose or drop an .eml file first."; return; }
    button.disabled = true; button.textContent = "Reading file…"; msg.className = "form-message"; msg.textContent = "Reading .eml file and preparing the scan…";
    try { const form = new FormData(); form.append("emailFile", fileInput.files[0]); const response = await fetch("/api/analysis/upload", { method: "POST", body: form }); await showResult(response, msg); }
    catch (err) { msg.className = "form-message error"; msg.textContent = err.message; }
    finally { button.disabled = false; button.textContent = "Analyze .eml file →"; }
  });
});
