function setupCommon() {
  if (localStorage.getItem("eta-theme") === "dark") document.body.classList.add("dark");
  function apply(theme) { document.body.classList.toggle("dark", theme === "dark"); localStorage.setItem("eta-theme", theme); }
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => btn.addEventListener("click", () => apply(document.body.classList.contains("dark") ? "light" : "dark")));
  document.getElementById("lightTheme").addEventListener("click", () => apply("light"));
  document.getElementById("darkTheme").addEventListener("click", () => apply("dark"));
  document.querySelectorAll("[data-logout]").forEach(btn => btn.addEventListener("click", async () => { await fetch("/api/auth/logout", { method: "POST" }); location.href = "/login.html"; }));
}
document.addEventListener("DOMContentLoaded", setupCommon);