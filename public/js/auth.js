async function postForm(url, data) {
  const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "Request failed.");
  return result;
}
document.addEventListener("DOMContentLoaded", () => {
  const login = document.getElementById("loginForm");
  const register = document.getElementById("registerForm");
  const message = document.getElementById("formMessage");
  const roleInput = document.getElementById("loginRole");
  const loginButtonText = document.getElementById("loginButtonText");
  document.querySelectorAll("[data-login-role]").forEach(button => button.addEventListener("click", () => {
    const role = button.dataset.loginRole;
    if (roleInput) roleInput.value = role;
    document.querySelectorAll("[data-login-role]").forEach(item => {
      const selected = item === button;
      item.classList.toggle("selected", selected);
      item.setAttribute("aria-pressed", String(selected));
    });
    if (loginButtonText) loginButtonText.textContent = role === "admin" ? "Sign in as admin" : "Sign in as user";
    if (message) { message.textContent = ""; message.className = "form-message"; }
  }));
  if (login) login.addEventListener("submit", async e => {
    e.preventDefault(); message.textContent = "Verifying your credentials…"; message.className = "form-message";
    const form = new FormData(login);
    try {
      const result = await postForm("/api/auth/login", Object.fromEntries(form));
      location.href = result.user.role === "admin" ? "/admin.html" : "/dashboard.html";
    } catch (err) { message.textContent = err.message; }
  });
  if (register) register.addEventListener("submit", async e => {
    e.preventDefault(); message.textContent = "Creating your account…"; message.className = "form-message";
    const form = new FormData(register);
    try { await postForm("/api/auth/register", Object.fromEntries(form)); location.href = "/dashboard.html"; }
    catch (err) { message.textContent = err.message; }
  });
});
