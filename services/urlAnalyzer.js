const { URL } = require("url");

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly"]);
const HIGH_RISK_TLDS = new Set(["zip", "mov", "click", "top", "work", "country", "gq", "tk", "ml", "cf"]);
const BRAND_LURES = ["microsoft", "office365", "outlook", "google", "paypal", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp", "bank", "icici", "sbi", "hdfc"];
function isIpv4(host) {
  const parts = host.split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;

function analyzeUrls(text) {
  const matches = [...String(text || "").matchAll(URL_RE)];
  const seen = new Set();
  const results = [];

  for (const match of matches) {
    const raw = match[0].replace(/[),.;!?]+$/, "");
    if (seen.has(raw)) continue;
    seen.add(raw);
    let parsed;
    try {
      parsed = new URL(raw.startsWith("www.") ? `http://${raw}` : raw);
    } catch {
      results.push({ url: raw, domain: null, findings: ["URL could not be parsed"], risk: "suspicious" });
      continue;
    }

    const domain = parsed.hostname.toLowerCase();
    const findings = [];
    if (parsed.protocol !== "https:") findings.push("Not using HTTPS");
    if (parsed.username || parsed.password) findings.push("Contains user-info before the domain");
    if (domain.startsWith("xn--") || domain.split(".").some(part => part.startsWith("xn--"))) findings.push("Contains an internationalized/punycode domain label");
    if (SHORTENERS.has(domain)) findings.push("Uses a known URL-shortening domain");
    if (parsed.hostname.length > 60) findings.push("Unusually long hostname");
    if (parsed.href.length > 180) findings.push("Unusually long URL");
    if (isIpv4(domain) || domain.includes(":")) findings.push("Uses an IP address instead of a typical domain name");
    const labels = domain.split(".");
    if (labels.length >= 5) findings.push("Contains many subdomains, which can obscure the registered domain");
    if (HIGH_RISK_TLDS.has(labels[labels.length - 1])) findings.push("Uses a top-level domain sometimes associated with abusive campaigns; this alone is not proof of harm");
    if (/[\u200B-\u200F\u2060\uFEFF]/u.test(raw)) findings.push("Contains invisible Unicode characters");
    if (/(?:^|[?&])(redirect|redirect_url|return|returnurl|next|continue|url)=/i.test(parsed.search)) findings.push("Contains a redirect-style parameter that may send users elsewhere");
    if (parsed.search.length > 120) findings.push("Contains an unusually long query string");
    if (labels.some(label => /^(?:secure|login|verify|account|update|support|signin|auth)[-0-9]/i.test(label)) && labels.length > 2) findings.push("Uses login/security-themed words in a multi-part hostname");
    const brandMentions = BRAND_LURES.filter(brand => domain.includes(brand));
    if (brandMentions.length && !domain.endsWith(`.${brandMentions[0]}.com`) && domain !== `${brandMentions[0]}.com` && !domain.endsWith(`.${brandMentions[0]}.org`)) {
      findings.push(`Contains the brand-like term “${brandMentions[0]}” in a domain that is not its obvious primary domain; verify independently`);
    }

    results.push({ url: raw, domain, findings, risk: findings.length >= 3 ? "suspicious" : findings.length >= 1 ? "review" : "no-obvious-indicator" });
  }
  return results;
}

module.exports = { analyzeUrls };