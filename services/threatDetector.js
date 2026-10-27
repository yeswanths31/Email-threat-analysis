const { analyzeUrls } = require("./urlAnalyzer");

const RULES = [
  { category: "Urgency or pressure", points: 12, regex: /\b(act now|immediately|urgent|within 24 hours|final warning|account will be (?:blocked|suspended|closed)|expires today)\b/i, explanation: "The message pressures the recipient to act quickly." },
  { category: "Credential or sensitive-data request", points: 22, regex: /\b(enter|confirm|verify|submit|reset)\b.{0,45}\b(password|passcode|otp|one[- ]time code|bank details|credit card|login credentials)\b/i, explanation: "The message may be asking for credentials or sensitive information." },
  { category: "Threatening account language", points: 12, regex: /\b(suspended|locked|terminated|permanently closed|unusual activity detected)\b/i, explanation: "The message uses account-threat language commonly seen in phishing attempts." },
  { category: "Prize or unexpected reward", points: 14, regex: /\b(you (?:have )?won|claim your prize|lottery winner|free gift|cash reward)\b/i, explanation: "The message promises an unexpected reward." },
  { category: "Payment or invoice pressure", points: 14, regex: /\b(overdue invoice|wire transfer|urgent payment|payment failed|gift cards|pay immediately)\b/i, explanation: "The message includes a payment request or payment pressure." },
  { category: "Generic greeting", points: 5, regex: /\b(dear customer|dear user|valued customer|dear account holder)\b/i, explanation: "A generic greeting can be a weak warning sign when combined with other indicators." },
  { category: "Suspicious attachment wording", points: 10, regex: /\b(enable macros|open the attached|invoice\.exe|password protected attachment)\b/i, explanation: "The message encourages potentially risky attachment behavior." },
  { category: "Sensitive account action", points: 10, regex: /\b(click here to (?:verify|secure|restore)|confirm your identity|validate your account)\b/i, explanation: "The message urges an account or identity action." },
  { category: "MFA / OTP harvesting", points: 20, regex: /\b(share|send|reply with|provide|enter)\b.{0,35}\b(otp|one[- ]time password|verification code|authenticator code|mfa code)\b/i, explanation: "The message may be trying to collect a one-time code that should remain private." },
  { category: "Executive or supplier impersonation cues", points: 16, regex: /\b(ceo|cfo|managing director|director|supplier|vendor)\b.{0,80}\b(confidential|urgent transfer|bank account changed|new account details|wire transfer|keep this between us)\b/i, explanation: "The message combines authority or supplier language with a sensitive financial request." },
  { category: "Unexpected document sharing", points: 10, regex: /\b(shared (?:a )?(?:document|file)|view (?:the )?(?:document|invoice)|secure document|document is ready)\b.{0,80}\b(sign in|login|password|verify)\b/i, explanation: "A document-sharing lure paired with a login request can be used to steal credentials." },
  { category: "Cryptocurrency or gift-card payment", points: 16, regex: /\b(pay (?:me )?in (?:bitcoin|crypto|cryptocurrency)|buy (?:me )?gift cards|send gift card codes|crypto wallet address)\b/i, explanation: "The message requests a payment method commonly abused in scams." },
  { category: "Possible data exfiltration request", points: 18, regex: /\b(send|upload|forward)\b.{0,45}\b(customer database|employee records|payroll|tax records|passport copies|identity documents)\b/i, explanation: "The message requests potentially sensitive organizational or identity data." }
];

function analyzeEmail(input) {
  const subject = String(input.subject || "");
  const sender = String(input.sender || "");
  const body = String(input.body || "");
  const combined = `${subject}\n${sender}\n${body}`.slice(0, 50000);
  const findings = [];
  let score = 0;

  for (const rule of RULES) {
    if (rule.regex.test(combined)) {
      score += rule.points;
      findings.push({ category: rule.category, points: rule.points, explanation: rule.explanation });
    }
  }

  const urls = analyzeUrls(combined);
  for (const url of urls) {
    if (url.findings.length) {
      const points = Math.min(18, 6 + (url.findings.length - 1) * 4);
      score += points;
      findings.push({
        category: "URL warning",
        points,
        explanation: `${url.domain || url.url}: ${url.findings.join("; ")}. This is a warning signal, not proof that the destination is malicious.`
      });
    }
  }

  // Authentication-Results is only a reported header claim from the supplied message.
  // It is not independently validated here and can be forged in an untrusted .eml file.
  const authResults = String(input.authenticationResults || "").slice(0, 2000);
  if (authResults) {
    const failed = [];
    if (/\bspf\s*=\s*fail\b/i.test(authResults)) failed.push("SPF reports fail");
    if (/\bdkim\s*=\s*fail\b/i.test(authResults)) failed.push("DKIM reports fail");
    if (/\bdmarc\s*=\s*fail\b/i.test(authResults)) failed.push("DMARC reports fail");
    if (failed.length) {
      score += 18;
      findings.push({ category: "Email authentication header warning", points: 18, explanation: `${failed.join(", ")}. This is a claim in the supplied Authentication-Results header and has not been independently verified.` });
    } else if (/\b(spf|dkim|dmarc)\s*=\s*(none|neutral|softfail|temperror|permerror)\b/i.test(authResults)) {
      score += 5;
      findings.push({ category: "Email authentication needs review", points: 5, explanation: "The supplied Authentication-Results header contains a non-passing or inconclusive result. The header is not independently verified by this prototype." });
    }
  }

  const senderDomain = (sender.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
  const replyTo = String(input.replyTo || "");
  const replyDomain = (replyTo.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
  if (senderDomain && replyDomain && senderDomain.toLowerCase() !== replyDomain.toLowerCase()) {
    score += 15;
    findings.push({ category: "Sender / Reply-To mismatch", points: 15, explanation: "The sender domain differs from the Reply-To domain. Legitimate services can also use different domains, so review the context." });
  }

  score = Math.min(100, score);
  let level = "Low";
  let category = "No strong indicators found";
  if (score >= 60) { level = "High"; category = "High-risk indicators detected"; }
  else if (score >= 30) { level = "Medium"; category = "Suspicious indicators detected"; }
  else if (score >= 12) { level = "Elevated"; category = "Some warning signs detected"; }

  const recommendations = [];
  if (urls.length) recommendations.push("Do not open links from the message until you verify the destination independently.");
  if (findings.some(f => /credential|sensitive|account/i.test(f.category))) recommendations.push("Never share passwords or OTPs through an email link. Visit the official service directly.");
  if (findings.some(f => /attachment/i.test(f.category))) recommendations.push("Do not open unexpected attachments; verify with the sender using a trusted channel.");
  if (findings.some(f => /Sender \/ Reply-To/i.test(f.category))) recommendations.push("Check the sender using a known contact method rather than replying to the message.");
  if (!recommendations.length) recommendations.push("No strong indicators were found by these basic checks. This does not guarantee the email is safe.");
  recommendations.push("Treat this score as a heuristic screening result, not a definitive verdict.");

  return {
    score,
    level,
    category,
    findings,
    urls,
    recommendations,
    analyzedAt: new Date().toISOString(),
    engine: "hybrid-rules-url-header-v3",
    disclaimer: "This prototype uses heuristic content rules and URL structure checks. It does not query live reputation services, safely detonate attachments, or independently verify SPF/DKIM/DMARC. Authentication-Results is treated only as an unverified supplied header claim. Scores are triage signals, can produce false positives/negatives, and do not prove that a message is safe or malicious."
  };
}

module.exports = { analyzeEmail };