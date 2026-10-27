function parseEmail(raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const splitAt = text.indexOf("\n\n");
  const headerText = splitAt >= 0 ? text.slice(0, splitAt) : "";
  const body = splitAt >= 0 ? text.slice(splitAt + 2) : text;
  const headers = {};
  let lastKey = null;

  for (const line of headerText.split("\n")) {
    if (/^\s/.test(line) && lastKey) {
      headers[lastKey] += " " + line.trim();
      continue;
    }
    const idx = line.indexOf(":");
    if (idx > 0) {
      lastKey = line.slice(0, idx).trim().toLowerCase();
      headers[lastKey] = line.slice(idx + 1).trim();
    }
  }

  return {
    from: headers.from || "",
    to: headers.to || "",
    subject: headers.subject || "",
    replyTo: headers["reply-to"] || "",
    authenticationResults: headers["authentication-results"] || "",
    body,
    headers
  };
}

module.exports = { parseEmail };