EMAIL THREAT ANALYZER — LOCAL SETUP (WINDOWS)

Requirements:
- Node.js LTS installed
- Command Prompt (cmd.exe)

RUN:
1. Extract this ZIP into a folder such as C:\Users\YourName\Desktop\Email-Threat-Analyzer
2. Open Command Prompt.
3. Move into the project folder, for example:
   cd %USERPROFILE%\Desktop\Email-Threat-Analyzer
   (Adjust this path if you extracted it somewhere else.)
4. Install dependencies:
   npm.cmd install
5. Start:
   npm.cmd start
6. Open http://localhost:3000
7. Create an account, then analyze a sample email.

SAMPLE TEST EMAIL:
Subject: Your account will be suspended today
From: security@example.com

Dear Customer,
Your account will be suspended today. Verify your account immediately using the link below to avoid permanent closure.
http://example.com/verify

BENIGN TEST EMAIL:
Subject: Meeting agenda for Friday
From: colleague@example.org

Hello,
Here is the agenda for our Friday meeting. Please review the attached notes before the meeting.
Thanks.

.eml FILE TEST:
Create a plain text file named sample.eml with these lines, then upload it in the analyzer:
From: security@example.com
To: you@example.com
Subject: Urgent account verification
Reply-To: different@example.net
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer, your account will be suspended today. Verify your password immediately:
http://example.com/verify

IMPORTANT LIMITATIONS:
- This is a learning prototype using heuristic rules and URL structure checks.
- It does not use a trained ML model or live URL/domain reputation API yet.
- It does not independently verify SPF/DKIM/DMARC.
- A low score is not proof that an email is safe.
- Do not deploy publicly with the default session secret.
- JSON files are suitable only for a small local prototype; simultaneous writes and concurrent users need stronger storage/locking.
- Use only test/sample email content unless you have permission to process the real message.
- The application does not automatically open links or execute attachments.


REPORT DOWNLOADS:
- Open a saved report from Scan History.
- Use Download PDF report for a professional, shareable threat analysis report (recommended for general users).
- An optional HTML report can also be downloaded and opened or printed from a browser.
- JSON export remains available as a technical endpoint for developers; it is not the main report button.
- PDF generation uses PDFKit, installed by running npm.cmd install.


URL THREAT ANALYSIS AND ADMIN DASHBOARD
- Open URL analysis from the sidebar to scan a URL without visiting it.
- URL reports provide a PDF download for general users.
- Admin dashboard shows registered accounts, scan counts, high-risk scans, URL scan counts and recent activity.
- The sign-in page has separate User login and Admin login choices. The server checks the account's actual role; selecting Admin does not grant admin rights.
- This build includes the admin account configured for the email you supplied. Choose Admin login and enter the password you supplied. The password is stored as a salted PBKDF2 hash, not as plain text. For security, consider changing it to a unique, stronger password after first sign-in.
- Configure an admin account safely from Command Prompt:
    cd path\\to\\Email-Threat-Analyzer
    set ADMIN_EMAIL=your-email@example.com
    set ADMIN_NAME=MailGuard Admin
    npm.cmd run setup-admin
  The setup script asks for the admin password without echoing it in a normal interactive CMD terminal and stores only a bcrypt password hash. It creates or upgrades the account for that email to admin. If terminal input is not interactive, it warns that input may be visible.
- Then start the app in the same CMD window:
    set SESSION_SECRET=replace-this-with-a-long-random-secret
    npm.cmd start
- For deployment, set ADMIN_EMAIL and SESSION_SECRET in the host's environment-variable settings. Use HTTPS and persistent storage. Never commit real passwords or session secrets.
- Detection is heuristic: it does not query live domain reputation, DNS, Safe Browsing, or threat-intelligence APIs. A low-risk result is not proof a URL is safe.

REPORT DOWNLOAD NOTE
Email reports and standalone URL reports provide a PDF download as the main user-facing option. JSON is kept for technical/debug use, not as the main download button.

VERSION 1.3 UI + DETECTION ENHANCEMENTS
- Added subtle 3D hover depth, perspective transitions, animated surface sheen, floating security orb, animated background accents, and page entrance motion.
- Includes reduced-motion support for accessibility and toned-down movement on small screens.
- Expanded heuristic checks for OTP/MFA harvesting, executive/supplier payment impersonation cues, document-share login lures, crypto/gift-card payment requests, and sensitive-data exfiltration language.
- Expanded URL structure checks for IP-literal hosts, long/many subdomains, risky-looking TLDs, invisible Unicode characters, redirect-style parameters, long query strings, and brand-like terms in non-obvious domains.
- These are heuristic indicators only. They may produce false positives and do not replace live reputation, sandboxing, or SPF/DKIM/DMARC validation.


LATEST UI AND WORKFLOW REFRESH
- Redesigned security dashboard with a dark security-console sidebar, threat snapshot cards, recent scan list and quick-action panels.
- Redesigned email analyzer with sample messages, live character count, clipboard paste, .eml drag-and-drop, selected-file feedback and clearer progress/error messages.
- Responsive layout for desktop and mobile, plus retained dark/light theme toggle.
- Hybrid screening combines content rules, URL structure signals, sender/Reply-To mismatch checks and optional Authentication-Results header claims from .eml files.
- Authentication-Results header values are not independently verified; they are treated only as untrusted claims.
- Existing scan history, per-user reports, URL scanner, admin dashboard and PDF report download are retained.

IMPORTANT LIMITATIONS
- This is a heuristic screening prototype, not a trained machine-learning classifier or enterprise mail gateway.
- No live threat-intelligence/reputation service is queried. The app does not independently validate SPF/DKIM/DMARC, detonate attachments, or guarantee safety.
- Scan data is stored in local JSON files. Protect the host computer and do not use this prototype as the only security control.
