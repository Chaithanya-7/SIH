# PhishLens — Implemented Things

This file tracks completed implementation work. It is updated as each verified increment is finished.

## 2026-09-17 — In progress: ingestion correctness

- Started removing the duplicate reservation path in the shared analysis pipeline. SMTP, IMAP, and Gmail reserve a message before invoking the pipeline; the pipeline now consumes that active reservation instead of reserving it a second time.
- Gmail ingestion now skips a message that another worker is already processing, matching SMTP/IMAP behavior.
- IMAP now waits for every asynchronous message analysis to finish before ending its fetch cycle or releasing the poll lock; the UID checkpoint advances only after successful processing.
- IMAP TLS certificate validation is enabled by default. An invalid certificate requires explicit, documented lab-only opt-in.
- Disabled the misleading user-supplied “Google identity” flow by default. It is now an explicitly enabled local demo identity only, cannot run in production, and is labelled honestly in the dashboard.
- Rebranded active dashboard, backend runtime, reports, notifications, audit/evidence defaults, and new Gmail quarantine labels as PhishLens. Existing persisted cases retain their stored historical label values.

## 2026-09-17 — Explainable language analysis

- Added a dependency-free, local NLP/social-engineering analyzer to the common email pipeline.
- It identifies urgency pressure, credential requests, financial pressure, impersonation language, and link/attachment calls-to-action as separate evidence-backed signals.
- NLP findings include matched terms, explanation, severity, confidence, and an explicit limitation that language signals do not independently establish maliciousness.
- Replaced the prior undifferentiated BEC keyword check in evidence fusion with the structured NLP signals.
- Added a Language Analysis tab to the case investigation view so analysts can inspect these findings directly.
- Verified against a controlled phishing/BEC-style message: urgency, credential-request, financial-pressure, and link-call-to-action signals were all identified.

## 2026-09-17 — Safe attachment forensics

- Added MIME attachment metadata analysis to the common pipeline.
- Extracts a sanitized filename, extension, MIME type, size, transfer encoding, and SHA-256 hash without writing, opening, or executing untrusted attachment content.
- Includes attachment hashes in the case IOC list and added an Attachments tab to the investigation view.

## 2026-09-17 — Evidence scoring calibration

- Replaced the fixed additive confidence score with correlation-aware evidence fusion.
- Authentication, language, and campaign signals are grouped, so only the strongest signal in each family contributes to threat scoring.
- Cases retain the representative evidence contribution for analyst review; infrastructure and campaign confidence now use their actual forensic/graph values.

## 2026-09-17 — Security baseline

### API access control

- Removed the source-visible fallback API key (`securemail_dev_key_2026`).
- Removed automatic development-mode admin authentication for requests without credentials.
- Service access now requires an explicitly configured `PHISHLENS_API_KEY`; dashboard sessions continue to use their issued session token.
- Added authentication middleware to manual analysis, webhook email ingestion, cases, graph, VIP, audit, remediation, reports, Gmail OAuth, organization, mailbox, and admin routes.

### Browser access control

- CORS now permits only the explicitly configured `ALLOWED_ORIGINS` list in every environment.
- Requests without an Origin header remain available to authenticated non-browser clients such as trusted ingestion daemons.

### SMTP ingestion safety

- SMTP ingestion is disabled unless `ENABLE_SMTP_INGESTION=true` is set.
- Enabling SMTP now requires `SMTP_USERNAME` and `SMTP_PASSWORD`.
- The listener uses SMTP authentication, retains loopback binding by default, applies a configurable 10 MB message limit, and waits for pipeline completion before accepting a message.

### Configuration and launcher

- Added `my-product-backend/.env.example` with the required API key, CORS, SMTP, detection, and remediation configuration.
- Updated `start-all.bat` to use paths relative to the repository and PhishLens branding instead of a stale `D:\sih` location.

### Verification completed

- JavaScript syntax checks passed for `server.js`, `middleware/authMiddleware.js`, and `adapters/smtpListenerAdapter.js`.
- An unauthenticated request was verified to receive HTTP 401.
- A request carrying a configured service key was verified to authenticate as the service account.
- `git diff --check` passed.
- Installed locked Node dependencies and built the dashboard successfully with `npm run build`.
- Started the backend on a test port and verified: health correctly reports `DEGRADED` when the detection provider is unavailable; unauthenticated case access returns HTTP 401; the configured PhishLens service key receives HTTP 200.

### Known verification limitation

- The repository does not currently have installed Node dependencies. The dashboard build cannot run until dependencies are installed (`tsc` and `smtp-server` were unavailable locally).

## 2026-09-19 — Checkpoint push and project rename

- Verified and committed the 2026-09-17 security/ingestion/NLP/attachment work that had never been committed or pushed (`git log` showed only the original "Initial commit"). Re-ran `node --check` on every changed backend file and `npm run build` on the dashboard before committing; both passed. Pushed to `origin/main` on `https://github.com/mdyounus-git/PhishLens.git` (first push — the remote branch did not exist yet).
- Renamed the placeholder `my-product-backend` / `my-product-dashboard` / `my-product-extension` directories to `phishlens-backend` / `phishlens-dashboard` / `phishlens-extension` via `git mv`, and updated every reference: `start-all.bat` paths, both `package.json` names, both `package-lock.json` names, the dashboard `<title>`, and the extension's `manifest.json`, `config.js` (`SECUREMAIL_CONFIG` → `PHISHLENS_CONFIG`), `background.js`, `popup.js`, and `popup.html`.
- Rebranded remaining "SecureMail" strings in the backend `scratch/` dev test scripts (log labels only; these scripts are not part of the runtime pipeline).
- Removed the stale "Sublime Dashboard: http://localhost:3000" line from `start-all.bat` — no `sublime-platform` service exists in this repository, so the line was misleading.
- Re-verified after the rename: backend boots cleanly on a test port (loads persisted case/remediation/graph state, SMTP/IMAP correctly report disabled), and the dashboard `npm run build` still succeeds.

### Next architectural gap (not yet started)

- `DETECTION_PROVIDER` is still hardcoded to `sublime` with no local Sublime service in this repository — every ingestion path still calls out to an external, unconfigured detection dependency for MQL/rule matching (`mqlBridge.js` only normalizes a Sublime response; it does not run its own rules). This is the single largest remaining gap against the master plan's Phase 3 (Detection Engine): a native, source-cited MQL/rule engine (MITRE ATT&CK, APWG, CISA, OWASP, abuse.ch/OpenPhish/PhishTank-seeded rules per the compact plan) is not yet implemented, so the platform has no working detection path without an external Sublime instance.
