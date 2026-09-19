# PHISHLENS — MASTER BUILD PROMPT

You are a senior full-stack engineer, cybersecurity/threat-detection engineer, and AI/NLP engineer. Transform the existing Sublime-derived codebase into **PhishLens**: a production-quality phishing-email detection, investigation, and SOC platform. Audit the existing code first — keep what's useful, refactor or delete the rest. The existing project is a *reference starting point*, not the final architecture. End state must be one coherent system: no duplicate services, no old+new naming mixed together, no dead Sublime-era code or branding (except where license/attribution requires it).

---

## 1. INGESTION — ALL EMAIL-ENTRY SOURCES

PhishLens must be able to ingest mail from every realistic entry point, each mapped to *where the data actually comes from*:

| Source | Data origin |
|---|---|
| SMTP | Inline MTA hook / milter (e.g. Postfix milter, Sendmail milter) intercepting mail-in-transit |
| IMAP | Scheduled/polling or IDLE-based mailbox connector against the user's IMAP server |
| POP3 | Polling connector for legacy mailboxes |
| Gmail API | OAuth2 + Gmail REST/Push (Pub/Sub) — Google Workspace |
| Microsoft Graph API / Exchange Online | OAuth2 + Graph webhooks — Microsoft 365 |
| On-prem Exchange | EWS or transport agent hook |
| Browser extension (webmail) | DOM/API read of the open message in Gmail/Outlook web UI |
| Manual `.eml` / `.msg` upload | File parsed via a MIME parser (analyst-submitted samples) |
| REST API | Third-party systems (SIEM/SOAR, ticketing, mail relay) pushing messages in |
| Webhook / push notification | Provider-initiated near-real-time delivery (Gmail Pub/Sub, Graph webhooks) |
| User-reported "Report Phishing" forward | Dedicated abuse mailbox that re-ingests forwarded `.eml` |

All sources normalize into **one common email object** before entering the shared analysis pipeline. Never build a separate detection engine per source.

## 2. GATEWAY PLACEMENT

PhishLens is deployed inline at the network boundary (before or after the firewall, per environment), but it **only inspects mail-entry traffic** — SMTP/IMAP/API/extension channels above — never full network traffic. Non-mail traffic must pass through untouched.

---

## 3. DETECTION PIPELINE (each stage: input → source of truth → output)

```
Ingestion → Preprocessing/MIME parsing → Auth Analysis → Header & Relay Forensics
→ Content Analysis → NLP Analysis → MQL/Rule Engine → IOC Extraction
→ Threat Intel Enrichment → URL/Domain/IP Analysis → Geolocation/Infra Intel
→ Campaign Correlation → Risk/Confidence Fusion → Explainable Verdict
→ Policy Engine → Response/Mitigation → Forensic Report → SOC Dashboard
```
Every email must be traceable to: **who** sent it, **how** it arrived (reconstructed relay path from `Received:` chain), **where** the infrastructure is, **what** indicators fired, whether it's **related** to another campaign, and **what action** is recommended. No bare "PHISHING"/"SAFE" label without evidence.

### 3a. Authentication (SPF/DKIM/DMARC/ARC)
Validate per RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8617 (ARC). Do not just show PASS/FAIL — explain the mechanism and its security relevance, and keep authentication result separate from a maliciousness verdict (legitimate forwarding can break auth).

### 3b. NLP Engine
Detect urgency, fear-based language, financial pressure, credential/payment requests, executive impersonation, social-engineering patterns, semantic anomalies. Base the lexicon/patterns on **published social-engineering taxonomies** — e.g. APWG eCrime research reports, SANS/CISA phishing-indicator guidance, NIST SP 800-177/800-45 language on email threats, and academic phishing-linguistics corpora — not invented keyword lists. Output signals + reasoning + confidence per email, never a bare score.

### 3c. MQL / Rule Engine — precision requirement
Rules, string/keyword matches, and detection patterns must be sourced from **recognized authorities**, not invented ad hoc. Use as reference/seed material:
- **MITRE ATT&CK** (Phishing: T1566 and sub-techniques) for technique-to-indicator mapping
- **Anti-Phishing Working Group (APWG)** eCrime/phishing trends reports for real-world lure language and infrastructure patterns
- **CISA** phishing advisories and Known Exploited Vulnerabilities context
- **OWASP** Email Security cheat sheet for header/content validation rules
- **abuse.ch** (URLhaus, ThreatFox), **OpenPhish**, **PhishTank** for confirmed malicious URL/domain/IOC feeds usable as rule seeds
- **SANS Internet Storm Center** diaries for emerging phishing patterns
- IANA/RFC specs (5322, 7208, 6376, 7489) for structurally-invalid-header rules

Every rule must cite its source/rationale in-code or in rule metadata so it's auditable — not a magic string. MQL is one layer among several (NLP, ML, forensics, threat intel) and must never be the sole detector.

### 3d. IOC Extraction & Threat Intelligence
Extract/normalize/deduplicate IPs, domains, URLs, email addresses, file hashes, headers. Enrich through a swappable `ThreatIntelProvider` abstraction (IP/domain/URL reputation, geolocation) backed by free sources: AbuseIPDB, VirusTotal (free tier), WHOIS/RDAP, DNS, abuse.ch feeds, public blocklists (Spamhaus DBL/PBL where permitted). No hard dependency on any single paid provider. Clearly separate **IP location** from **attacker location**.

### 3e. URL & Attachment Analysis
URLs: normalize, resolve redirects/shorteners, detect homograph/lookalike characters, check domain age, HTTPS, IP-literal resolution, reputation. Attachments: filename/extension/MIME/hash/size/archive structure/macro indicators/embedded URLs; never execute untrusted files on host — isolate in a sandbox if implemented.

### 3f. Campaign Correlation
Graph model linking Email–Sender–Domain–IP–URL–Attachment–Hash–ASN–Campaign, correlated by shared sender/domain/IP/URL/hash/infrastructure or NLP semantic similarity — turning single emails into tracked campaigns.

### 3g. Impersonation / BEC
Detect executive/vendor impersonation, lookalike domains, display-name spoofing, Reply-To mismatch, urgent payment/credential requests — always multi-signal, never display-name alone.

---

## 4. PHISHING-PREVENTION TECHNIQUES TO IMPLEMENT

Beyond detection, apply recognized mitigation techniques:
- **Policy-driven response**: quarantine, soft-delete, release, flag, warning banner, mark-safe/mark-threat — all threshold-gated, never auto-delete on an uncertain score
- **Human-in-the-loop review** for high-impact/ambiguous verdicts, with analyst feedback looped back into rule/model tuning
- **DMARC/SPF/DKIM policy hardening recommendations** to the domain owner (p=quarantine/reject guidance per RFC 7489)
- **URL rewriting / click-time re-verification** for links in delivered mail
- **Attachment sandbox detonation** (isolated, never on host) before delivery
- **Sender reputation scoring** and progressive rate-limiting of low-reputation senders
- **User-facing warning banners** on suspicious-but-not-blocked mail, with a reporting-phishing button that feeds back into the pipeline
- **IOC sharing/reporting** to PhishTank/APWG-style feeds to contribute back to the ecosystem
- **Continuous feedback loop**: confirmed verdicts (analyst or user-reported) retrain/tune NLP and rule weighting over time

---

## 5. SOC DASHBOARD & INVESTIGATION

Professional SOC-style UI (not a chatbot UI): threat overview, recent detections, risk levels, campaign view, IOC intelligence, threat map, quarantine queue, detection rules, audit logs, exportable PDF forensic reports (case info, headers, auth, relay path, IOCs, threat intel, geolocation, NLP/MQL findings, campaign links, evidence, timeline, recommended action, analyst notes). Per-email investigation view separates **evidence** from **conclusions**: verdict, risk/confidence, why-flagged, auth, relay path, IOCs, NLP/MQL matches, threat intel, geolocation, related campaigns, recommended action.

## 6. BROWSER EXTENSION

Manifest V3, thin client only — calls the central PhishLens API, no duplicate detection logic inside it.
- **Popup (on icon click)**: compact live counts — suspicious / spam / legitimate totals.
- **"More info"** → opens the full SOC dashboard for per-email deep-dive analysis.

---

## 7. NON-FUNCTIONAL REQUIREMENTS

- **Zero-cost core**: open-source/local models + free-tier APIs only for the mandatory path; paid services are optional, never a dependency.
- **Security of PhishLens itself**: input validation, output encoding, authN/authZ, least privilege, secret management (env vars, never in git/frontend/logs), rate limiting, audit logging, CORS/CSRF, dependency scanning, safe MIME/URL parsing.
- **Privacy**: data minimization, encryption at rest where appropriate, configurable retention, never log credentials/tokens, prefer metadata over full-body storage where sufficient.
- **Explainability**: every verdict must answer what/why/evidence/signal-strength/supporting-signals/recommended-action — no unexplained "AI score: 97%".
- **No black-box AI, no faked/stubbed implementations** — if something isn't really implemented, say so explicitly rather than simulating output.
- Clean modular architecture (backend pipeline / API / frontend / extension / DB), clean API routes (`/api/emails`, `/api/analyze`, `/api/detections`, `/api/iocs`, `/api/threat-intelligence`, `/api/campaigns`, `/api/reports`, `/api/rules`, `/api/nlp`, `/api/remediation`, `/api/audit`), clean DB entities (emails, cases, IOCs, domains, IPs, URLs, attachments, campaigns, detections, rules, NLP results, threat intel, geolocation, actions, audit logs).

## 8. PROCESS

1. Full audit of the existing repo (what exists/works/broken/duplicated/obsolete) before any edits.
2. Baseline + git checkpoint before large refactors.
3. Choose tech by security/performance/maintainability/open-source-availability/offline-capability — not popularity.
4. When replacing a component: migrate → update deps/imports/config/tests → remove old → verify working.
5. Maintain tests, docs, and clean git history throughout.

**Deliverable**: one coherent PhishLens system (multi-source ingestion → explainable multi-signal detection pipeline → SOC dashboard → thin browser extension) with an auditable, officially-sourced rule/keyword base, no dead legacy code, and a zero-mandatory-cost core.
