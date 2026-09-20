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

## 2026-09-19 — PII discovered and purged from git history

- While finishing the rename commit, found `data/remediation_actions.json` (a tracked file, 2114 lines of synthetic remediation-action test records) contained a real-looking personal Gmail address (`cha7thanya@gmail.com`) among mostly-placeholder addresses (`cfo@company.com`, `victim@org-i.com`). It had been present since the Initial commit.
- Root cause: a nested `my-product-backend/.gitignore` had `!data/cases.json` / `!data/remediation_actions.json` negation rules that force-included these files despite the root `.gitignore` listing them as ignored. Removed the negation rules.
- Untracked both files (kept locally on disk; they are real local runtime state, not deleted).
- Confirmed with the user before doing anything destructive. With explicit approval, rewrote all local git history with `git filter-branch --index-filter` to strip both files from every commit, verified the new `main` tip and its full reachable history contain neither the file paths nor the leaked email string, then force-pushed the rewritten history to `origin/main` (`92936ed...557a58d main -> main (forced update)`), overwriting the previously pushed commits that contained the PII. Deleted local filter-branch backup refs (`refs/original/*`) and ran `git gc --prune=now --aggressive` to drop the old blobs from the local object store too.
- Residual risk noted to the user: the PII was live on GitHub for a few minutes between the first push and the force-push; a force-push cannot retroactively clear anything GitHub itself may have cached (e.g. code search indexing) in that window — outside what a client-side rewrite can control.

## 2026-09-19 — Native MQL detection engine (Phase 3 core)

Detection previously could not work at all without an external Sublime instance: every ingestion path called it first and the pipeline aborted when it was down, header/auth analysis read only Sublime's parsed data model (so SPF/DKIM/DMARC were permanently "unknown" without it), and the rule matches it returned were stored but never scored by evidence fusion.

- **`modules/ruleEngine.js`** — 22 deterministic rules across authentication, sender/domain identity, URL risk, attachment risk, NLP combinations, and a BEC composite. Every rule carries its public source in metadata (MITRE ATT&CK T1566/T1204, APWG, CISA, FBI IC3, OWASP, RFC 5322/6376/7489/8601) and records why it fired on that specific message. Runs after forensics/IOC/NLP so rules reason over full context, and feeds evidence fusion rather than setting a verdict itself.
- **`modules/emailParser.js`** — one shared MIME parse (mailparser) replacing three separate ad-hoc regex parses. Attachment extraction now handles nested MIME and transfer encodings; NLP reads the real body instead of the whole raw message including headers.
- **`modules/authAnalyzer.js`** — SPF/DMARC read from the receiving infrastructure's own `Authentication-Results` header (RFC 8601), labelled `HEADER_CLAIMED`; DKIM additionally re-verified cryptographically by PhishLens and labelled `INDEPENDENTLY_VERIFIED`. Live DMARC policy lookup over DNS TXT (verified working against gmail.com's real published record). A header claiming a DKIM result that independent verification contradicts is flagged as possible forged-header filter evasion (MQL-AUTH-102).
- **Scoring correction** — a pure BEC email leaves no auth/URL/attachment/infrastructure trace, so it structurally could never exceed 0.55 and could never reach HIGH_RISK. Fixed with an auditable BEC composite rule in its own evidence family rather than by inflating weights. Within a family the strongest finding now contributes in full and further findings at progressively halved weight, so correlated facts still are not double-counted but genuinely multi-signal messages score higher.
- **External provider is now optional** — `DETECTION_PROVIDER` defaults to `native`. Sublime, if configured, is an informational cross-check that cannot block the pipeline or affect the score. Removed the `DEV_DETECTION_FALLBACK` path that fabricated a FLAGGED verdict when Sublime was down. `/api/health` now reports native detection and external provider separately instead of claiming DEGRADED whenever Sublime is unreachable.
- **NLP expanded 5 → 9 categories** — added gift-card request, account-threat, secrecy pressure, generic greeting; every signal now cites its source.
- **Tests** — `npm test` (`node --test`, no new test dependencies). 11 tests covering rule matching, source-citation coverage, attachment handling, RFC 8601 parsing, and false-positive guards for legitimate password-reset, marketing, and internal payment mail.
- **Verified end to end over HTTP**, not just in unit tests: benign samples score 0.02–0.25 (SAFE), phishing/BEC samples 0.77–0.94 (HIGH_RISK).
- Dependencies added: `mailparser`, `mailauth` (both MIT, pure JS). Added npm `overrides` to patch transitive nodemailer/joi/semver advisories; `npm audit` reports 0 vulnerabilities.

## 2026-09-19 — Two access surfaces: browser extension and installed desktop app

Requested: the tool should be reachable both as a browser extension and as an application installed on the system; the extension popup should show only limited information with a "More info" option that opens the installed application, while opening the application directly gives the full SIEM-style dashboard.

- **`GET /api/summary`** (authenticated) — compact verdict counts, quarantine/review totals, and the five most recent detections, scoped by the same org/employee rules as `/api/cases`. The popup needs nothing more than this.
- **Extension reworked as a genuine thin client** — compact popup (high risk / suspicious / legitimate counts, quarantine and review totals, recent detections) plus a **More info** button. Added a settings page for backend URL and API key (the API requires authentication, so the extension could not have worked without this). Toolbar badge shows the current high-risk count. Removed the dead unauthenticated `ANALYZE_EMAIL` proxy that nothing called.
- **Cross-browser** — MV3 manifest declaring both `service_worker` (Chrome/Edge/Brave/Opera) and `scripts` (Firefox) plus `browser_specific_settings`; all code uses `globalThis.browser || globalThis.chrome`.
- **`phishlens-desktop/`** — Electron shell around the same dashboard build (not a second implementation). Registers the `phishlens://` scheme, handles deep links via argv/`second-instance` on Windows/Linux and `open-url` on macOS, enforces single-instance, and runs with context isolation on and Node integration off. `phishlens://case/<id>` is wired end to end: the dashboard subscribes to the deep link and selects that case, resolving it once the case list loads.
- If the desktop app is not installed the browser cannot open the scheme, so the popup always offers an explicit web-console fallback link rather than guessing with a focus/timer heuristic.

## 2026-09-19 — Four-branch architecture, behavioural analysis, and real-time learning

The pipeline now follows the architecture in `workflow.md`: MQL + NLP form the detection layer, and their output is handed to four analysis branches that converge on evidence fusion.

- **Pipeline restructured** into preprocessing → detection layer (MQL + NLP) → four branches → convergence. Branch execution order is set by real data dependencies rather than preference: the forensic branch selects the origin IP that the behavioural and infrastructure branches both reason about, and campaign correlation needs the indicators the infrastructure branch produces. The two genuinely independent branches (behavioural, infrastructure) run concurrently. Verified from the live log that stages execute in this order.
- **`modules/behavioralAnalyzer.js` — the fourth branch, which did not exist before.** Judges a message against what this deployment has actually observed: first contact from a sender, a display name previously seen from a *different* address (the classic known-contact impersonation, invisible to content analysis), sending infrastructure that has changed for a known sender, and send times outside that sender's pattern. Baselines are built only from mail that was not judged high risk, so an attacker cannot define themselves as normal by sending volume.
- **`modules/adaptiveLearning.js` — real-time learning from confirmed verdicts.** A confirmed message is broken into discrete characteristics (wording, sender domain and TLD, linked hosts, attachment types, authentication state, rules tripped, NLP and behavioural signals, structural traits) and each is counted against malicious and legitimate outcomes. Later messages sharing those characteristics score accordingly. Learning is immediate — no batch retraining, no model download.
  - **Explainable by construction**: scoring is a log-odds sum over individual characteristics, so the engine always names which characteristics drove a score, how strongly, and from how many examples. Exposed at `GET /api/learning`.
  - **Honest when untrained**: below 5 confirmed examples of each class it reports `INSUFFICIENT_TRAINING_DATA` and contributes nothing, instead of emitting a confident number derived from two examples.
  - **Corroborating, never deciding**: capped at 0.15 in the confidence engine, so what the system taught itself can tip a borderline case but can never drive a HIGH_RISK verdict on its own. The deterministic, source-cited rules remain the primary authority.
  - **Self-labels only corroborated detections** (score ≥ 0.85 across ≥ 3 independent evidence families), so it cannot spiral on its own mistakes.
  - **One message counts once.** A message can be self-labelled and then reviewed by an analyst; the second is recognised as the same case and does not double-count.
  - **An analyst overturning a verdict withdraws the earlier lesson** — per-characteristic counts are rolled back, not merely offset. This is how a false positive the system taught itself gets corrected rather than entrenched.
- **Analyst judgement is no longer lost when the mailbox action fails.** Releasing or confirming previously learned nothing if the Gmail call threw (e.g. no OAuth token). Whether the mailbox can be reached is an operational matter; the analyst's judgement is a fact about the message, and is now recorded either way.
- **Cases no longer store raw message bodies.** `saveCase` persisted the entire object including `_raw_email_string`, which is why `cases.json` reached 314 MB in the original audit and contradicted the plan's data-minimisation requirement. Raw message and provider model are now stripped at save time; a compact `learning_features` list is kept instead, so an analyst decision made days later still teaches the model without any body text being retained.
- **Fixed a leak in the test helper itself**: `try { return run(...) } finally { restore }` without `await` restored the model files *before* the async test body ran, so tests were writing to the operator's real learned model. Now awaited and verified to leave no trace.
- 21 tests passing, including learning, un-learning, double-count prevention, and behavioural impersonation detection.

## 2026-09-19 — Phase 4: threat intelligence from open feeds, held locally

- **`modules/threatIntelStore.js`** — five open indicator feeds downloaded, normalised and indexed on the local machine: abuse.ch URLhaus, abuse.ch ThreatFox, abuse.ch Feodo Tracker, OpenPhish community, and Spamhaus DROP. First live sync loaded ~25,000 indicators (13,627 URLs, 5,775 hosts, 1,952 domains, 2,407 IPs, 1,712 netblocks).
  - **Deliberately not a per-message reputation API client.** Querying a hosted service would mean sending the domains and URLs found in the operator's own mail to a third party, one message at a time. Downloading the list and matching locally reveals nothing about what mail this installation receives, needs no API key or paid tier, has no rate limit, and keeps working with no network at all once synced.
  - Feed licences are recorded per feed and surfaced through `GET /api/threat-intelligence`, so an operator can check terms before commercial deployment rather than discovering them later.
  - A feed that fails to download keeps its previously synced indicators and is reported as FAILED with its age — stale intelligence beats none, provided the age is honest.
- **Serious false positive found and fixed during verification.** URL feeds legitimately list malicious content *hosted on* multi-tenant platforms, so indexing the hostname condemned the whole platform: `github.com`, `raw.githubusercontent.com`, `drive.google.com`, `docs.google.com`, `cdn.discordapp.com` and `firebasestorage.googleapis.com` were all being matched as malicious. Any message linking to Google Drive would have been flagged. Multi-tenant hosts are now excluded from host-level matching at both index and lookup time, while exact URLs on them still match and attacker-controlled subdomains (e.g. a lookalike login on a site builder) remain indexed normally.
- **`adapters/rdapAdapter.js`** — domain registration age over RDAP (RFC 9083), free and key-less. Registration dates never change, so results are cached on disk permanently and each domain is queried once. Verified live against real registry data.
- **`modules/threatIntelEnricher.js`** — applies intelligence to every extracted indicator rather than only the origin IP, and resolves ages for the sender domain plus linked domains (capped per message).
- **Two-stage MQL evaluation.** Rules now declare a stage: `message` rules reason over the message alone and run in the detection layer; `enrichment` rules reason over what the branches produced and run after them. Findings accumulate rather than replace. This keeps threat-intelligence detection inside the same auditable, source-cited rule engine instead of bypassing it. Five new rules (MQL-INTEL-101 to 105) cover exact malicious URL, known malicious host, known malicious IP/netblock, and newly-registered sender and linked domains.
- **Decisive findings.** The family caps exist to stop correlated facts compounding, but they also prevented a single confirmatory fact from being decisive: a message whose link is *currently listed* on a phishing feed scored only 0.35 (SUSPICIOUS). A rule may now declare itself `decisive`, which raises the case to the high-risk threshold on its own. Only the exact-URL feed match qualifies — a third party has directly observed that specific resource being used maliciously and there is no benign reading of it. A weaker host-level match deliberately does not qualify. The floor appears as its own visible line in the confidence contributions, never as a silent override.
- Verified end to end against live feed data: a message linking to a genuinely listed phishing URL is HIGH_RISK (0.70) with the decisive floor explained, while an ordinary business email linking to Google Drive and GitHub stays SAFE (0.02).
- Feeds auto-sync 5 seconds after startup and every 6 hours, never blocking boot or message processing; `THREAT_INTEL_AUTO_SYNC=false` disables all outbound feed traffic.
- 32 tests passing.

## 2026-09-20 — Operator-configurable detection content

Requested: a way to feed the tool information for MQL and NLP, and to describe new types of phishing, so a deployment can configure detection as it wants.

- **`modules/customDetectionConfig.js`** — one local JSON file (`data/custom_detection.json`) holding operator-defined MQL rules, NLP language patterns and indicator lists. Editable directly or through the API, reloadable without a restart, and never committed (gitignored).
- **Declarative conditions, never executed code.** A rule engine that ran operator-supplied JavaScript would be a remote code execution hole the moment anyone reached the API or dropped a file in the data directory. Conditions are field/operator/value structures evaluated by a fixed interpreter; nothing reaches `eval` or `Function`. There is a test asserting that a code-shaped condition is refused and that supplied content never executes.
- **20 queryable fields** (subject, body, sender address/domain/display name, reply-to domain, URLs and hosts, attachment names/extensions/count, SPF/DKIM/DMARC, NLP signals, already-matched rule ids, sender domain age) with text, list and numeric operators, combinable with `all` / `any` / `not` up to five levels.
- **ReDoS guard**: `matches_regex` rejects nested-quantifier patterns and long patterns, so one unfortunate rule cannot hang analysis of every incoming message.
- **A cited source is mandatory on every custom rule**, exactly as for built-in rules, so operator content stays as auditable as the shipped detection.
- **Custom NLP patterns** are evaluated alongside the built-in categories and carry their own operator attribution.
- **Operator indicator lists** (URLs, domains, IPs) are checked before the downloaded feeds and take effect even when no feed has ever been synchronised.
- **Graduated authority.** Custom rules were initially scored so weakly that an operator's own HIGH rule still produced a SAFE verdict, which would have looked broken. They now have their own scoring family capped at 0.30, and an operator may additionally mark a rule `decisive` — gated behind declaring it CRITICAL, since a decisive match raises the verdict to high risk on its own. Verified live: operator HIGH rule alone → SUSPICIOUS (0.38); the same rule declared CRITICAL + decisive → HIGH_RISK (0.70) with the floor shown in the contributions.
- **Malformed entries are skipped individually and reported** through `GET /api/detection-config`, so one bad rule never silently disables the whole configuration.
- **`POST /api/detection-config/test`** dry-runs a rule against a sample message and returns the evaluated context, so a rule can be checked before it is committed. Rule additions and removals are audit-logged with the acting user.
- 45 tests passing.

### Answer recorded on continuous monitoring (asked 2026-09-20)

The tool does **not** yet continuously monitor a live mailbox. The ingestion adapters exist (Gmail API + Pub/Sub, IMAP, SMTP, REST/webhook) but Gmail needs OAuth configured, IMAP and SMTP are off by default, remediation still defaults to `simulation`, the browser extension is a thin client that does not read mail, and the desktop app does not run the backend. Only the REST/webhook path is exercised today. Closing this is Phase 9 plus having the desktop app supervise the backend, and it should not be described as live monitoring until that is genuinely true.

## 2026-09-20 — Phase 9: ingestion coverage and the first verified live path

- **`modules/ingestionRegistry.js`** — an inventory of every way mail can enter, with each path's real state reported by the adapter itself rather than assumed from the existence of code. `GET /api/ingestion` answers the question that matters: could a message reach a user without being examined.
  - **Stall detection.** A poller that dies quietly is worse than one that was never enabled, because the dashboard keeps looking healthy while mail stops being examined. Sources that should report in declare a heartbeat interval and are marked STALLED after three missed intervals, with a warning saying mail arriving that way may not be examined. They recover automatically when polling resumes.
  - **Honest top-line state.** `monitoring_live_mail` is false, with an explicit warning, whenever only the manual submission paths are active — so a deployment that is merely analysing submitted samples is never described as monitoring a mailbox.
  - Unwatched paths carry an `enable_hint` saying exactly how to turn them on.
- **SMTP, IMAP and Gmail adapters now publish real state** — listening/disabled/failed with the reason, per-source ingested counts, last message time, and failures. IMAP heartbeats every poll cycle and reports connection failures as FAILED rather than only logging them.
- **Message file ingestion added** (`POST /api/ingest/file`), the entry path that was entirely missing: analyst-submitted samples and user-reported phishing forwarded as `.eml`. Outlook `.msg` is detected by its OLE signature and rejected with a clear explanation rather than being parsed as garbage.
- **Gmail preflight** (`gmailIngestionAdapter.preflight()`) states precisely which environment variables are missing and what to do next, instead of failing opaquely at the OAuth redirect. It also records that push delivery needs a Pub/Sub subscription, which is easy to miss.
- **Security fix caught during wiring**: the protected-route list contained `/api/ingest/email`, which does not cover `/api/ingest/file` — the new upload route would have been unauthenticated. Replaced with the `/api/ingest` prefix so no future ingestion route can be added unauthenticated by omission, with `/api/ingestion` listed separately because Express prefix matching needs a path boundary. Verified both return 401 without a key.
- **First genuinely verified continuous-monitoring path.** The SMTP gateway was started for real and a message delivered to it over SMTP with nodemailer: accepted with `250 OK`, intercepted by the listener, analysed automatically with no API call, and stored as case SM-2026-016026 at HIGH_RISK 0.86. The uploaded `.eml` BEC sample scored HIGH_RISK 0.99. This is the first path that can honestly be called live monitoring.
- 53 tests passing.

### Still not live monitoring Gmail

Gmail ingestion remains unverified because it requires the operator's own Google Cloud OAuth client and a Pub/Sub push subscription, neither of which can be created or tested from here. The code path exists and the preflight now says exactly what is missing. Remediation also still defaults to `simulation`, so actions are not performed against a real mailbox until both OAuth and `REMEDIATION_MODE=live` are configured.

## 2026-09-20 — Phase 5: campaign correlation that does not invent campaigns

The original audit flagged this as a real defect: "A Google/Microsoft/Cloudflare/shared-hosting IP/domain/ASN can therefore create false campaign links." A campaign view that merges unrelated incidents is worse than none, because an analyst acts on the grouping.

- **`modules/correlationGuard.js`** — decides whether an indicator may link cases at all. The distinction that matters is specificity:
  - *High specificity* (attachment hash, exact URL, exact sender address) is attacker-chosen, so sharing one is meaningful even across hundreds of messages.
  - *Low specificity* (ASN, provider mail IP, freemail sender domain, multi-tenant hosting domain) is shared by unrelated parties by design and proves nothing alone.
  - Suppressed both by a list of well-known providers **and** by prevalence: any low-specificity indicator appearing across 8+ cases in this deployment is infrastructure, whatever it is called. Prevalence is deliberately **not** applied to high-specificity indicators, because suppressing a widely reused phishing URL would break exactly the mass-campaign case correlation exists to catch. Both directions are tested.
  - Provider sending infrastructure is identified by reusing the forensic engine's existing `CLIENT_IP_OBSCURED_BY_PROVIDER` conclusion rather than guessing again.
- **Grouped scoring instead of summing.** One attacker host observed as an IP, a domain and a URL was previously worth 0.75 as though it were three independent proofs. Factors are now grouped into families (PAYLOAD, CONTENT, IDENTITY, INFRASTRUCTURE, TARGETING); the strongest in each counts in full and the rest at progressively halved weight. Independent families still accumulate normally.
- **Suppressed links are reported, not hidden.** `campaign_association.suppressed_factors` records each link that was deliberately not made and why, so an analyst asking why two similar-looking cases were not grouped gets an answer.
- **`modules/semanticCorrelation.js` — the missing Phase 5 capability.** Infrastructure correlation misses a campaign that rotates senders, domains and hosts between sends, which is what a competent operator does. What tends not to change is the lure written once and reused. Similarity is Jaccard overlap over the token characteristics already captured for adaptive learning, so it needs no extra storage and no retained message bodies, and the shared terms that produced a link are reported. Weight scales with similarity, since near-identical wording is far more specific than partial overlap.
  - Ordering bug found and fixed while wiring: it originally read `threatObject.learning_features`, which is not populated until after correlation runs, so it would never have matched anything. It now tokenises the current message directly and compares against the stored features of past cases using the same tokeniser.

### Verified end to end

- **Two unrelated phishing emails, both sent from gmail.com** → `UNASSOCIATED`, confidence 0, no related cases, with the suppression explained: *"gmail.com is a consumer mail provider used by unrelated senders."* Previously these would have been merged into one fabricated campaign.
- **One campaign reusing a lure across rotated sender, domain, IP and URL** → correctly linked at 100% wording similarity with the shared terms listed. Before this change these two shared no correlatable indicator at all and would have been entirely unlinked.

65 tests passing.

## 2026-09-20 — Phase 8: surfacing the intelligence the backend already had

Several capabilities were producing good data that no analyst could see. The dashboard now exposes them, each with its limitations stated alongside, per the plan's explainability requirement that no score appears without its evidence.

- **Mail Coverage view (new nav section)** — renders the ingestion registry: whether live mail is being monitored at all, every entry path with its real status, per-source ingested counts and failures, enable hints for unwatched paths, and Gmail readiness with exactly which settings are missing. The headline states plainly when only manual submission paths are active.
- **Intelligence State view (new nav section)** — what the system has taught itself and what it is matching against: learned-from counts, the strongest learned indicators with their malicious/legitimate evidence counts, behavioural baseline totals, recent learning events (including label corrections), and every threat feed with its status, indicator count and licence. When adaptive learning is below its training threshold it says so rather than showing a meaningless score.
- **Case investigation gained two tabs** — *Behaviour* (sender history, behavioural signals with explanations, and the learned-pattern match with its contributing characteristics) and *Threat Intel* (feed state, indicator matches with their source feed, and RDAP domain registration ages).
- **Campaign tab rebuilt** — now shows why cases are linked, the per-family scoring, messages reusing the same wording with the actual shared terms, and **links deliberately not made** with the reason, so an analyst asking why two similar cases were not grouped gets an answer.

### Verified in a real browser against live data

Not just compiled: backend and dashboard were run, four messages seeded through the pipeline, and each view checked in the browser.

- Mail Coverage showed `Monitoring live mail`, the SMTP gateway listening on 2531, IMAP switched off with its enable hint, Gmail not configured with the exact missing variables, and REST API correctly crediting 4 ingested messages.
- Intelligence State showed all five feeds SYNCED with live counts (13,342 URLs among them) and adaptive learning honestly reporting "not yet contributing to scoring" at 1 malicious / 0 legitimate.
- Threat Intel tab showed a real RDAP result (gmail.com, 11,360 days old) and correctly reported `.example` and an IP literal as unavailable with reasons.
- Campaign tab showed the semantic link at 92% similarity with the shared terms listed.
- A suspected verdict-badge mismatch in the threat queue was checked against the API rather than assumed: all four badges matched their true verdicts. No bug.

**Inconsistency found and fixed while reviewing the rendered output**: the Gmail enable hint named `GOOGLE_REDIRECT_URI`, but the variable the adapter actually reads is `GMAIL_REDIRECT_URI`. An operator following that hint would have set a variable nothing reads.

65 tests passing.

## 2026-09-20 — Phase 7: an investigator-complete forensic report

The report was a thin technical dump. It omitted NLP findings, MQL rule matches, threat intelligence, behavioural analysis, learned-pattern assessment, campaign detail, the case timeline, recommended action, analyst notes and any disclaimer — most of what the plan's section 28 requires and most of what the pipeline now produces. Its campaign section also read `threatObject.correlations`, a legacy field nothing populates, so it always reported zero.

- **Rewritten as 19 sections** covering everything section 28 lists: case information, message metadata, authentication, relay path, infrastructure and geolocation, threat intelligence, IOCs, attachments, language findings, rule matches, behavioural findings, learned-pattern assessment, evidence register, risk assessment, campaign relationships, remediation, timeline, analyst notes, and scope/limitations.
- **Written to be defensible rather than impressive.** The disposition and recommended action are stated first, and everything after is the evidence needed to check that conclusion. Every rule match prints the public source it derives from, so a reader can audit why a rule exists rather than trusting the match. Limitations are printed beside the finding they qualify, not buried at the end.
- **Absence is stated, never implied.** Anything undetermined renders as "Not available" rather than being omitted, so a gap is never mistaken for a negative result. Feed absence explicitly reads as "unknown, not established as safe".
- **Real data now included** that previously had no route into the report: audit events for the case timeline, remediation action history with provider results and failures, campaign factors, semantic matches, and the links deliberately *not* made with their reasons.
- **Pagination bug found by inspecting the output.** Writing the footer inside the bottom margin made PDFKit start a new page, so the report emitted one blank page per footer — 10 pages instead of 5 — and the printed totals said "of 5". Fixed by suspending the bottom margin for the footer write. This was only visible by parsing the generated PDF; it would not have shown up in any code review.
- **Verified against a real generated PDF**, not just compiled: a live case produced a 5-page report with all 19 sections, real RDAP data (gmail.com registered 1995), real rule citations (APWG, OWASP), the executable attachment, and no placeholder artefacts.
- Added `pdf-parse` as a dev dependency and 7 regression tests that parse the rendered PDF, asserting section completeness, rule-source citation, limitation text, suppressed campaign links, footer/page-count agreement, and clean rendering of a sparse case.

72 tests passing, 0 npm vulnerabilities.

## 2026-09-20 — Theme system, real executive protection, tamper-evident ledger, and Phase 11

### Architecture diagram audit

Checked the technical-approach diagram against the code. Everything shown exists **except** two items, both now addressed:

- **"Tamper-Evident Ledger"** was a plain JSON array, no hashing, capped at 500 entries via `pop()`.
- **"Executive Guard / VIP impersonation"** was four hardcoded names matched with substring tests.

### UI: light and dark themes

- Semantic theme tokens with dark (default) and light variants; **800 hardcoded colours across 19 files** replaced with tokens so a colour is never defined twice and the themes cannot drift.
- Status colours are not inverted between themes — a red that reads on near-black is washed out on white, so each theme carries its own ramp chosen for contrast.
- Follows the OS preference until the analyst chooses, then their choice wins and persists. Applied to `<html>` so scrollbars, form controls and Leaflet follow; map tiles are filtered per theme.
- Verified in a browser in both themes including the dense investigation view.

### Tamper-evident audit ledger

- Each entry carries a SHA-256 over its contents plus the previous entry's hash, so altering, deleting or inserting a record breaks every hash after it.
- Entries are now appended chronologically (a chain must run in the direction it was written) and overflow is **archived** rather than discarded — the old behaviour destroyed the earliest history and would have severed the chain.
- Integrity is returned with `/api/audit`, so a broken chain is never read as a trustworthy log. Honest about scope: this detects tampering, it does not prevent it; the limitation and latest hash are exposed for external anchoring.
- 8 tests attempt real tampering — modify, delete, forge, reload — all detected.

### Real executive protection

- Operator-managed directory of protected people and organisation domains, API-managed, validated and audit-logged. With none configured it reports `NO_DIRECTORY_CONFIGURED` rather than implying protection.
- Detects display-name impersonation (whole-token name matching, so a job title inside an unrelated address cannot trip it and a shared surname does not identify anyone), lookalike organisation domains by edit distance scaled to domain length, reply redirection while impersonating, and repeat targeting.
- **Wiring corrected**: executive evaluation now runs *before* evidence fusion, so its findings become evidence through the same path as every other signal. New EXECUTIVE scoring family.
- Verified end to end: a CEO-fraud message impersonating a configured CFO from a `cornpany.example` lookalike was caught on all three signals at HIGH_RISK 0.99.

### Phase 11 — measured, then optimised

Measurement first, per the plan. Two benchmarks added under `scratch/`.

**Local CPU is not the bottleneck**: ~1.08 ms per message end to end, ~926 messages/second on one core. MIME parsing is 73% of that; every other stage is under 0.05 ms.

**Network latency dominates wall-clock time**:

| Stage | Cold | Cached |
|---|---|---|
| RDAP domain age | 2125 ms | 0.2 ms |
| Reverse DNS PTR | 171 ms | — |
| DMARC DNS TXT | 69 ms | — |
| DKIM verification | 5.8 ms | — |

Two real problems found by measuring rather than guessing:

1. **DKIM verification and the DMARC lookup ran sequentially** despite being independent. Parallelised: `authAnalyzer.analyze()` median fell from ~102 ms to ~28 ms.
2. **Stored cases grew with the square of campaign size.** Semantic correlation wrote one factor *and* one evidence item per related case, so 50 similar messages produced 27 evidence items and 49 KB per case. In a 1,000-message campaign this would be crippling. Factors are now capped at the strongest 5 while `related_cases` stays complete and the remainder is recorded as `additional_similar_cases`. Storage fell from **49 KB to 27 KB per case** and evidence items from 27 to 7, with no scoring change since only the strongest per family counts in full.

Other measurements: API latency mean ~150 ms p95 ~180 ms (warm, dominated by lookups for unseen sender domains); memory 105 MB RSS after 50 cases; SQLite graph 100 KB.

90 tests passing.

## 2026-09-20 — SIEM operations overview, global threat map, and Phase 12 validation

### Operations overview rebuilt as a SIEM console

- Headline counts, 24-hour activity by verdict, ingestion-path breakdown, and a detections-by-rule table showing which rules are actually firing. Every figure derives from stored cases; an empty deployment says so rather than rendering an impressive-looking chart of nothing.

### Global threat map

- Every geolocated address the deployment has observed, on a pannable, zoomable world map, coloured by the severity of the worst case it appeared in (green / amber / red).
- Marker size reflects how often an address has been seen; severity is carried by colour alone so the two dimensions cannot be confused. Lower severities draw first so high-risk markers are never hidden beneath them.
- Each marker names the address, city, country, ASN, ISP, the role it played and how many cases it appeared in.

### Geolocation reworked

- **Fixes an audit finding**: lookups went to ip-api.com over plain HTTP, so addresses seen in the operator's mail crossed the network in clear text and the response driving the map could be modified in transit. Now HTTPS to a free, key-less endpoint.
- Results cache to disk rather than memory only, so a restart no longer re-queries every address ever seen.
- **Every public address in a message is now located, not just the selected origin** — a relay chain often crosses several networks and an analyst needs the whole path. Bounded per message, run concurrently.
- Reserved ranges are reported as unlocatable rather than given a guessed point.
- Verified with real routable addresses resolving to Brisbane, Moscow, San Francisco and San Jose with correct ASNs, rendering as severity-coloured markers in both themes.

### Phase 12 — final validation

The plan requires proving the whole chain, not the individual links. Added a validation test that drives `EMAIL → INGESTION → FORENSICS → NLP → MQL → IOC → THREAT INTELLIGENCE → GEOLOCATION → CAMPAIGN → RISK → EXPLANATION → MITIGATION → REPORT → DASHBOARD` in one pass against isolated state, asserting each stage actually contributed so a silently failing stage cannot pass as success.

A single crafted message exercising every capability produced **11 matched rules, 25 evidence items and a 0.99 score**, with the CFO impersonation, the `cornpany.example` lookalike, the known-bad URL, the newly-registered sender domain and the executable attachment all detected, the audit chain verifying, the raw message correctly not retained, and the generated PDF containing the verdict, the rules, the impersonated executive, the attachment and its limitations. A paired test confirms ordinary business correspondence passes the same pipeline as SAFE with no language signals.

Network-dependent stages are injected in the validation so it runs deterministically offline; each has its own tests and was verified live against real services separately.

**92 tests passing, 0 npm vulnerabilities, dashboard builds clean.**

## 2026-09-20 — Desktop app supervises the backend: one install, one thing to launch

Previously the desktop app was a shell that expected the backend to already be running, so a "single install" still meant starting services by hand.

- **`phishlens-desktop/backendSupervisor.js`** — starts, watches and stops the backend:
  - **Attaches rather than duplicates.** If a backend is already listening and healthy, the app uses it instead of starting a second. Two backends over one data directory would corrupt the case store and sever the audit chain, so this is a safety rule, not an optimisation.
  - **Owns a key, not a password.** A desktop install has no operator to invent a secret, so one is generated on first run, stored owner-only in the per-user application data directory, and passed to both the backend it starts and the console it loads. This is what makes the app work with no setup.
  - **Restarts a crash, gives up on a loop.** Three attempts, with the restart budget reset for a process that ran normally before exiting. Repeated immediate failures mean something is really wrong and silently restarting forever would hide it.
  - **Never orphans the backend.** The child is stopped on every exit path, since an orphaned server holding the port would block the next launch. A backend it merely attached to is left alone.
  - **Health probe checks for PhishLens specifically** — an occupied port answering 404 is not a working backend.
- **Startup screen replaces the blank window.** Live status, the backend's own captured log, a retry button, and a plain statement of what went wrong. The console is not loaded until the backend genuinely answers, because a dashboard rendering empty panels is indistinguishable from a healthy one with no mail.
- **Console authenticates itself** in the desktop app: the key arrives from the main process over the preload bridge, and the first data load waits for it rather than firing unauthenticated requests and rendering an empty console.
- **Installer now bundles the backend** as well as the dashboard build.

### Verified by actually running it, with nothing pre-started

| Test | Result |
|---|---|
| Launch app alone, nothing running | Backend went from HTTP 000 to HTTP 200; console loaded |
| Ownership | Backend pid 14396 confirmed as a child of the Electron main process |
| Generated key | Persisted (64 bytes); authenticated request 200, unauthenticated 401 |
| Close the app | Backend stopped, 0 processes left holding the port |
| Launch with a backend already running | Stayed at 1 listener, 0 spawned children — it attached |
| Close app that attached | Pre-existing backend still HTTP 200 — correctly left alone |
| Port blocked by a decoy | Stayed on the startup screen rather than showing a blank console |

9 supervisor tests added (`npm test` in `phishlens-desktop`) covering attach-not-duplicate, leaving a borrowed backend alone, rejecting a non-PhishLens listener, the restart-loop limit, the restart-budget reset, and key persistence.

**Honest caveat documented in the README**: the backend's `sqlite3` is a native module, so a packaged build must rebuild it for Electron's ABI (or point `PHISHLENS_BACKEND_NODE` at a system Node). A packaged build that skips this starts and then fails when the campaign graph opens its database.

**92 backend tests + 9 desktop tests passing.**

### Next architectural gap (not yet started)

- `DETECTION_PROVIDER` is still hardcoded to `sublime` with no local Sublime service in this repository — every ingestion path still calls out to an external, unconfigured detection dependency for MQL/rule matching (`mqlBridge.js` only normalizes a Sublime response; it does not run its own rules). This is the single largest remaining gap against the master plan's Phase 3 (Detection Engine): a native, source-cited MQL/rule engine (MITRE ATT&CK, APWG, CISA, OWASP, abuse.ch/OpenPhish/PhishTank-seeded rules per the compact plan) is not yet implemented, so the platform has no working detection path without an external Sublime instance.

## 2026-09-20 — Phase 6: making the response layer real, and honest about what it is not

Detection was finished and the response layer behind it was not. What was there
looked complete from the outside — a mode switch, a quarantine queue, approve
and rollback endpoints — and four separate parts of it did nothing at all.

### What was actually wrong

**The simulation switch decided nothing.** `REMEDIATION_MODE` was read by
`mailboxActionAdapter`, which had **zero callers**. The remediation engine
imported the Gmail adapter and called it directly. The server printed
`Remediation Mode: simulation` at boot and `/api/summary` reported `SIMULATION`
to the console, while the code underneath would have issued a real Gmail modify
call. The only thing preventing live mail from being touched was that no mailbox
had been connected yet; connecting one would have turned a setting that reads as
a safety switch into a label on a live wire.

**Every high-risk case was recorded as a failure.** Nothing ever wrote
`mailbox_provenance`, so every case carried the object's defaults — provider
`GMAIL`, `provider_message_id: null` — and containment could not resolve a
target. Verified by running it: a HIGH_RISK case came back
`remediation.status = FAILED`, `mailbox.status = ACTION_FAILED`. The console
would have shown a wall of action failures for messages that were never
actionable, with genuine provider failures indistinguishable among them. The
identifiers existed the whole time: the Gmail loop held the message id and
mailbox and handed them to the dedup store, and the IMAP poller was already
passing its UID into a fourth argument `processPipeline` did not accept.

**The safety guard could never fire.** It refused containment when
`detection.is_dev_fallback` was set or `verification_status` contained
`DEVELOPMENT` — fields from the era when detection was delegated to an external
service. `mqlBridge` assigns `is_dev_fallback` the literal value `false` and the
rule engine always sets `verification_status` to `PHISHLENS_NATIVE_MQL_VERIFIED`.
The condition was unsatisfiable. To anyone auditing the file it read as a safety
interlock; it was inert.

**Three endpoints called methods that did not exist.**
`/api/remediate/approve`, `/rollback` and `/override` called `approveAction`,
`rollbackAction` and `adminOverride`. None were defined on the engine. An
approval-gated policy could never be approved, and no action could be undone.

**A 0.95-confidence HIGH_RISK message got `NO_ACTION`.** Found by running a BEC
message through the live API. Every quarantine policy carried its own extra
condition — executive context, a Return-Path mismatch, campaign correlation —
and the warning policy only fired between 0.40 and 0.60. A message matching none
of them fell through to `DEFAULT_ALLOW`. Detection reached the right conclusion
and the response layer did nothing with it.

### What replaces it

**One chokepoint** (`modules/remediationGateway.js`). Every change to a real
mailbox goes through it and nothing else reaches Gmail or IMAP. It distinguishes
five outcomes, because conflating them is how a system ends up lying about
itself: `CONTAINED`/`RELEASED` mean a provider confirmed the change on read-back;
`WARNED` means marked and deliberately left delivered; `SIMULATED` means decided
and not carried out; `NOT_ACTIONABLE` means there is no mailbox to reach into — a
normal result for a message handed to us as bytes; `FAILED` means a real attempt
against a real mailbox failed, and is the only one worth an alarm.

`mailbox.status` now answers only the physical question — where is the message.
In simulation the answer is `INBOX`, so the dashboard's quarantine count stays
correct without knowing anything about modes.

**Guards that can actually refuse** (`modules/containmentGuard.js`), each naming
itself in the audit trail: a confidence floor above the HIGH_RISK line, because a
human reviewing a queue and a machine moving mail unasked are different risks;
two independent evidence families or one decisive finding, with `LEARNED_PATTERN`
excluded so a mistaken lesson cannot be a leg the decision stands on; an operator
never-contain list for mail whose delay costs more than the phishing it might
carry; and a burst ceiling so a misfiring rule cannot empty an inbox before
anyone notices.

**Provenance carried from ingestion**, so containment resolves a real target and
a file upload is reported as not actionable — naming the source — rather than as
a failure.

**IMAP containment** (`adapters/imapActionAdapter.js`), because remediation was
Gmail-only: a message could be analysed, scored and correlated and then not acted
on. Containment is a move into a folder, never a delete. Verification cannot
follow the UID — a moved message gets a new one — so it searches by the RFC 5322
Message-ID, which meant carrying that field through from parsing.

**Recipient warnings, described accurately.** PhishLens does not rewrite the body
of a delivered message. No provider permits editing mail already in a mailbox,
and a tool claiming to inject a banner into delivered mail is either rewriting at
the gateway before delivery or not doing it. What it does is apply a visible
provider label — a Gmail label, an IMAP keyword — and `recipient_visible` is true
only where a provider confirmed it on read-back.

**Policy coverage closed.** Every verdict now maps to a response; the specific
policies still take precedence because they explain themselves better. A test
walks confidence from 0.35 to 0.99 and asserts nothing falls through.

**Prevention, not just reaction** (`modules/dmarcAdvisor.js`). Everything else
here reacts to a message already sent. A domain published with DMARC `p=reject`
cannot be spoofed outright, which pushes an attacker onto a lookalike domain —
something detection catches far more reliably. The advisor assesses the
operator's own domains and returns the DNS record to publish, a staged rollout
rather than a jump to reject, and the consequence of leaving it. Checked against
real DNS: `gmail.com` correctly reported HIGH on its published `p=none`,
`paypal.com` OK on `p=reject`.

### Two defects found while verifying, outside Phase 6

**`campaignGraph.js` crashed the entire pipeline.** `totalWeight` is incremented
in four places and declared nowhere; a class method is strict mode, so each
assignment threw `ReferenceError`. The pipeline died the moment a case shared a
hash, URL, sender or executive target with an earlier one — precisely when
correlation becomes useful. The lines were also dead: scoring moved to
`correlationGuard.scoreFactors()`, which groups correlated indicators instead of
summing them. Removed.

**`/api/remediation/*` was unauthenticated.** The authenticated prefix list
contained `/api/remediate`, and Express prefix matching needs a path boundary, so
it did not cover `/api/remediation`. The admin routes failed closed with 401, but
posture and domain-hardening were publicly readable. Same class of bug as the
earlier `/api/ingest/email` vs `/api/ingest/file` gap; the file already carried a
comment explaining exactly this hazard.

### Where data lives

Twenty-one storage paths across eighteen modules resolved to a `data` folder
beside their own source. That is wrong twice over: a packaged desktop app's
directory is read-only on Windows and macOS, so the install shipped in the
previous chunk would have started and then failed at the first thing it tried to
remember; and in the test suite every module resolved to the same fixed folder,
so a test isolating its own state by moving those files aside did it to every
other test file running concurrently. That is not hypothetical — it is how it was
found, with the end-to-end test losing its own case mid-run.

All of them now go through `modules/dataPaths.js`, honouring
`PHISHLENS_DATA_DIR`. The desktop supervisor points it at the per-user
application data directory. Unset, the behaviour is exactly as before. A test
asserts no module has slipped back to a hard-coded path.

### Verified

| Check | Result |
|---|---|
| Simulation reaches the provider | 0 calls |
| Simulated case counted as quarantined | 0 of 3 |
| Live containment on confirmed read-back | reported CONTAINED |
| Provider that does not confirm | FAILED, not contained |
| File-uploaded HIGH_RISK case | NOT_ACTIONABLE, source named |
| Guard refusals (confidence, corroboration, list, burst) | each blocked, provider untouched |
| Burst limit of 3 across 5 messages | 3 contained, 2 held, 3 provider calls |
| Approval-gated policy | 0 provider calls until approved |
| Rollback of a simulated action | refused, with the reason |
| `/api/remediation/*` without a key | 401 on every route |
| Two related messages through the live API | both complete (crashed before) |
| Full suite, three consecutive runs | 139 / 139 each time |

**139 backend tests** (up from 92 — remediation had none), **9 desktop tests**,
dashboard builds clean.

### Still not built, and why

- **URL rewriting / click-time re-verification** needs a click-through endpoint
  the user hosts. Buildable locally, but it is a service with its own
  availability story, not a module.
- **Attachment sandbox detonation** needs an isolated VM or container.
  `attachmentAnalyzer` does static metadata and hash analysis with no execution;
  calling that detonation would be false.
- **IOC sharing to PhishTank/APWG** sends the operator's data to a third party.
  That is their decision to make, not a default.

**Phase 6 remains blocked on one thing only for live operation**: a Google Cloud
OAuth client (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GMAIL_REDIRECT_URI`),
a connected mailbox, and `REMEDIATION_MODE=live`. Until then every action is
reported as simulated, and the console says so at the top of the Response view.

## 2026-09-20 — Hardening audit: seven silent defects in code that already worked

No new features. The Phase 6 audit found five real defects in one pass by
looking for a specific shape — code that reads as protection and provides none —
so the same pass was run across the rest of the system. Everything below was
already shipped, already tested, and reported success while being wrong.

### A guard that hid a missing method

`gmailIngestionAdapter.preflight()` called
`mailboxConnectionManager.getAllConnections()`, which did not exist, behind a
`typeof === 'function'` check that substituted an empty list when it was
missing. The guard did its job perfectly: nothing ever threw, and readiness
reported **zero connected mailboxes for ever**.

`reportState()` feeds that straight into the ingestion registry, so the Mail
Coverage view — the one whose entire purpose is answering *could a message reach
someone without being examined* — would have shown Gmail as `NOT_CONFIGURED`
while it was actively ingesting mail.

The method was added and the guard removed. A defensive `typeof` on another
module's method converts a loud, once-only failure into permanently wrong
behaviour, so a test now fails if one reappears anywhere.

### A function that fabricated an audit record

`notificationAdapter.dispatchRecipientWarning()` composed a message, wrote an
audit entry reading `Recipient <address> notified: "..."`, and returned
`{ success: true }` — without sending anything to anyone. No email, no API call.

Nothing called it, which is the only reason the tamper-evident ledger was not
already carrying permanent false records of people being warned. It is removed
rather than repaired: warning a recipient is done by marking the message where
they will see it, which the remediation gateway does and reports as visible only
on provider read-back.

The same file's `dispatchSocAlert()` was real but had never been wired up, so an
operator who set `SOC_WEBHOOK_URL` got nothing. It is now called on containment,
awaited so a delivery failure is recorded as a failure rather than vanishing
into an unhandled rejection, and the audit entry distinguishes delivered from
failed.

### Authentication that defaulted open

`GET /api/overview` had **no authentication at all**. Its own isolation logic
keys off `req.user` — filtering by organisation, restricting employees to their
own mail — and `req.user` was never populated, so with no user it applied no
filter and returned every case in every organisation to anyone who asked:
senders, recipients, subjects, origin IPs, geolocation.

It was the third instance of one bug. Authentication was an allowlist of
protected prefixes, and Express matches mount paths on segment boundaries, so
`/api/ingest` did not cover `/api/ingestion` and `/api/remediate` did not cover
`/api/remediation`. Each was one forgotten line.

The default is now inverted: everything under `/api` is authenticated unless it
appears in `PUBLIC_API_ROUTES`, which holds three entries — liveness, sign-in,
and Google's push endpoint, the last separately verified by its Pub/Sub JWT.
Forgetting a line is now the safe outcome. Adding one is a visible edit to a
list of three.

While making that change the Gmail *connect* endpoints were briefly exempted by
mistake; they read `req.user.id`, so the exemption turned an authorization check
into a `TypeError` on undefined. Caught by testing every route in both states
rather than by reading the diff.

### Three identifier spaces that collide

| Identifier | Space | Collision by | Consequence |
|---|---|---|---|
| `campaign_id` | 900 | **48.8% at 35 campaigns**, 99.7% at 100 | PRIMARY KEY violation; the insert callback discarded its error |
| `action_id` | 90,000 | 99.6% at 1,000 actions | Map key — silently overwrites the record of something done to mail |
| `case_id` | 16.7M | 94.9% at 10,000 cases | Map key — silently replaces an investigation |

The campaign one is the worst, because `createCampaign` ended
`() => resolve(campaign)` — the callback ignored its error argument entirely. On
collision nothing was written, the function resolved as though it had succeeded,
and the case was filed under a `campaign_id` belonging to somebody else's
attack. Every later update then poured this case's indicators into that
campaign, silently merging two unrelated attacks in the graph an analyst uses to
understand what is happening to them.

Ten thousand cases is a few weeks of one corporate mailbox. All three now draw
six bytes from `crypto.randomBytes`; 100,000 generated ids of each kind are
distinct in the test.

### An enrichment failure that killed the detection

`updateCampaign` resolves `null` when its row has gone or the query errored, and
the very next line read `campaignRecord.campaign_id`. A storage problem in an
enrichment step would have taken the whole detection down with it — verdict,
evidence, remediation decision and all — for a message that had already been
correctly identified as malicious.

Campaign correlation is enrichment. Losing it must not lose the detection, so a
failed or absent campaign record is now recorded on the case as `UNAVAILABLE`
with the reason, and the message stays protected.

### What was checked and found clean

- **102 call sites** from `server.js` into modules: every method exists
- **68 cross-module call sites**: one missing method, fixed above
- **59 files** scanned for assignments to undeclared identifiers: none remain
  (`totalWeight` was the only one)
- **60 files** scanned for branches comparing against values nothing produces:
  none remain (the dead `DEVELOPMENT` guard was the only one)
- **58 routes** checked against the authentication mount in both states

Two of the scans produced false positives worth recording, because a check that
cries wolf is worse than no check: a parameter with a default value
(`evaluateRelayHops(hops = [], …)`) is a declaration, and an apostrophe inside a
comment broke a naive read of a quoted list. Both were the tooling being wrong,
not the code, and both were confirmed by hand before anything was changed.

### Also

`/api/summary` now carries the response posture, and the extension popup states
it. "Quarantined: 0" is ambiguous on its own — it reads as *nothing was
malicious* when it may mean *this installation does not move mail*, and a reader
should not have to infer which.

**151 backend tests** (up from 139), 9 desktop tests, dashboard builds clean,
full suite stable across consecutive runs. Twelve of the new tests are
regressions for the defects above; the rest guard the shapes that produced them.

The audit run wrote to its own data directory and left the real one untouched —
the `PHISHLENS_DATA_DIR` change from the previous chunk paying for itself
immediately.

## 2026-09-20 — The extension gets the two themes the console already had

The light/dark theming asked for at the UI overhaul reached the desktop console
and stopped there. The extension — the surface most people actually look at,
opened dozens of times a day — stayed dark-only with 308 lines of hard-coded
colours.

That is the one place a dark-only UI is most jarring: a popup opens *over*
whatever the person is already reading, so a near-black panel appears on top of
a white webpage in daylight.

### What it now does

Same two themes as the console, using the same token names, so a colour is
defined once per theme and the two surfaces cannot drift apart. The toggle sits
beside the settings gear in the popup header and beside the heading on the
settings page, matching the existing icon placement rather than introducing a
new control style.

Behaviour matches the console exactly: an explicit choice always wins; with no
choice stored the operating system preference is followed, and it keeps being
followed if the OS switches — until the person picks a theme themselves.

`theme.js` runs from `<head>`, not on `DOMContentLoaded`, and reads the
preference from `localStorage` rather than the extension storage API. Both
decisions are forced by the same constraint: the attribute has to be on `<html>`
before the first paint or the popup flashes the wrong theme on every single
open, and extension storage is asynchronous so it cannot be read in time.
Extension pages share one origin, so the popup and the settings page see the
same value.

### Contrast was measured, not eyeballed

The popup's text runs from 9.6px to 12.5px, so nothing in it qualifies for the
WCAG large-text exemption. Fifteen text-on-background pairs were measured in
both themes by flattening every translucent layer down to the page background
and computing the real ratio.

Three failed 4.5:1 — and two of them failed in the **dark** theme, meaning they
had been failing since before this change:

| | was | now |
|---|---|---|
| `--text-dim` on the app background (dark) | 4.15 | **4.65** |
| `--text-dim` on white (light) | 4.38 | **4.64** |
| HIGH badge on its own tint (dark) | 4.45 | **4.65** |

`--text-dim` is used by the section headings and the footer link. The
replacement values were computed by walking each colour towards white or black
until it cleared the threshold, not chosen by eye. All fifteen pairs now pass in
both themes.

The first measurement run was itself wrong and reported nonsense — it read the
page background once before switching themes, so every dark colour was scored
against a white backdrop, and `.recent-subject` came out at 1.48:1 while plainly
legible on screen. The screenshot disagreeing with the number is what caught it.

### One defect found in the process

The toggle rendered its label once, on attach. Any route to changing the theme
other than clicking it left the label stale — most realistically the
system-preference listener firing while the popup is open, which would leave the
button offering to switch to the theme already showing. Every route now goes
through one `apply()`, which notifies whatever is displaying the current theme,
so the label cannot disagree with the screen.

### Verified

| Check | Result |
|---|---|
| 15 text/background pairs, dark | all ≥ 4.5:1 |
| 15 text/background pairs, light | all ≥ 4.5:1 |
| Choice survives reopening the popup | dark → light → still light |
| No stored choice, OS set to light | light applied |
| No stored choice, OS set to dark | dark applied |
| Label after a theme change that was not a click | tracks correctly |
| Settings page | themed, toggle present |
