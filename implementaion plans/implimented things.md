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

**Caveat documented in the README**: the backend's `sqlite3` is a native module, so a packaged build must rebuild it for Electron's ABI (or point `PHISHLENS_BACKEND_NODE` at a system Node). A packaged build that skips this starts and then fails when the campaign graph opens its database.

> **Correction, 2026-09-20.** The caveat above is wrong, and is left in place rather than edited away so the record shows what was believed at the time. `sqlite3` 6.x is a Node-API addon — `napi_versions: [3, 6]`, and the compiled binary exports `napi_*` symbols — and Node-API is ABI-stable across runtimes. The same `node_sqlite3.node` opens a database, creates a table, inserts, reads the row back and closes cleanly under system Node (ABI 137) and under Electron's Node (ABI 149). No rebuild is needed. It was written from reasoning about native modules in general rather than from checking this one, and checking took a single command. See the packaging entry below for what the real packaging defect turned out to be.

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

## 2026-09-20 — The installer, built and actually run: it was broken, and so was the caveat

The one thing that had been claimed but never proven. "Runs from the repository"
was verified; "installs on a clean machine" was not. Proving it turned up two
defects, one of them in my own documentation.

### The first build succeeded and shipped a backend that cannot start

electron-builder exited 0 and produced a 111 MB `PhishLens Setup 1.0.0.exe`. The
backend inside it had **no `node_modules` at all** — no express, no sqlite3, no
mailparser. It would have installed cleanly and then died on the first
`require`, on a user's machine, with nothing in the build log to suggest
anything was wrong.

The cause is that electron-builder omits `node_modules` from an
`extraResources` file set, and no filter pattern overrides it — adding
`**/node_modules/**/*` to the filter changed nothing, which was checked rather
than assumed. The fix is a second resource set whose `from` points directly at
the directory, so `node_modules` is not a path segment being filtered but the
root being copied.

A green build is not evidence that the thing built works. That is the whole
lesson of this entry.

### The native-module caveat was wrong

The previous entry documented, at some length, that `sqlite3` would have to be
rebuilt for Electron's ABI before packaging or the app would fail when the
campaign graph opened its database.

That is false. `sqlite3` 6.x is a Node-API addon — its `package.json` declares
`napi_versions: [3, 6]` and the compiled binary exports `napi_*` symbols — and
Node-API is ABI-stable across runtimes. The same `node_sqlite3.node` opens a
database, creates a table, inserts, reads the row back and closes cleanly under
system Node (ABI 137) and under Electron's Node (ABI 149).

It was written from reasoning about native modules in general rather than from
checking this one, and checking took a single command. The README is corrected,
and the original claim is left in the log above with a dated correction under it
so the record shows what was believed at the time.

Correcting it also removed dead code: `runtime()` had an `if (!app.isPackaged)`
branch whose two sides returned identical values, left over from when a system
Node was going to be preferred.

### What the packaged app actually did

Launched from `dist/win-unpacked` — the real packaged layout — with no data
directory and nothing on the port:

| Check | Result |
|---|---|
| Backend answers after launch | HTTP 200 after ~9s, from a cold start |
| Backend is a child of the app | backend pid 10376, parent 25580 (the Electron main process) |
| Runtime used | Electron's own Node, no system Node required |
| Data location | `%APPDATA%\phishlens-desktop\data` |
| Written into the install directory | nothing |
| Generated key | 64 chars; `/api/summary` 401 without it, 200 with it |
| SQLite campaign graph | opened and written under Electron's Node, no rebuild |
| Full pipeline, twice | both HIGH_RISK; the second correlated into a campaign |
| Audit ledger | 6 entries written |
| Ingestion coverage | reported honestly: `monitoring_live_mail: false` |
| Closing the app | 5 processes → 0, port released, no orphan |

The machine was returned to how it was found: the data directory created by the
run held only synthetic test mail and was removed, and the repository's own data
directory was untouched throughout.

### Six packaging tests

They inspect the built output rather than the source tree, and skip cleanly when
there is no build to inspect: the backend and console are present; **every
declared dependency resolves from the packaged location**; the sqlite3 binary is
there; sqlite3 loads under Electron's Node specifically; and no `.env`, `data`,
`tests`, `scratch` or stray `test.json` travels inside the installer.

That last one matters on its own — an installer is a thing you hand to other
people, and the first build was shipping a `test.json` from somebody's scratch
work.

**15 desktop tests** (was 9), 151 backend tests, dashboard builds clean.

### Not done

The installer binary exists and is verified in unpacked form. It has **not** been
run against this machine: installing writes to Program Files and registers the
`phishlens://` scheme with the operating system, which is the user's call rather
than something to do while they are not looking. Everything that would differ
between the unpacked run and a real install is NSIS's own business — file
placement, shortcuts, the uninstaller, protocol registration — not the
application behaviour verified above.

Installer size is 134 MB, up from 111 MB, because it now contains the
dependencies it always needed. Documentation, tests, examples and source maps
are excluded from the bundled `node_modules`.

## 2026-09-20 — Attack shapes the pipeline could not see, and a caution about sources

A research document proposed an intelligence architecture. Most of it was
already built — MIME parsing, independent SPF/DKIM/DMARC, MITRE-cited rules,
open indicator feeds, evidence-based non-binary verdicts. What follows is the
part that genuinely was not.

### First, what was not implemented, and why

Every URL in the source document carried `?utm_source=chatgpt.com`, and the
statistics attached to them were the kind of precise-sounding detail that AI
chats fabricate: a named vendor report with a figure to one decimal place, an
attack count for a specific month, a Zenodo record number, a campaign dated to
the day. None of it was verifiable from here.

So none of it was hardcoded. No statistic from that document appears anywhere
in this codebase, and no report is cited that could not be checked. What *was*
taken from it is the architecture, which is sound, and the standards it names,
which are real and were read: RFC 8617, RFC 8628, and the MITRE technique
identifiers.

The feeds were checked by fetching them rather than trusting the list.

### ARC — the chain that must never reassure

`modules/arcAnalyzer.js`. RFC 8617 was not handled at all.

ARC exists because ordinary authentication breaks on forwarding: a mailing list
rewrites a message, destroying the DKIM signature and sending from its own IP,
so SPF and DKIM fail for mail that was legitimate when sent. ARC records what
each intermediary saw.

The reason it is a separate module rather than folded into the authentication
result is the warning in §9: ARC authenticates *who handled* a message, and says
nothing about whether they are trustworthy. So a valid chain never lowers risk
here. `affects_risk` is a field on the output rather than an implicit behaviour,
so that anybody wiring ARC into scoring later has to change that line and read
why it is there.

What a chain is good for is the opposite direction: explaining why SPF failed on
a message that really was forwarded, so an honest forward is not scored as a
spoof. A chain that is *broken* is a signal in its own right — forging a
plausible one is a way to manufacture an excuse for failed authentication.

Structural validation only, stated plainly: instance numbering, set
completeness, and `cv=` consistency. The seals are not re-verified
cryptographically, because that needs each intermediary's key and the exact
canonicalised bytes they signed, and getting it subtly wrong would produce
confident nonsense. Unverified is reported as unverified — which costs nothing,
since a passing chain cannot lower risk anyway.

### QR codes — a link that is not in the message

`modules/qrAnalyzer.js`. Every URL check in PhishLens — feeds, domain age,
lookalike detection — operates on URLs found in the text. A QR code is a URL
that is *not* in the text: it is pixels in an attachment, invisible to any
amount of language analysis, and the recipient resolves it on a phone that is
usually outside whatever protection the organisation runs on desktops.

Decoded locally with jsQR, jpeg-js and pngjs — all pure JavaScript, no native
build, no service, no key, nothing leaves the machine. The recovered URLs join
the IOC set before enrichment runs, so the existing intelligence applies to them
exactly as it does to a link somebody typed.

PDFs are reported as *not scanned* rather than skipped silently. Reading one
needs a full PDF renderer — a large dependency and a parser attackers actively
target. Saying so is the difference between a known gap and a blind spot.

**Three bugs found in my own decoder, by testing it rather than reading it:**

1. The first version inverted the pixel buffer by hand for a second pass, with a
   comment claiming jsQR misses inverted codes. Measured: it does not. Its
   default `inversionAttempts` is `attemptBoth`.
2. The second version called jsQR twice with fresh buffers to learn *which*
   polarity read. That silently stopped inverted codes being decoded at all —
   because **jsQR carries state between calls**. A failed `dontInvert` attempt
   makes the next call return null for an image it decodes perfectly on its own.
   Verified directly.
3. `onlyInvert` throws a TypeError from inside the library on a valid image.

The working version makes exactly one call, and observes polarity independently
from the image's mean luminance. An inverted fixture is now in the test suite,
which is what caught (2).

### Authentication-flow abuse

Rules for the case where every URL check comes back clean because the link
genuinely *is* the provider's. A device-code flow (RFC 8628) points at a real
Microsoft or Google authorisation page and supplies a code; what the recipient
authorises is a session for whoever generated it. No domain reputation check
will ever object.

Also: a near-empty body with an attachment, which is the shape where a content
classifier has nothing to read because nothing is written; and links served
through generic edge or tunnelling hosts, kept deliberately weak because that is
ordinary developer infrastructure.

### MITRE techniques as data

Every rule already cited MITRE in prose, which reads well in a report and is
useless to anything else — a SIEM cannot correlate on a sentence. The same
citations are now emitted as sorted technique identifiers, each carrying the
rules that attributed it so the attribution can be questioned rather than
trusted. Rules that predate this are parsed from their citation strings rather
than being hand-edited thirty times.

The name table covers only the techniques these rules actually cite. An unnamed
technique is reported with its id and a null name, which is honest, rather than
carrying a stale copy of the whole catalogue.

### PhishTank — and a conclusion of mine that was wrong

First attempt: three rapid requests returned HTTP 429, I concluded the feed
required a registered key, and I gated it behind `PHISHTANK_API_KEY`.

That was wrong, and it was wrong in the worst direction - it silently switched
off a working source. Checked properly, with redirects followed and requests
spaced: the keyless URL redirects to a signed CDN link and returns the complete
verified set. **76,677 URLs, 14 MB, three spaced requests all HTTP 200.** The
429 was rate limiting, not authentication. A key raises the rate limit; it does
not unlock the data.

Corrected: on by default, keyless, with the key used when present. Because the
feed is large and rate limited it declares a minimum sync interval of six hours
- asking for 14 MB every cycle earns a 429 and gains nothing, since the verified
set does not turn over minute to minute.

The effect is not marginal. The local indicator set went from roughly 20,000
URLs and addresses to **96,692**, almost five times as many, entirely from
re-checking something I had already decided.

Its CSV is parsed with a quote-aware splitter, because a phishing URL routinely
contains a comma and splitting on commas truncates it into an indicator that
matches nothing. Offline entries are dropped: a taken-down URL is history, not a
current indicator.

### Sources checked, by fetching them

Every endpoint below was requested rather than recalled.

| Source | Result |
|---|---|
| abuse.ch URLhaus / ThreatFox / Feodo / MalwareBazaar | 200, 2.4 MB / 1.2 MB / 565 B / 120 KB |
| OpenPhish community feed | 302 → GitHub raw, 200, 15 KB |
| PhishTank verified online | 302 → signed CDN, 200, 14 MB, 76,677 rows |
| Spamhaus DROP | 200, 47 KB |
| MITRE ATT&CK STIX (`attack-stix-data`) | 200 - the machine-readable form, better than scraping technique pages |
| RFCs 7208, 6376, 7489, 8601, 8617, 8628 | all 200 |
| CISA Known Exploited Vulnerabilities | 200, 1.7 MB - but it is a vulnerability catalogue, not email intelligence |
| Google Safe Browsing v4 | 404 without a key |
| VirusTotal v3 | 401 without a key |

Two datasets I had previously assumed were fabricated turned out to be real, and
saying so matters more than being consistent:

- **Zenodo 10.5281/zenodo.17314806** - "Phishing-Email-Detection-Dataset",
  published 2025-10-10, CC-BY-4.0, four named academic creators, 372.9 MB merged
  and 342.1 MB balanced. Research-grade provenance.
- **Zenodo 10.5281/zenodo.20250116** - "Cross-model evaluation of phishing
  detectors against LLM-generated emails", published 2026-05-16, CC-BY-4.0, tied
  to a peer-reviewed Frontiers paper. This is the AI-generated phishing corpus,
  and it is the only one of its kind found with a DOI and a licence.
- **cw-l/email-corpus** exists and is MIT licensed, but it is a personal GitHub
  account with 3 stars and no institutional backing. It fails the stated bar of
  avoiding unverified repositories, so it is recorded as found and not adopted.

### A test that failed for a reason unrelated to the change

The executive-guard suite moved a shared data file aside and put it back —
the same pattern already fixed twice elsewhere. `node --test` runs files
concurrently, so it relocated that file for every other suite at the same time,
and the domain-posture tests read organisation domains from it. The result was a
failure that appeared only when the two overlapped. Both now use private data
directories; four consecutive full runs are clean.

### Packaging

devDependencies were shipping inside the installer — a file watcher, a PDF
parser used only by tests, a QR *generator* used only to build fixtures. None
reachable at runtime, all of it weight in the download and surface in the
install.

Fixed with a staging step that resolves a production-only tree from the lockfile
rather than a hand-maintained exclusion list, which would need every transitive
dependency of every dev tool tracked by hand and would break silently when they
changed.

**Two bugs in that script, both caught by running it:**

1. It passed an invalid npm flag, and reported the failure as a bare "install
   failed" with nothing to act on. The message now carries the error.
2. The real cause underneath was `spawnSync npm.cmd EINVAL` — since the fix for
   CVE-2024-27980, Node refuses to spawn a `.cmd` without `shell: true`, and
   says nothing useful about why.

Worth noting what that near-miss looked like: the staging step failed, and a
134 MB installer was still produced, with **zero** packages in its backend.
Three packaging tests now assert that no dev dependency ships, that no runtime
dependency was pruned with them, and specifically that the QR decoder ships
while the QR generator does not.

### Installed, verified, uninstalled

The installer was run against a real machine, on a per-user install (no
elevation), with a deliberately stale `phishlens://` registration in place
pointing at a path that no longer existed.

| Check | Result |
|---|---|
| Install location | `%LOCALAPPDATA%\Programs\phishlens-desktop` |
| Backend after launch | HTTP 200 after ~10s, cold |
| Process tree | backend pid 2316, child of main pid 20876 |
| Per-user data | `%APPDATA%\phishlens-desktop\data` |
| Generated key | authenticated (401 without, 200 with) |
| QR phishing message end to end | decoded, T1566.001 + T1566.002 attributed, verdict SUSPICIOUS, policy chose RECIPIENT_WARNED rather than containment |
| Start menu shortcut | created |
| Deep link `phishlens://dashboard` | launched, no duplicate instance |
| Uninstall | install directory, Start menu entry and registry entry all removed |
| User data after uninstall | kept, which is correct |
| Orphan process on the port | none |

**The protocol-claim fix, tested properly.** The first attempt proved nothing:
the stale registration happened to point at the same path the app installed to,
so "it now points at the installed app" was true before the fix as well. Tested
again with the registration deliberately pointing at
`E:\some\old\build\PhishLens.exe` - a path belonging to no installed
application - the app reclaimed the scheme within a second of starting.

**One leftover, stated plainly.** The uninstaller does not remove the
`phishlens://` registration. NSIS removes what it created; that key is written
by Electron at runtime, so nothing cleans it up. After uninstalling, the scheme
points at a deleted executable. The practical impact is a dead deep link to an
application that is gone, and the reinstall case is covered by the claim fix
above. Removing it would mean dropping the runtime registration entirely, which
breaks running from source.

## 2026-09-20 — The Public Suffix List, and a false negative it was hiding

Continuing from the source research: of the sources verified, the Public Suffix
List was the one already needed by code that did not have it.

### The heuristic got 7 of 10 hosts wrong

`rdapAdapter.registrableDomain` treated the last two labels as the registrable
domain, with a hardcoded allowance for `co.uk` and six similar second-level
labels. Tested against ten realistic hosts, seven were wrong - and the wrong
ones were not obscure:

| Host | Heuristic said | Correct |
|---|---|---|
| `evil-bank-login.github.io` | `github.io` | `evil-bank-login.github.io` |
| `secure-login.pages.dev` | `pages.dev` | `secure-login.pages.dev` |
| `phish.workers.dev` | `workers.dev` | `phish.workers.dev` |
| `fake.web.app` | `web.app` | `fake.web.app` |
| `lure.blogspot.com` | `blogspot.com` | `lure.blogspot.com` |
| `x.netlify.app` | `netlify.app` | `x.netlify.app` |
| `trust.nhs.uk` | `nhs.uk` | `trust.nhs.uk` |

The consequence was concrete and exploitable. A domain-age lookup for a phishing
page on `evil-bank-login.github.io` queried `github.io` and got GitHub's own
registration date - **9,929 days, verified** - so a page created that morning
scored as a well-established domain. The newly-registered-domain signal could
not fire anywhere an attacker obtains a free subdomain, which is where phishing
pages actually live.

No pattern derives this. `co.uk` is a public suffix and `co.com` is not; only
the list knows.

### Verified against the list's own conformance suite

Not against cases chosen by whoever wrote the implementation - that is exactly
how the heuristic passed review while being wrong. The official
`test_psl.txt` was fetched and run: 82 cases, all passing.

The first run failed six of them, revealing two real bugs:

1. **A leading dot was silently accepted.** `.example.com` should have no
   registrable domain; `filter(Boolean)` dropped the empty label and turned it
   into `example.com`, answering a question that was never valid. Empty labels
   now make a host invalid.
2. **Punycode hosts never matched.** The list is published with unicode labels
   (`公司.cn`) while hosts arrive from mail headers already in punycode
   (`xn--55qx5d.cn`). The rule simply never matched and the host fell through to
   its last two labels - silently, with no error. Rules are now stored in ASCII
   form.

A third thing looked like a bug and was not: the ASCII-range check appeared in
the editor as `[^ -]`. The shell that wrote the file had turned the escape
sequence into literal control bytes, which JavaScript reads as the correct
range. It was unreadable rather than broken, and has been replaced with a form
no quoting layer can mangle.

### Correct extraction is not yet a detection

Fixing it only turns a wrong answer into an honest one: RDAP for
`evil-bank-login.github.io` returns 404, because nobody registered it. That is
better than a false reassurance, but it detects nothing.

The useful fact is the one the list supplies: the parent is a suffix **anyone
can obtain a subdomain of**. The attacker inherits a sixteen-year-old reputable
domain and valid TLS for the price of signing up. An organisation asking a
customer to sign in does not do so on one.

`MQL-URL-110` acts on that, and is deliberately a MEDIUM at 0.50 - these
platforms are entirely legitimate and heavily used, so it corroborates rather
than convicts. Verified to fire on github.io, pages.dev, workers.dev and
blogspot.com subdomains, and not on `login.paypal.com`, `www.bbc.co.uk`,
`example.com` or the bare suffix.

### Kept current, safely

The list is bundled in `reference/` rather than fetched during analysis - a
detection must not depend on a network call - and refreshable, because new
platforms are added regularly and a missing platform is precisely the blind spot
this closes. A refresh is sanity-checked before it replaces a working list: a
captive portal or error page returning 200 with HTML would otherwise silently
disable registrable-domain extraction for every host. Both failure paths are
tested.

**186 backend tests** (was 175).

## 2026-09-20 — The keyword layer could be switched off by the attacker

Given latitude to choose the approach rather than follow a source list, the
most valuable thing available was not another feed. It was a vulnerability in
what was already built.

### Demonstrated, not theorised

Take a sentence the language analyser detects — "Please verify your password
immediately. This is your final notice to sign in to your account." — and insert
a zero-width space between every character.

| | signals | score |
|---|---|---|
| Plain text | 2 | 0.48 |
| Zero-width space between each character | **0** | **0** |

The message renders identically in every mail client. The bytes differ, 94
against 187. Every pattern in that analyser matches substrings, and a substring
match cannot survive characters inserted between its letters.

This reframes the premise the work started from. Attackers are said to have
stopped using obvious keywords. Frequently they have not — the keywords are
arranged so the filter cannot see them, which costs one line of code and defeats
every keyword list ever written, including a perfectly good one.

### Two outputs, both necessary

`modules/textDeception.js` produces:

1. **A normalised copy of the text**, which the language analyser now reads
   instead of the raw body. Invisible characters removed, NFKC applied to fold
   fullwidth and mathematical variants, and Cyrillic/Greek/Armenian/Cherokee
   lookalikes folded to their Latin skeleton. Verified: obfuscated text now
   scores exactly what the text it renders as scores — 2 signals, 0.48.
2. **Findings about what was done to the text**, which are worth more than the
   words they concealed. Fluent AI-written prose is still fluent after
   normalisation; deliberately obfuscated prose is not. That distinction does
   not care how well the message is written, which is precisely the property
   needed here.

Four rules act on the second: invisible characters through the body, invisible
characters in the display name or subject (the two fields shown before a message
is opened), a word built from more than one alphabet, and a text-direction
override — the long-standing way to make a filename display with a different
extension from the one it has.

### What it must not flag, and does not

- **Ordinary correspondence** — clean, no findings.
- **A genuinely Greek email** — not flagged. The mixed-script check runs per
  *word*, not per message, exactly so that writing in another language is not
  treated as deception. A message containing English and Greek sentences is
  unremarkable; a single word built from both alphabets is not.
- **One stray zero-width character** — not flagged. Copying from a web page
  genuinely leaves one behind; scattering them through the text does not happen
  by accident. The threshold is five in the body.
- **A zero-width non-joiner in isolation** — not flagged. ZWNJ is grammatically
  significant in Persian and several Indic scripts, and treating its presence as
  an attack would penalise writing in those languages.

### End to end

A message combining a Cyrillic display name, a zero-width space in the subject
and zero-width injection through the body, run through the real pipeline:

- **HIGH_RISK, 0.77**
- Three deception rules matched
- 76 hidden characters counted
- `Аpple` resolved to `Apple`
- **The language signals were recovered** — URGENCY_PRESSURE and
  CREDENTIAL_REQUEST both fired, which they could not have done before

**200 backend tests** (was 186).

## 2026-09-20 — Thread hijacking: the case where reading the message cannot help

The strongest remaining gap, and the clearest answer to "attackers use AI to
write convincingly". In a hijacked thread the prose is genuinely flawless,
because it is a real conversation — quoted underneath, real names, real history.
No language model finds fault with it and no urgency heuristic applies. What is
wrong is who replied.

### The headers were parsed and thrown away

`mailparser` supplies `inReplyTo` and `references`; `emailParser` mapped neither
through. Nothing downstream could tell a genuine reply from a message that
merely claims to be one.

### Four shapes, weighted by how often they are what they look like

**A reply from a lookalike of an address already in the thread** (HIGH). A
correspondent being impersonated inside their own conversation.

**Authentication that changes partway through** (HIGH). Mail from this sender in
this thread has passed DMARC before and this message does not. The earlier
messages are what make it meaningful — they establish what this correspondent
normally looks like.

**"Re:" with no thread headers at all** (MEDIUM). Clients write In-Reply-To when
a person replies; presenting a message as part of an exchange without them
borrows the credibility of a conversation that left no trace.

**A new participant in a long-running thread** (MEDIUM, confidence 0.40).
Deliberately weak.

### Two bugs my own test found, not code review

**It accused a supplier of hijacking their own reply.** The first version
flagged any participant not seen before. In a two-party exchange the *second
message is always from somebody new* — so the rule fired on Sam's perfectly
ordinary first reply. What matters is not that a participant is new but which
one. Reworked so a new address only matters when it resembles one already
present, or when the thread is genuinely established.

**The lookalike comparison missed the most obvious hijack there is.** Comparing
whole domains, `supplier.example` and `supplier-invoices.test` are eleven edits
apart — the entire suffix differs — so it scored below every threshold. The
impersonation lives in the *label*, and comparing `supplier` against
`supplier-invoices` makes it plain. That fix depends on the Public Suffix List
added earlier, which is what resolves the label correctly.

Three lookalike shapes now caught: a domain built around a participant's name
(`supplier-invoices.test`), a single-character substitution (`suppiier`), and
the same name on a different suffix (`supplier.test`).

### Never learn from the attack

A high-risk message is never recorded as a thread participant. Indexing a
hijacker's address as legitimate would make the *next* message in that
conversation look entirely normal — the attack would teach the system to accept
it. Asserted by a test rather than left to comment.

### What the index holds

Message ids, the sending identity, and how each message authenticated. No
subjects and no bodies. It answers "has this conversation happened here", and is
not a second copy of the mail. Oldest threads are dropped past five thousand.

Its limitation is reported on every case: thread history covers only what this
installation has observed, so a newly deployed system knows no conversations and
these signals strengthen over time.

**212 backend tests** (was 200).

## 2026-09-20 — The installed app opened to a black screen

Reported from a screenshot: the window opened, the title bar read "PhishLens —
SOC Investigation Platform", and the content area was entirely black.

### Cause

`vite.config.js` set no `base`, so Vite defaulted to `/` and emitted

    <script src="/assets/index-CaRNkRRp.js"></script>

Served over HTTP that is correct, which is why `npm run dev` was never affected.
The packaged app loads the console over `file://`, where a leading slash means
the root of the filesystem — `C:/assets/…`. Every asset returned 404. The HTML
itself loaded, so the window title was right and the body's
`background-color: #0a0a0f` painted. A correctly-titled black rectangle.

Fixed with `base: './'`.

### Why it was not caught

The earlier verification checked that the backend answered HTTP 200 and that the
supervisor reported the console loaded. Both were true. `loadFile()` resolves
whether or not the page renders — the check confirmed the plumbing and never the
picture.

Measured with a headless Electron window loading the real build from disk:

| | rendered characters | root children |
|---|---|---|
| Absolute paths (shipped) | **0** | 0 |
| Relative paths (fixed) | **508** | 1 |

A packaging test now fails on any absolute asset path in the packaged console,
and separately resolves every referenced file to confirm it is actually in the
package rather than merely spelt correctly.

### The protocol handler, and where the investigation stopped

While fixing the above, `phishlens://` was found not to be registered after a
fresh install. The investigation, all of it against `dist/win-unpacked` rather
than by reinstalling:

| Launch method | Result |
|---|---|
| Direct execution | registers in ~3s |
| `ShellExecute` (what the installer uses) | ~1s |
| Via a `.lnk` shortcut | ~1s |
| With `--updated` (the upgrade path) | ~1s |
| From the installed app, over a stale handler | ~1s |
| From the installed app, over a bogus third path | ~1s |

electron-builder's NSIS template launches the app with
`StdUtils.ExecShellAsUser` on the Start Menu shortcut, passing `--updated` on
upgrades. Every one of those was reproduced by hand and every one registered
normally.

**The cause was not established.** The app's claim is correct in every scenario
that could be constructed; only the launch the installer performs itself fails.
The most plausible remaining explanation is that the installer's elevation is
not fully dropped, so the write lands in a different user's `HKCU` — but that
was not proven, and it is recorded as a hypothesis rather than a finding.

Two mitigations are in place. The app re-asserts the claim over the first ten
seconds of every launch, stopping as soon as it succeeds. And
`build/installer.nsh` registers the scheme from the installer, which also fixes
a leftover noted earlier: because the app wrote the key at runtime, NSIS had
nothing to remove and uninstalling left the scheme pointing at a deleted
executable. **The installer-side registration has not been observed to run** and
is carried as unverified.

In practice the handler is correct from the first time a person opens the
application themselves, which was confirmed on the installed build.

### Installed state, verified

| Check | Result |
|---|---|
| Console asset paths in the installed build | relative |
| Console renders | 488 characters, real navigation |
| Backend supervised | up in ~16s, child of the main process |
| Protocol handler after a normal launch | points at the install directory |
| QR hidden in an attachment | HIGH_RISK 0.77, decoded, 3 rules |
| Invisible-character obfuscation | HIGH_RISK 0.77, 60 characters, 3 rules |
| Fake "Re:" with no thread headers | SUSPICIOUS 0.40 |

### On method

Three install-and-uninstall cycles were spent on this before it became clear
that every one of those experiments could have been run against
`dist/win-unpacked` — the same packaged layout, no installer involved. Doing it
that way took minutes instead of cycles, and the whole launch-method matrix
above came from it.

## 2026-09-20 — The protocol handler: found, and it was not what any of the guesses said

Three hypotheses were tested and all three were wrong. The answer came from
making the installer report on itself.

### What was ruled out, with evidence

**Elevation.** The installer's embedded manifest requests `asInvoker`, read
straight out of the binary. It never elevates, so `HKCU` is the invoking user's
hive throughout. This had been the leading theory.

**The launch mechanism.** electron-builder's NSIS template starts the app with
`StdUtils.ExecShellAsUser` on the Start Menu shortcut, passing `--updated` on
upgrades. Every one of those was reproduced by hand against
`dist/win-unpacked` — direct execution, `ShellExecute`, a real `.lnk`, and the
`--updated` argument — and every one registered the scheme in about a second,
including over a stale handler and over a bogus third path.

**"The installer skipped as already installed."** The executable was rewritten
and its timestamp moved, so the installer genuinely ran.

### What it actually was

The `customInstall` macro was not executing, which could not be seen from
outside: the NSIS script is LZMA-compressed inside the installer, so 7-Zip reads
the payload rather than the script, and the registry afterwards only shows an
end state without saying who produced it.

So the macro was made to report on itself — perform its writes, read the value
back, and record both to a file beside the application. The first install after
that change produced **no file at all**, and alongside it a second fact: the
installed executable was present and current, but there was **no uninstall
registry entry**.

That places the failure precisely. In `installSection.nsh` the order is

    uninstallOldVersion → installApplicationFiles → registryAddInstallInfo
      → shortcuts → customInstall

Files were installed and everything after them was not. The install section was
terminating partway through, which is also why an earlier "upgrade install"
appeared to *remove* the application rather than update it.

Running the same installer again, with the previous version's state no longer
in the way, completed the section and the macro reported:

    customInstall ran
    INSTDIR=C:\Users\moham\AppData\Local\Programs\phishlens-desktop
    handler after write="C:\...\phishlens-desktop\PhishLens.exe" "%1"
    read-back=ok

The residue of a previous install is what breaks the run — the failure is in
electron-builder's uninstall-the-old-version path, not in the custom script.

### Where it stands

The installer now registers the scheme itself: the command, the `URL Protocol`
marker and a `DefaultIcon`, all verified present after install. Because the
installer owns the key, the uninstaller can also remove it, which fixes the
leftover recorded earlier — the app used to write the key at runtime, so NSIS
had nothing to delete and uninstalling left the scheme pointing at a deleted
executable.

The application still re-asserts the claim over the first ten seconds of each
launch. That is deliberate belt-and-braces: it costs one registry read when the
scheme is already correct, and it covers an install whose section did not
complete.

The self-reporting log is kept. It is a few hundred bytes and it answers, in one
file, a question that otherwise took an afternoon.

### Verified on the installed build

| Check | Result |
|---|---|
| Handler | points at the install directory |
| `URL Protocol` marker | set |
| `DefaultIcon` | set |
| Uninstall entry | PhishLens 1.0.1 |
| Start menu shortcut | present |
| Backend supervised | up in ~4s |
| `phishlens://dashboard` | opens the app, no duplicate instance |
