# SecureMail AI — Current-State Audit

**Scope:** read-only source, configuration metadata, persisted-state metadata, syntax, and localhost health checks on 2026-09-05.  No services were started and no email was submitted.  Evidence labels: **CODE** = verified from source; **RUNTIME** = verified by safe local check; **INFERRED** = needs a controlled integration test.

## Executive summary

SecureMail is a Node/Express orchestration and investigation dashboard around a **single external detection dependency: Sublime**.  It accepts raw email through unauthenticated local SMTP, optional IMAP polling, or unauthenticated HTTP; sends the full raw message to Sublime; then normalizes a small subset of Sublime's response and applies local heuristics, enrichment, graph correlation, policies, persistence, and a PDF view.

The strongest implemented elements are persistent local case/dedup/audit storage, a SQLite graph, defensive public-IP filtering, and a UI that renders backend case data.  The highest reliability blockers are the unavailable detection/runtime stack, duplicate race conditions, lossy IMAP acknowledgement, case-ID collisions, stuck dedup records, no API authentication, simulation mislabeled as confirmed remediation, and a demo-only extension.

## 1. Simplified project map

```
start-all.bat                         starts backend and Vite dashboard only
my-product-backend/
  server.js, config.js                Express API and complete processing pipeline
  adapters/                           Sublime, IMAP/SMTP, mailbox, DNS/geo/reputation adapters
  modules/                            local forensic, IOC, graph, evidence, policy, report logic
  models/                             ThreatObject, evidence, graph, audit and action shapes
  data/                               ignored runtime JSON/SQLite state (not source)
  test.json                           tiny non-executable test artifact
my-product-dashboard/                React/Vite SOC dashboard
my-product-extension/                Manifest-v3 popup extension (demo scan)
sublime-platform/                    vendored Sublime deployment/configuration repository (submodule modified)
sublime-rules/                       vendored Sublime rules, examples, EMLs, insights, YARA
```

Important backend files: `server.js` wires every pipeline stage and all APIs; `config.js` selects `sublime` and `http://localhost:8000`; `adapters/sublimeAdapter.js` POSTs base64 MIME to `/v1/messages`; `modules/mqlBridge.js` maps response fields to `ThreatObject`; `modules/dedupStore.js` persists RFC-Message-ID/raw-hash keys; `modules/caseManager.js` persists cases; `modules/campaignGraph.js` persists graph/campaigns in SQLite; `modules/pdfReportGenerator.js` streams PDFKit output.

Important dashboard files: `src/components/Dashboard.jsx` polls four backend APIs every 4 seconds; `CaseInvestigationView.jsx`, `ThreatMap.jsx`, `EvidenceGraphView.jsx`, `ExecutiveView.jsx`, `RemediationTimeline.jsx`, `AuditTimeline.jsx`, and `ForensicReportModal.jsx` are views over API data. `src/counter.ts`, `src/main.ts`, and starter SVG assets are unused Vite scaffolding; actual entry is `src/main.jsx`.

Important extension files: `manifest.json` has no Gmail/Outlook content script; `popup.js` always posts a hardcoded BEC sample; `background.js` can proxy a caller-supplied raw message to `/api/analyze`, but nothing sends it one.

Sublime files are not SecureMail-owned code. The repository includes a substantial vendored platform deployment plus rules/fixtures (`sublime-rules/emls`, tutorials, and rules); this is a detection corpus/deployment input, not a SecureMail runtime implementation.

## 2. Actual architecture and execution trace

| Step | File / function | Input | Output / next module |
|---|---|---|---|
| Ingest | `smtpListenerAdapter.start` / `IMAPAdapter.start`; `POST /api/analyze`, `POST /api/ingest/email` | raw MIME string | `mailIngestionAdapter.handleIncomingRawEmail` or directly `processPipeline` |
| Dedup | `dedupStore.computeMessageKey/reserveMessageKey` | RFC Message-ID preferred, otherwise raw SHA-256 | persistent JSON reservation |
| Detection | `detectionAdapter.analyze` → `sublimeAdapter.analyzeMessage` | base64 raw MIME | POST `${DETECTION_ENDPOINT}/v1/messages`, returns raw Sublime response |
| Normalize | `mqlBridge.normalize` | Sublime response + raw MIME | `ThreatObject` with sender/recipient/subject, auth from hop 0, raw hash |
| Audit | `auditLogger.log` | initial object | JSON audit event |
| Forensics | `forensicEngine.analyzeHeaders` → `relayTrustEngine` / `dnsAdapter` | Sublime hops or raw `Received:` headers | relay roles, return-path mismatch, selected public infrastructure candidate |
| IOC | `iocExtractor.extract` | case + raw message | IP/domain/HTTP(S) URL sets; no attachment hashes |
| Enrich | `infraEnricher.enrich` | selected origin IP | IP-API, optional VPNAPI, AbuseIPDB/IPQS, DNS/PTR |
| Correlate | `campaignGraph.processThreatObject` | case IOCs/infra | SQLite nodes/edges/campaign association |
| Evidence | `evidenceFusion.fuse` | auth, mismatch, keywords, enrichments, campaign | freshly generated `EvidenceObject[]` |
| Executive | `executiveGuard.evaluateTarget` | sender/recipient/subject | hardcoded VIP context and additional evidence |
| Confidence | `confidenceEngine.calculate` | evidence/relay | threat, infra, campaign labels and verdict |
| Policy/remediation | `policyEngine.evaluate` → `remediationEngine.executePolicyDecision` | case | local action record; simulation by default |
| Persist | `caseManager.saveCase`, `dedupStore.bindCaseId` | final case | `cases.json`, dedup JSON |
| Presentation | `/api/*`, dashboard, PDF endpoint | persisted in-memory/local state | dashboard cards/graph/PDF |

## 3. Sublime/MQL boundary

| Capability | Current owner | Evidence |
|---|---|---|
| Email parsing, message model, parsed hops/auth fields | **SUBLIME** | `mqlBridge.normalize` reads `rawResponse.data_model`; SecureMail has a limited raw Received fallback. |
| Detection provider/rules/MQL execution/classification | **SUBLIME** | `detectionAdapter` supports only `sublime`; endpoint `/v1/messages`. |
| SPF/DKIM/DMARC input | **SUBLIME** | only `hops[0].authentication_results` is read. |
| Rule matches | **NOT IMPLEMENTED in SecureMail normalization** | `matchedRules` is created as `[]` and never filled. |
| Raw fallback header/Received parsing, mismatch heuristic | **SECUREMAIL** | `relayTrustEngine`, `forensicEngine`. |
| IOC extraction and local evidence/policy/graph | **SECUREMAIL** | local modules listed above. |

If Sublime stops, all ingestion paths reach `sublimeAdapter` and throw; no new case can complete. There is no fallback provider, and no mocked detection fallback.  Once a valid normalized ThreatObject already exists, the local forensic, IOC, enrichment, graph, evidence, executive, confidence, policy, remediation, persistence, dashboard, and PDF code can conceptually operate—but there is no exposed endpoint to resume that stage independently. **CODE.**

## 4. Backend subsystem status

| Subsystem | Status | Evidence / main limitation |
|---|---|---|
| Email ingestion | PARTIAL | SMTP and optional IMAP code exists; runtime down; SMTP unauthenticated. |
| ThreatObject | PARTIAL | model exists; ID is random 5 digits and has no provider message ID field. |
| Forensic/header/relay reasoning | PARTIAL | local heuristics, no trusted-boundary configuration or timestamp validation. |
| IOC extraction | PARTIAL | regex URLs/domains/IPs only; hashes always empty. |
| DNS/PTR/FCrDNS | IMPLEMENTED BUT UNVERIFIED | `dnsAdapter.lookupPtr`; IPv6 validation is incomplete. |
| Geo/ASN/ISP/anonymization/reputation | IMPLEMENTED BUT UNVERIFIED | live providers only when configured; memory-only cache; no RDAP/WHOIS implementation. |
| Evidence fusion | PARTIAL | evidence is regenerated, not independently persisted; correlation facts can double-count. |
| Confidence | PARTIAL | fixed additive weights, campaign calculation conflicts with graph result. |
| Campaign graph | PARTIAL | SQLite persists; broad IP/domain/ASN links can over-correlate. |
| Executive protection | MOCKED/PARTIAL | four hardcoded VIPs; no persistence/configuration/lookalike or Reply-To logic. |
| Policy/remediation | PARTIAL/MOCKED | policy works locally; default simulation claims success. |
| Cases/audit | PARTIAL | JSON persists; restart mutates old cases (see below); audit capped at 500. |
| PDF report | PARTIAL | PDFKit endpoint exists, but sections omit true rule data, full campaign/evidence provenance/remediation history/audit events. |
| Health/startup | PARTIAL | health endpoint is static claim; runtime check found no listeners. |

## 5–7. Ingestion, phantom data, and idempotency

**Can one real email enter `processPipeline()` more than once? Yes—risk verified from code.** `mailIngestionAdapter` reserves a key, then `processPipeline` reserves it again. The second reservation does not return when the existing record lacks a `case_id`; concurrent direct `/api/analyze` or `/api/ingest/email` calls can both proceed while a key is `PROCESSING`. There is no lock across processes. **CODE: `server.js:processPipeline`, `mailIngestionAdapter.js`.**

SMTP and IMAP of byte-identical mail share the same RFC-ID/raw-hash key and normally suppress after binding. Variants of the same physical message (rewrapping, header changes, missing/changed Message-ID) are distinct keys. The IMAP worker saves UID **before awaiting** pipeline completion; failure/restart can lose a message, while the generic first-start `UNSEEN` search and UID state loss can revisit mail. It has one interval per process and clears a prior interval, but multiple backend processes have no coordination. **CODE.**

Dedup persists across restart in `data/processed_messages.json`, but failed/processing entries are never retried or expired. Current state has 2,635 records: 802 `COMPLETED`, 1,098 `FAILED`, and 735 `PROCESSING`; 2,632 list `IMAP_INBOX`, 3 `MANUAL_TEST_API`, and 1 `SMTP_GATEWAY`. **RUNTIME: read-only state count.**

One email does **not** reliably map to one case: dedup is identity-based but `ThreatObject` case IDs are random `SM-YYYY-#####`, are not collision checked, and concurrent reservations can create multiple cases. Dedup survives restart if its ignored JSON survives, but case identity is not the dedup identity. `caseManager.initStorage` also rewrites loaded cases and may mark old `PENDING` cases as `QUARANTINED` without provider action when a policy condition is met. **CODE.**

No normal backend startup timer creates email/cases. The extension does create a case by posting its hardcoded `sampleEmail` every time Scan is clicked. Therefore **phantom/demo cases can be created during normal extension runtime**. Random identifiers do not themselves create cases. **CODE: `my-product-extension/popup.js`.** `test.json` is a small unused artifact; vendored Sublime contains sample EMLs.

## 8–12. Detection, forensics, infrastructure, evidence, confidence

Sublime is definitely the configured and only detection engine (`DETECTION_PROVIDER` defaults to `sublime`); it is local by default at `http://localhost:8000`, configurable by `DETECTION_ENDPOINT`. SecureMail sends `{raw_message: <base64 MIME>}` with Bearer key. It receives and retains the raw response only transiently in `_raw_data_model`; it normalizes preview/data-model sender, recipients, subject, hop-0 SPF/DKIM/DMARC and `rawData.status`. Rule matches are discarded. Unavailability aborts the pipeline. **CODE.**

SecureMail itself does a naive From/Return-Path containment comparison, regex Received parsing, host-name keyword relay role classification, public-range filtering, origin selection, URL/domain extraction, BEC keyword matching, and fixed confidence/policy logic. It does not independently validate SPF/DKIM/DMARC, parse Reply-To, reconstruct timestamp chronology, validate a recipient trust boundary, or extract MIME attachments/hashes. `relayTrustEngine` labels hosts by substrings such as `google`, `outlook`, `mail-`, so trust/origin conclusions are heuristic. It gives a timestamp-consistency +0.15 contribution unconditionally. **CODE.**

Infrastructure correctly returns null/UNAVAILABLE for non-public/test-net addresses and the UI explicitly says location is observed infrastructure, not a human sender (`ThreatMap.jsx`). IP-API is plain HTTP, cached only in memory; VPNAPI/AbuseIPDB/IPQS require optional env keys; there is no RDAP/WHOIS. Provider failure returns nulls rather than fake geo. **CODE.**

Evidence has type, source, severity, confidence, explanation, and limited provenance but is not its own durable store. It can double-count correlated facts: shared URL and the domain derived from it each add 0.25; shared IP/domain/ASN may describe one provider relationship; SPF/DKIM/DMARC failures each add high evidence. `confidenceEngine` simply adds severity values (critical .35/high .25/medium .15), caps at .99, floors every case at .05, derives infrastructure confidence from a questionable “earliest” relay selection, and overwrites graph campaign confidence with .85 whenever legacy `correlations` is nonempty (that array is otherwise never populated). Executive risk has no separate score; actor attribution is always `INSUFFICIENT EVIDENCE`. **CODE.**

## 13–16. Graph, executive protection, remediation, report

The graph has persistent `nodes`, `edges`, and `campaigns` SQLite tables and `/api/graph` returns at most 200 each. It correlates exact hashes (.30), IP/domain/URL (.25 each), sender (.20), executive (.15), and ASN (.05); no common-provider suppression exists. A Google/Microsoft/Cloudflare/shared-hosting IP/domain/ASN can therefore create false campaign links and multiple related facts can compound confidence. Executive context is evaluated **after** graph processing, so executive graph/correlation branches do not work for a newly processed object. Actor identity is not inferred. **CODE.**

Executive protection is **MOCKED/PARTIAL**: four hardcoded names/email addresses, simplistic substring matching, no stored VIP directory or API, no lookalike-domain distance, Reply-To, Return-Path-specific executive logic, repeated-target scoring, or separate executive confidence. **CODE: `executiveGuard.js`.**

`QUARANTINED` is normally **local simulation state**, because `REMEDIATION_MODE` defaults to `simulation`; `simulationMailboxAdapter` returns success with random simulated IDs. Gmail live code exists only when mode is literally `live` and a Gmail token is present. Critically, without a token `gmailMailboxAdapter` pretends a simulated request and `verifyMessageState` returns verified true, so it can label an unperformed action as confirmed. No Microsoft Graph, gateway action, or real block-list adapter exists. IOC/campaign response objects are recommendations in memory; recipient warning only writes audit text unless an external SOC webhook is configured. **CODE.**

PDF report is **PARTIAL**: PDFKit streams case metadata, detection/auth/header/relay/infra/IOC/evidence/confidence/remediation text. It does not load audit events, show remediation action history, enumerate campaign factors, preserve raw Sublime rule matches, include a general forensic disclaimer, or manage pagination; it is a technical data dump rather than an investigator-complete report. **CODE.**

## 17–20. Frontend, extension, data, APIs

Dashboard pages are Overview, Investigations, Campaigns, Intelligence Graph, Executive Protection, Response, Reports, and Audit. `Dashboard.jsx` polls cases, graph, VIPs, and audit every 4 seconds; remediation has its own 4-second poll. Views use backend data and locally compute only display counts/filtering/colors/relative times. Empty states exist in several components; the root dashboard catches errors only to console and still displays “Systems Operational”/“Live Ingestion” regardless of health. Graph calls itself interactive but renders pills/listed edges, not a spatial graph. **CODE.**

The extension is **DEMO-ONLY**: no Gmail/Outlook host permissions or content scripts, no active-email extraction, no raw MIME/header acquisition, no case lookup, and hardcoded localhost URLs. Its popup submits a fixed test-net BEC email and Report only shows an alert. No credentials are embedded. **CODE.**

Persistent stores: `cases.json` (941 cases, 314 MB), `processed_messages.json` (2,635 dedup records), `remediation_actions.json` (46 actions), `audit_log.json` (500 retained events, cap 500), and `knowledge_graph.sqlite` (25 MB). `iocResponseManager` is in memory only; VIP list and policy configuration are source literals; geo cache is in memory. IMAP UID state would persist in ignored `imap_state.json` when created. **RUNTIME metadata/CODE.**

| Method | Path | Purpose | Auth | Used by | Status |
|---|---|---|---|---|---|
| GET | `/api/health` | static health/dedup/mode claim | none | none found | misleading health |
| POST | `/api/analyze` | raw email processing | none | extension/dashboard service | active code |
| POST | `/api/ingest/email` | webhook raw email processing | none | none found | duplicate of analyze |
| GET | `/api/cases`, `/api/cases/:id` | local cases | none | dashboard | active code |
| GET | `/api/graph`, `/api/vips`, `/api/audit` | graph/VIPs/audit | none | dashboard | active code |
| GET/POST | `/api/remediate/actions`, `/approve`, `/rollback`, `/override` | local/possibly Gmail action control | none | dashboard | unsafe unauthenticated control |
| GET | `/api/remediate/iocs`, `/api/remediate/campaign/:id` | memory recommendation/plan | none | dashboard | partial |
| GET | `/api/reports/pdf/:id` | case PDF | none | dashboard | partial |

## 21–24. Security, Git, startup, runtime health

**Security findings:**

1. **CRITICAL — unauthenticated destructive APIs and permissive CORS.** `server.js` uses `cors()` and has no authentication on analyze/ingest/approve/rollback/override; local browser origins can invoke them.
2. **HIGH — unauthenticated SMTP listener.** `smtpListenerAdapter.js` disables AUTH on port 2525; binding is not restricted to loopback.
3. **HIGH — plaintext HTTP to IP-API.** `geoIntelAdapter.js` sends queried IP data over `http://`.
4. **HIGH — false remediation confirmation.** simulation/default and no-token Gmail paths return success/verified without mailbox proof.
5. **MEDIUM — raw mail/PII persists locally.** Cases/audit include sender, recipient, subject, hashes and can be very large; `test.json` contains email content. Audit API exposes it without auth.
6. **MEDIUM — IMAP TLS disables certificate verification.** `tlsOptions.rejectUnauthorized: false`.
7. **MEDIUM — stale state reliability.** 735 `PROCESSING` and 1,098 `FAILED` dedup records have no recovery state machine.
8. **LOW — frontend presents health as operational without health check.**

Git hygiene is presently **SAFE TO PUSH only after reviewing `git status` and without force-adding ignored state**: `.env`, SQLite, JSON state, logs, node_modules, and dist are ignored; redacted tracked-source pattern check found no literal key assignment. It is not a guarantee: untracked `.env` exists, current state files can contain PII, and `sublime-platform` is a modified submodule. Never force-add ignored runtime files.

Startup is not unified. `start-all.bat` starts `node server.js` and `npx vite --port 3005`; it starts neither Sublime on 8000/3000 nor any separate DB service (SQLite is embedded). SMTP always starts with backend; IMAP starts only with `IMAP_ENABLED=true` and credentials. Package scripts do not define `securemail`; backend test script intentionally fails. Required manual order: start configured Sublime/MQL, then backend, then dashboard (or batch for the latter two).

**RUNTIME health:** localhost checks found no listeners/services at backend 3001, dashboard 3005, Sublime default 8000 or SMTP 2525; `/api/health`, `/api/cases`, `/api/graph`, and dashboard were unreachable. Backend/extension JS syntax check passed for 42 source files. No integration behavior is runtime verified.

## 25. Feature matrix

| Feature | Status | Owner | Real/Mock | Runtime Verified | Main Issue | Decision |
|---|---|---|---|---|---|---|
| Sublime detection | PARTIAL | SUBLIME | real integration code | no | sole dependency, rule matches discarded | VERIFY |
| SMTP/IMAP ingestion | PARTIAL | SECUREMAIL | real adapters | no | unauth SMTP, race/loss risks | FIX |
| Threat/case/dedup persistence | PARTIAL | SECUREMAIL | local JSON | state only | random IDs, stuck records | FIX |
| Header/IOC forensics | PARTIAL | HYBRID | heuristics | no | incomplete parsing/validation | IMPROVE |
| IP intelligence | PARTIAL | THIRD-PARTY SERVICE | live if configured | no | no keys/configured proof; HTTP geo | VERIFY |
| Evidence/confidence | PARTIAL | SECUREMAIL | local | no | arbitrary/double counting | FIX |
| Graph/campaign | PARTIAL | SECUREMAIL | SQLite | state only | broad correlation | FIX |
| Executive protection | PARTIAL | SECUREMAIL | hardcoded demo registry | no | no config/lookalikes | REMOVE |
| Remediation | MOCKED | HYBRID | simulation default | no | success can be false | FIX |
| Dashboard | PARTIAL | SECUREMAIL | backend-driven | no | fake operational indicator | VERIFY |
| PDF report | PARTIAL | SECUREMAIL | local PDFKit | no | incomplete provenance/history | IMPROVE |
| Chrome extension | DEMO-ONLY | SECUREMAIL | hardcoded sample | no | does not inspect mail | REMOVE |

## 26–32. Decisions, MVP, evaluator view, completion, risks, roadmap

### Keep & freeze

Public/test-net IP filtering, null/unavailable enrichment behavior, location disclaimer, raw-hash provenance, basic JSON/SQLite persistence structure, and the dashboard’s backend-data rendering should be retained while behavior is verified.

### Fix now

Authenticate APIs/SMTP and restrict CORS; make the dedup reservation a single durable state machine; do not advance IMAP UID before successful durable processing; make case IDs collision-safe and bind to durable message identity; make remediation status truthful; stop `caseManager` from mutating historical remediation on startup; replace dashboard health claims with health data.

### Verify

Actual Sublime response schema/auth fields/rules, IMAP delivery/restart behavior, DNS/geo/reputation providers, SQLite operational behavior, Gmail tokened action/rollback, and PDF rendering.

### Improve later / remove or disable

Improve report readability and actual graph visualization. Disable the extension scan or label it explicitly demo-only; remove unused Vite scaffold files and stale `test.json` after a separate approval. Do not claim RDAP/WHOIS, real executive protection, real quarantine, or active IOC blocking.

### True MVP today

There is **no runtime-verified end-to-end MVP today** because all services were down. The strongest code-supported demo, once a controlled Sublime instance is verified, is: controlled raw EML → authenticated/controlled `/api/analyze` → Sublime verdict/auth input → SecureMail header/IOC/enrichment/evidence → persisted case/graph → dashboard/PDF. Desired SIH demo adds real mailbox acquisition, validated detection/rules, reliable idempotency, truthful remediation and actual active-email extension; these are material gaps.

### SIH evaluator assessment

Impressive: a cohesive investigator workflow, structured evidence/provenance intent, infrastructure caveat, persistent graph, and explicit actor-attribution limitation. It looks like a Sublime wrapper where detection/auth parsing is presented as SecureMail AI. Strongest original contribution is the downstream case/evidence/correlation workflow, not the detection. Judges will question detection ownership, rule output absence, real-mail ingestion, duplicate claims, hardcoded VIPs, actual quarantine, and extension authenticity. Demonstrate the controlled pipeline only after runtime proof; do not demonstrate live remediation, extension scanning, health indicators, or attacker geolocation until fixed. Scope is too large for the current trust baseline.

Completion estimate (implementation maturity, not correctness): Detection integration **45%**; Email ingestion **35%**; Forensic engine **40%**; Infrastructure intelligence **35%**; Evidence fusion **35%**; Campaign correlation **35%**; Executive protection **20%**; Remediation **20%**; Dashboard **55%**; Forensic report **40%**; Chrome extension **10%**; Operational reliability **15%**; Demo readiness **25%**. **Overall SIH MVP readiness: 30%**—there is substantial code and persisted historical state, but no current runtime proof and several mechanisms make security conclusions/actions untrustworthy.

Top risks: (1) unauthenticated action APIs; (2) unauthenticated SMTP; (3) false quarantine confirmation; (4) duplicate/racy case creation; (5) IMAP loss/stuck reservations; (6) Sublime single point of failure and discarded rules; (7) heuristic/double-counted scoring; (8) false campaign links; (9) hardcoded/demo extension/VIPs; (10) misleading availability UI. Priority future action is respectively auth/restriction, SMTP hardening, truthful action verification, transactional idempotency, recovery/retry, detection contract test, scoring calibration, correlation guards, remove/label demo paths, health-driven UI.

Recommended sequence (maximum seven milestones):

1. **Trust boundary** — auth/CORS/SMTP binding; acceptance: unauthorized local/browser/SMTP requests are rejected.
2. **Ingestion correctness** — durable transaction/state/retry semantics; acceptance: same message via SMTP+IMAP+restart produces one case and no lost UID.
3. **Detection contract** — run known controlled EMLs through a live Sublime instance; acceptance: stored rule/auth/hop fields match the response contract.
4. **Truthful response** — separate simulation/local/live and require provider proof; acceptance: UI/API never call a simulated action quarantined.
5. **Evidence/correlation calibration** — group dependent facts and suppress common infrastructure; acceptance: test cases do not inflate scores/campaigns.
6. **Freeze verified demo** — add safe integration tests and health checks; acceptance: full controlled EML-to-dashboard/PDF demo repeats after restart.
7. **Only then polish** — report UX, real extension acquisition, configurable VIPs; acceptance: each claim has an automated or witnessed proof.

## CURRENT REALITY

SecureMail is an unverified local orchestration/dashboard prototype with persisted historical cases, not a demonstrated production mail-security system.

## WHAT IS SUBLIME

The only configured detection engine and source of parsed email model/authentication/hop input. SecureMail posts raw MIME to it; SecureMail currently discards MQL rule matches.

## WHAT IS SECUREMAIL

Ingress adapters, normalization, local heuristics, enrichment adapters, persistence, graph, evidence/scoring, hardcoded executive checks, policy/action records, dashboard, PDF, and demo extension.

## WHAT ACTUALLY WORKS

**RUNTIME:** source syntax checks pass and persisted JSON/SQLite state is readable. No service integration is verified. **CODE:** the local pipeline is wired end-to-end.

## WHAT IS BROKEN

Runtime stack unavailable; duplicate/race and IMAP acknowledgement defects; stuck dedup records; case-ID collision risk; unauthenticated control plane; incorrect historical remediation mutation; confidence/campaign inconsistencies.

## WHAT IS MOCKED

Default quarantine/restore, extension scan source, VIP registry, no-token Gmail verification, and any response action without configured live provider proof.

## WHAT IS UNVERIFIED

Sublime response compatibility, mail ingestion, all third-party enrichments, real Gmail action, dashboard/API/PDF runtime, and graph persistence under live processing.

## WHAT SHOULD BE FROZEN

The public-IP safeguards, unavailable-state behavior, infrastructure-location disclaimer, persistence baseline, and dashboard data-binding approach.

## WHAT MUST BE FIXED FIRST

Control-plane authentication and SMTP exposure; truthful remediation; transactional durable idempotency/recovery; live detection contract verification.

## WHAT SHOULD WE BUILD NEXT

Do not add features. Follow the seven milestones above: fix, verify, freeze, then improve.

## EVALUATOR'S VERDICT

Promising downstream forensic workflow, but current claims must be narrowed to a controlled prototype. It is not safe to present real-time detection, executive protection, mailbox quarantine, or active email scanning as proven.

AUDIT COMPLETE — NO CODE MODIFIED

SAFE TO CONTINUE DEVELOPMENT: **NO**

Blockers: no runtime verification; unauthenticated ingress/action control; remediation can falsely report success; duplicate/loss/stuck-message reliability defects.
