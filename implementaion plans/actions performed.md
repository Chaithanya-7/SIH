# PhishLens — Actions Performed

An accountability ledger. Every action is recorded here, whether it shipped,
was reverted, was abandoned, or turned out to be based on a wrong diagnosis.

## Why this exists, and how it differs from the other files

`implimented things.md` is a narrative of completed work. This is not that. This
records **actions**, including the ones that produced nothing, because a record
that only lists successes cannot be used to check anything — it has already
decided what mattered.

It exists to be read **instead of the conversation**. Anyone (including me, in a
later session) should be able to answer "what was done, did it work, and how do
we know" from this file alone, without scrolling back through a transcript.

## Format

Each entry carries:

| Field | Meaning |
|---|---|
| **Action** | A short name, so it can be referred to later |
| **What** | What was actually changed or attempted |
| **Status** | `Done` · `Reverted` · `Abandoned` · `Blocked` · `Not started` · `Superseded` |
| **Evidence** | How it was verified — measurements, test counts, or "unverified" said plainly |
| **Commit** | The hash, or `—` where nothing was committed |

**Status is written honestly.** `Done` means verified, not "finished typing".
An action based on a wrong diagnosis is recorded as such rather than deleted —
those are the most useful entries in the file, because they are the ones that
would otherwise be repeated.

---

## Where this stands — paused 2026-09-22

**Installed:** PhishLens **1.7.5**, running. Repository clean, everything pushed.
**Tests:** 317 backend · 33 desktop · 4 console · 0 failing · 0 skipped.
**User's data:** 0 cases. Every probe message created while verifying was removed.

### The one thing waiting on an answer

The Gmail reader fix (**A-035**) is **not yet confirmed against live Gmail**. The
cause found from outside was that the message id sits on a `<span>` inside the
row rather than on the row itself, and that is fixed and tested — but whether it
is *the* cause on the user's actual inbox is unknown.

**To resume:** the user reloads the extension (⟳ on `chrome://extensions`), opens
Gmail, waits about fifteen seconds, and opens the popup. It will say one of three
things, and they are now distinguishable:

| What the popup says | What it means | What to do |
|---|---|---|
| `N messages in view, M examined` | Working | Nothing — the channel is live |
| `N rows on the page, but none carried a message id` | The row selector is right, the identifier moved again | Widen `identify()` in `mail-providers.js` |
| `found no messages in the list` | The row selector itself no longer matches | Fix the selector in `listVisible()` |

Do not guess between these. The distinction exists precisely so it does not have
to be guessed, and it cost a wrong diagnosis to learn that.

### Monitoring channels

| Channel | State | What it still needs |
|---|---|---|
| Inline SMTP gateway | **ACTIVE**, 1 examined then cleared | Nothing — verified end to end (A-039) |
| Browser (webmail) | `NOT_CONFIGURED` | The reload above |
| IMAP poller | `DISABLED` | A Gmail App Password from the user, into `channels.json` |
| Gmail API | `NOT_CONFIGURED` | An OAuth client from the user's Google Cloud project |
| REST / webhook / file upload | `ACTIVE` | Nothing |

SMTP credentials live in `%APPDATA%\phishlens-desktop\data\channels.json`
(loopback only, generated for this machine, not an account credential).

### Things a later session should not re-learn

- The app window reports `document.hidden = true` with **zero** animation frames
  when driven over CDP. No CSS transition completes, so animated zoom looks
  frozen. This has produced a false "the map cannot zoom" diagnosis **twice**
  (A-022). Check `document.hidden` before believing any animation result.
- `node --check` does not catch an undefined function (A-032). The extension
  pages are now run in the test suite for this reason.
- Windows Defender deletes `phishlens-extension/tests/provider-fixture.html`
  (A-028). It is Gmail-shaped phishing markup. Restore from git; do not commit
  the deletion.
- Reading a field name off a status object without checking it has now caused
  three false conclusions (A-005, A-006, A-040).

### Larger items still open

| Item | Why |
|---|---|
| Live packet capture | Needs Npcap and administrator rights — the user's decision |
| Phase 6 live remediation | Needs a Google OAuth client and `REMEDIATION_MODE=live` |
| `dist`, `dist-171`, `dist-172`, `dist-173`, `dist-174` | Superseded build output; `dist-171` carries the console crash |
| Test-suite cross-file coupling | Six tests; an isolated-data-dir attempt was backed out rather than leave the suite red |
| Console vocabulary | Some pages still use analyst terms (Threat data, Linked attacks) |

---

## 2026-09-21

### Session: open-source security tooling

**A-001 · Survey open-source tools for fit**
What: Evaluated Wireshark, YARA, ClamAV, oletools against the standing
constraints (free, local, no dependency on anyone's servers).
Status: `Done`
Evidence: Established that Wireshark **cannot read mail** — every mail path worth
watching is TLS, and decrypting would mean intercepting the user's own browser.
Its real fit is the behavioural stage: whether the machine connected to a host
an email pointed at.
Commit: —

**A-002 · Detect installed security tools honestly**
What: Added `modules/securityTools.js`. Detects tshark, oletools, YARA, ClamAV
and reports **why** each is unavailable rather than a bare false.
Status: `Done`
Evidence: Checks real install locations, not only PATH — the Wireshark installer
leaves PATH untouched on Windows, so a PATH-only check calls a machine that has
Wireshark a machine that does not.
Commit: `cae1439`

**A-003 · Open attachments instead of only describing them**
What: Added `modules/attachmentInspector.js`. Attachments were hashed and named
and **never opened** (`analysis_status: METADATA_ONLY`).
Status: `Done`
Evidence: Verified against real fixtures — macro-bearing `.docm`, a
remote-template `.docx` carrying no macros, `invoice.pdf.exe`, a PDF with
`/OpenAction`. A clean `.docx` produced **zero** findings.
Commit: `cae1439`

**A-004 · Connection evidence via tshark**
What: Added `modules/connectionEvidence.js` for the behavioural stage.
Status: `Done (parsing)` · `Unverified (live capture)`
Evidence: Parsing and correlation tested as pure functions. **Live packet
capture was never run** — it needs the Npcap driver and administrator rights,
and installing a kernel driver was left as the user's decision. Not claimed to
work.
Commit: `cae1439`

**A-005 · Wrong probe for olevba version**
What: Probed `olevba --version` to detect oletools.
Status: `Reverted`
Evidence: olevba has **no** `--version` flag and exits 2 on it — which reads
exactly like the tool being absent. Replaced with an import plus packaging
metadata. Recorded because the mistake was assuming an interface instead of
measuring it.
Commit: `cae1439`

**A-006 · Wrong record match for olevba output**
What: Matched olevba's JSON on `type === 'file'`.
Status: `Reverted`
Evidence: olevba names that record after the **container** it opened (`Text`,
`OLE`, `OpenXML`), so the match found nothing and reported a malicious document
as unremarkable. Now matched on shape — the record carrying an `analysis` array.
Commit: `cae1439`

**A-007 · Stop git tracking the extension signing key**
What: `phishlens-extension.pem` was untracked but **not ignored**.
Status: `Done`
Evidence: A committed `.pem` is a key belonging to everyone who clones the
repository, and it signs updates browsers accept as genuine. Added with `.crx`
and generated report PDFs.
Commit: `cae1439`

**A-008 · Console panel for detection depth**
What: Added `DetectionDepth.jsx` under "Where mail arrives".
Status: `Superseded` — see A-020, which fixes a crash this introduced.
Evidence: Endpoint verified by curl against the running backend. **The component
itself was never rendered before shipping**, which is how A-020 happened.
Commit: `34c48b6`

**A-009 · Rule engine that needs nothing installed**
What: `yara-python` would not install (no wheel for Python 3.14; fell back to
compiling libyara from source). Wrote `modules/yaraEngine.js` — reads YARA
syntax, implements a documented subset.
Status: `Done`
Evidence: A rule using an unsupported construct is **refused by name**, never
silently skipped. Real YARA still preferred where installed.
Commit: `301adce`

**A-010 · Twelve detection rules**
What: Rules describing structure rather than vocabulary — HTML smuggling,
credential forms, SVG carrying script, paste-to-run, LNK running a shell,
encoded PowerShell, RTF remote objects, DDE, disk images, encrypted archives.
Status: `Done`
Evidence: Each matches its own fixture; **11 deliberately similar-but-benign
cases stay silent**, including a password form posting to a relative path and a
copy-to-clipboard button.
Commit: `301adce`, `ae6caa2`

**A-011 · Three rule-engine parser bugs**
What: (a) a brace inside `"{\rt"` ended the rule early, silently discarding six
document rules; (b) a quote inside `["']?` began a phantom string literal;
(c) sequential escape replacement turned `"{\\rt"` into `{\<CR>t`.
Status: `Done`
Evidence: All three compiled cleanly and matched nothing — the worst way for a
rule to fail. Caught by the tests, not by reading.
Commit: `301adce`

**A-012 · Removed a duplicate PDF rule**
What: Wrote `PDF_OpenAction_With_Embedded_JavaScript`, then deleted it.
Status: `Abandoned`
Evidence: The inspector's own PDF walk already reports `/OpenAction`,
`/JavaScript` and `/Launch` separately. Two findings for one fact is noise in a
report and a double count in any score built from it.
Commit: `301adce`

**A-013 · Attachment findings never reached the verdict**
What: `evidenceFusion` never read `threatObject.attachments`.
Status: `Done`
Evidence: **Found by running a phishing email through the installed application,
not the test suite.** A HIGH finding on an emailed credential-harvesting form
returned a verdict of `SAFE`. Every finding from A-003 and A-010 was being
produced and discarded.
Commit: `93a6eac`

**A-014 · Decisive findings**
What: Family caps stopped correlated facts compounding — and also capped the one
fact that mattered, leaving an emailed sign-in page at 0.28 against a 0.35
threshold. Eight rules with no innocent reading now declare themselves decisive.
Status: `Done`
Evidence: Now `HIGH_RISK` at 0.70 with SPF, DKIM and DMARC all passing. Ordinary
HTML attachment stays `SAFE` at 0.07. Four rules deliberately **not** decisive —
each has a legitimate use — and that list is asserted in both directions.
Commit: `93a6eac`

**A-015 · Packaging tests validated a stale build**
What: The desktop tests looked only in `dist/win-unpacked`.
Status: `Done`
Evidence: Windows held a lock on that folder, so builds went elsewhere and the
tests silently went on validating the old one — the exact failure they exist to
catch. Now follow the most recently written build.
Commit: `0f241c9`

**A-016 · README with architecture diagrams**
What: There was no README at all. Added one with two Mermaid diagrams (message
flow through seven ingestion channels; component architecture).
Status: `Done`
Evidence: Both diagrams **verified to parse with Mermaid's own parser**, not
assumed to render.
Commit: `5922ff8`

**A-017 · Deleted dist-170**
What: Removed the 1.7.0 build output (533 MB) carrying the SAFE-verdict bug.
Status: `Done`
Evidence: Confirmed git-ignored and nothing tracked before deleting.
Commit: —

### Session: reported faults — setup panel and map

**A-018 · Reproduced both reported faults**
What: User reported "setup monitoring not working" and "map not functioning".
Status: `Done`
Evidence: Driven over CDP against the installed app. `#root` had **zero
children** — the console was blank, so both reports were one crash.
Commit: —

**A-019 · Root cause: `api.get` does not exist**
What: `DetectionDepth` (A-008) called `api.get(...)`. `api` is a hand-written
object of named methods, not an axios instance.
Status: `Done`
Evidence: Threw during render; with no error boundary anywhere the whole React
tree unmounted. My own bug, shipped because I verified the *build* and the
*endpoint* but never the *component*.
Commit: `86aa2b6`

**A-020 · Error boundary**
What: Added `PanelBoundary.jsx` so one failing panel cannot blank the console.
Status: `Done`
Evidence: A blank window tells the reader nothing about what is still being
watched. The boundary reports to the console rather than swallowing.
Commit: `86aa2b6`

**A-021 · Map markers painted with nothing**
What: Markers draw to a canvas (`preferCanvas`), and colours came from a table
holding `var(--danger)`.
Status: `Done`
Evidence: Measured live — `fillStyle` stays `#000000` after assigning
`var(--danger)` and takes the resolved `#c02626`. **A canvas context cannot
resolve CSS custom properties.** Marker pixels 0 → 812, surviving a theme switch.
Commit: `86aa2b6`

**A-022 · False diagnosis: "the map cannot zoom"**
What: Clicking zoom-in 17 times moved nothing. Nearly reported as a bug.
Status: `Abandoned` — the diagnosis was wrong, no change made.
Evidence: The window reports `document.hidden = true` with **zero
requestAnimationFrame frames**, so no CSS transition can complete and animated
zoom cannot finish. Reaching the Leaflet instance and calling
`setZoom(n, {animate:false})` showed zoom works at every depth, including past
native zoom where it scales real imagery. **This same false diagnosis had
already been made once earlier in the project.**
Commit: —

**A-023 · Static checks over console source**
What: Four tests: every `api.*` method exists, no canvas path option takes a CSS
variable, every React hook is imported, the page switch is wrapped.
Status: `Done`
Evidence: Both proven to fail when the bug is put back. The canvas test had to be
**rewritten first** — the original looked for a literal `var(--` inside
`pathOptions` and passed happily when the colour arrived through a name holding
one, which is exactly how the bug was written.
Commit: `86aa2b6`

### Session: extension setup

**A-024 · "Pack extension" error**
What: User hit *"A private key for specified extension already exists"*.
Status: `Done`
Evidence: Wrong button — *Pack extension* is for Web Store publishing and fails
because `phishlens-extension.pem` exists from an earlier attempt. *Load
unpacked* is the only correct path; a packed `.crx` is a frozen snapshot and
would not pick up the key rewritten on every application start.
Commit: `8ed9a73` (panel now names the wrong button)

**A-025 · Popup said "Not configured" over a working extension**
What: `background.js` imports `provisioned.js` and uses the key correctly. The
popup and options page read `chrome.storage.local` **only**, which is empty on a
provisioned install.
Status: `Done`
Evidence: The examination path was never broken — verified by submitting a
message in exactly the shape `content-gmail.js` builds, with its `x-api-key`
header: HTTP 200, `HIGH_RISK` at 0.70, and `browser_watch` flipped to `ACTIVE`.
Values are deliberately **not** copied into storage, because storage is where a
person's own choice lives.
Commit: `de4585f`

**A-026 · The watcher could not be questioned**
What: User: "I don't think it is monitoring real sources of mail."
Status: `Done`
Evidence: The fault was that this **could not be answered**. The watcher failed
quietly by design, so "never ran", "ran and recognised nothing on the page" and
"ran with nothing new" all produced identical silence. Each sweep now reports
rows seen, rows examined and the last error, and the popup says it in words. No
message content is reported.
Commit: `2421c1a`

**A-027 · Webmail readers had a fixture and no runner**
What: `provider-fixture.html` existed in the extension folder with **nothing
executing it** — the checks existed only as something once done by hand.
Status: `Done`
Evidence: Nine tests against a real DOM via jsdom, proven to fail when the row
selector is renamed as if Gmail had changed it (`pass 6, fail 3`). jsdom added as
a devDependency; the packaging test confirms it does not reach the installer.
Commit: `2421c1a`

**A-028 · Windows Defender deleted a repository file**
What: `phishlens-extension/tests/provider-fixture.html` vanished and appeared
staged as a deletion.
Status: `Done`
Evidence: The file is Gmail-shaped markup advertising a suspended PayPal
account — indistinguishable from a real phishing page. Restored from git and
confirmed not re-quarantined. **Not committed as a deletion.**
Commit: —

**A-029 · Live Gmail markup still unverified**
What: Whether the Gmail reader matches Gmail's *current* class names.
Status: `Blocked`
Evidence: Cannot be checked without the user's signed-in session, which will not
be used. The reader is correct against Gmail-shaped markup (A-027); whether
Gmail still looks like that is what the sweep report (A-026) exists to reveal.
Commit: —

**A-032 · Shipped a ReferenceError to the user's browser**
What: A-026 added a call to `showWatchState()` and **never added the function**.
Status: `Done` (fixed)
Evidence: An edit script hit an assertion and died part-way; the call landed, the
definition did not. I fixed the HTML half and moved on without re-running the
JavaScript half. `node --check` passed, because an undefined function is not a
syntax error — it is a ReferenceError at the moment the line runs. The user saw
the popup stuck on "Connecting…" and a red **Errors** badge. **Caught by the
user, not by me**, which is the point of recording it.
Commit: `2421c1a` introduced it

**A-033 · Run the extension's pages in a test**
What: Added `tests/extensionPages.test.js` — loads the real popup and options
HTML with every script it references, extension APIs stubbed, and fails if the
page throws while opening.
Status: `Done`
Evidence: Proven to fail when the `showWatchState` definition is removed again,
reproducing A-032 exactly. Also checks that every element the popup looks up
exists in its HTML, since `getElementById` returns null silently. Two harness
bugs of my own on the way: separate `eval` calls do not share a lexical scope the
way `<script>` tags do, and a heredoc ate a newline escape.
Commit: (this commit)

**A-034 · Removed the MV2 key Chrome rejects**
What: `background.scripts` sat beside `service_worker` for Firefox.
Status: `Done`
Evidence: Chrome lists it on the extension's error page under MV3. A red
"Errors" badge on a security tool reads as the tool being broken. Firefox
support was aspirational and never tested, so the browser actually in use wins.
Commit: (this commit)

**A-035 · A full inbox reported as an empty list**
What: The Gmail reader looked for the message id **only on the row element**.
Gmail carries it on a `<span>` inside the row, so every row was found and then
silently dropped for having no id.
Status: `Done` — cause fixed; **not yet confirmed against the user's live Gmail**
Evidence: Found by the diagnostic added in A-026, which reported "Running on
mail.google.com but found no messages in the list". `identify()` now searches
the row, its descendants, and the row's own `id` attribute, stripping the
`thread-f:` prefix. Tested against the real Gmail shape.
Commit: (this commit)

**A-036 · Two different faults looked identical**
What: "No rows on the page" and "rows found, none identifiable" both reported as
`rowsSeen: 0`.
Status: `Done`
Evidence: Added `countRows()` so rows-on-page and rows-identified are reported
separately, and the popup now says which of the two happened. The first means
the selectors are wrong; the second means the identifier moved. Diagnosing A-035
would have been immediate with this.
Commit: (this commit)

**A-037 · Switch monitoring channels on without touching the system**
What: The channels are enabled by environment variables, and for an installed
application the only way to set those was the Windows user environment.
Status: `Done`
Evidence: Writing a password into the registry for every process the user runs,
permanently, was the wrong shape — and was refused by a guardrail, correctly.
The supervisor now reads `channels.json` from the application's own data folder,
beside the API key and secret key already there. Absent, unreadable or malformed
means every channel stays **off**: a channel that cannot read its settings must
not come up half-configured and report itself as watching. SMTP will not start
without a credential, so it cannot become an open relay, and binds to loopback
unless deliberately changed. Five tests, including one asserting the settings are
spread where they cannot override the port, the API key or the data directory.
Commit: (this commit)

**A-038 · Enabled the SMTP gateway locally**
What: Generated a credential and switched the inline SMTP gateway on.
Status: `Done`
Evidence: The credential is generated for this machine and guards a listener on
127.0.0.1:2525 — it is not an account credential. This is the one channel of the
four that could be switched on from here; the other three need something only
the user has (a routed domain, a Gmail App Password, a Google Cloud project).
Commit: (this commit)

**A-039 · SMTP gateway verified end to end**
What: Sent a phishing message through the enabled gateway.
Status: `Done`
Evidence: Accepted (`250 OK: message queued`), examined, `HIGH_RISK` at 0.70,
source recorded as `SMTP_GATEWAY`, attachment finding
`RULE_HTML_CREDENTIAL_FORM_POSTING_OFFSITE`, and `messages_ingested` advanced to
1. This is the only channel that sees a message before it reaches a mailbox.
Commit: (this commit)

**A-040 · False alarm: "the examined counter is stuck at 0"**
What: Reported the channel counter as broken after it showed 0 following a
successful examination.
Status: `Abandoned` — the diagnosis was wrong, no change made.
Evidence: My probe read `messages_examined`; the field is `messages_ingested`,
and it was correctly 1. The console already reads the right field. Recorded
because it is the same mistake as A-005 and A-006 — assuming a name instead of
reading it — and this time I nearly reported it to the user as a defect.
Commit: (this commit)

### Releases

| Version | Carried | Status |
|---|---|---|
| 1.7.0 | Attachment inspection, rules | `Superseded` — verdict bug (A-013); build output deleted (A-017) |
| 1.7.1 | Verdict fix | `Superseded` — console crash (A-019) |
| 1.7.2 | Console and map fixes | `Superseded` — step-count copy bug |
| 1.7.3 | Step-count fix | `Superseded` — no Pack-extension warning |
| 1.7.4 | Pack-extension warning | **Installed** |

### Housekeeping

**A-030 · Removed test data from the user's install**
What: Cleared probe cases created while verifying, each time.
Status: `Done`
Evidence: All used `.example` domains (reserved for documentation). Backup at
`AppData\Roaming\phishlens-desktop\data-backup-before-probe-cleanup`. Final
state: 0 cases, summary reports 0 analysed.
Commit: —

**A-031 · Installed oletools on the user's machine**
What: `pip install oletools` (BSD-2, local, reversible with `pip uninstall`).
Status: `Done`
Evidence: Disclosed. Enabled end-to-end verification of the macro path rather
than shipping it untested. Wireshark was **not** installed — it needs a kernel
driver and administrator rights, which was left as the user's decision.
Commit: —

---

## Open items

| Item | Why it is open |
|---|---|
| Live packet capture (A-004) | Needs Npcap and administrator rights — the user's decision |
| Live Gmail markup (A-029) | Needs a signed-in session, which will not be used |
| Phase 6 live remediation | Needs a Google OAuth client and `REMEDIATION_MODE=live` |
| `dist`, `dist-171`, `dist-172` | 3.6 GB of superseded build output; `dist-171` carries the console crash |
| Test-suite cross-file coupling | Six tests; an isolated-data-dir attempt was backed out rather than leave the suite red |
