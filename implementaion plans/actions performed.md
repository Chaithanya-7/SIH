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

**Installed:** PhishLens **1.7.10**, running. Repository clean, everything pushed.
**Tests:** 323 backend · 33 desktop · 4 console · 0 failing · 0 skipped.
**User's data:** 0 cases. Every probe message created while verifying was removed.

**Map, as of 1.7.8:** country view ~1290 ms and street level ~1685 ms, against
~2350 ms for both this morning. Nowhere on earth draws a blank tile. The caption
states when the photography under the view was taken. Roads load from zoom 9;
an OpenStreetMap layer sits beneath the imagery, capped at zoom 12, and Esri
"no data" tiles are made transparent so it shows through. The map stops one level
past real detail and says so when magnified; street-level 3D was evaluated and
not built (A-058), and detectRetina was tried and reverted (A-059).

### The one thing waiting on an answer

**Nothing is reaching the backend from the browser.** `browser_watch` reads
**0 examined and 0 failures** — and zero *failures* is the informative half: a
watcher that was submitting and being rejected would show failures. Nothing is
being submitted at all.

Ruled out from this side (A-071): the backend answers, the provisioned key
authenticates, the content script loads cleanly when run the way Chrome loads
it, and the service worker evaluates with all six listeners registered. The code
is fine; something in the browser is not running it. Chrome cannot be inspected
from here — no browser is connected to this session.

**To resume:** the user reloads the extension, opens Gmail, and reads the top
line of the popup. It now names which case applies rather than saying only that
nothing has happened:

| What the popup says | What it means | What to do |
|---|---|---|
| `missing the permission it needs to watch tabs` | `scripting`/`tabs` were not granted | Reload on chrome://extensions and approve |
| `No Gmail or Outlook Web tab is open` | Nothing to watch | Open mail, press ⟳ |
| `N mail tabs are open but not being watched yet` | **The likely one.** A tab open before the reload has no content script | Press ⟳, or reload the mail tab |
| `Watching N mail tabs; nothing examined yet` | Live, nothing new found | Nothing |
| `N messages in view, M examined` | Working | Nothing |
| `N rows on the page, but none carried a message id` | The identifier moved again | Widen `identify()` |
| `found no messages in the list` | The row selector no longer matches | Fix `listVisible()` |
| `PhishLens returned NNN: <reason>` | The backend rejected it, and says why | Fix what it names |

Do not guess between these. The distinction exists precisely so it does not have
to be guessed, and it has already cost two wrong diagnoses.

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

## 2026-09-22 — map accuracy and speed (PAUSED MID-EXPERIMENT)

**A-046 · How old the map actually is**
What: Queried Esri's World Imagery metadata service for per-tile capture dates,
rather than repeating a general claim about satellite imagery.
Status: `Done`
Evidence: Esri publishes capture date, resolution and positional accuracy per
tile. For Hyderabad: captured **15 Nov 2025**, **0.46 m/pixel**, positional
accuracy **8.47 m**, sensor GeoEye-1, product "Vivid Advanced", released in
"Raster Basemaps 2026.R06". Other samples: Delhi 23 Oct 2025, rural Rajasthan
8 Dec 2025, London 6 Aug 2025, New York 14 Mar 2024. Indian coverage is roughly
**9–11 months old**; the United States sample was **2.5 years** old. The
OpenStreetMap layers are a different thing entirely — vector data edited
continuously, so minutes to days old, not years.
Commit: —

**A-047 · Why zooming takes seconds — measured**
What: Instrumented the application's own network stack during one zoom step.
Status: `Done`
Evidence: One zoom to level 13 costs **72 tile requests**, every one to
`server.arcgisonline.com`, over **HTTP/1.1**, median **800 ms**, slowest
1746 ms. The satellite view is three layers — imagery plus two Esri reference
overlays — and all three are served from the same host, so they compete for the
same per-host connection budget of about six.
Commit: —

**A-048 · Nearly trusted curl about HTTP/2**
What: Concluded from curl that every tile host was HTTP/1.1.
Status: `Abandoned` — the reading was an artefact.
Evidence: The local curl has **no HTTP/2 support compiled in**, so it reports
1.1 for everything. Chromium confirmed HTTP/1.1 independently, so the
conclusion happened to hold — but it was not evidence when it was first used.
Fourth instance of trusting a tool's answer without checking the tool.
Commit: —

**A-049 · Esri host sharding — measured, did not help, reverted**
What: Spread the 72 requests over `server`, `services` and `server2`
.arcgisonline.com, which return byte-identical tiles (verified by hash).
Status: `Reverted` — **the theory was wrong**
Evidence: Measured properly on a fixed location with the cache disabled: single
host **2430/2287/2414/2144 ms**, three hosts **3440/2332/2704/2166 ms**.
Sharding is **not faster** and is slightly slower — Chromium pools connections
well, and three cold hosts cost three TLS handshakes rather than saving
queueing. Three measurement mistakes on the way, each of which produced a
plausible wrong answer: per-request medians were compared first, and they can
move opposite to the total; a warm cache produced a run of zero requests that
read as an instant map; and a randomised location changed the tile count
between runs (72, then 45, then 60), making two configurations incomparable.

Also found while doing it: Leaflet splits a **string** `subdomains` option into
single characters, so `'server,services'` becomes `['s','e','r',…]` and every
tile URL names a host that does not exist. It must be an array.

This ruled out the theory but not the problem, which is the request count
itself. See A-050.
Commit: —

---

**A-050 · The request count is the whole cost**
What: Measured the wait against the number of tile layers, holding location and
cache constant.
Status: `Done`
Evidence: The wait is very nearly linear in the request count — about 30 ms per
tile. Imagery alone: **24 requests, ~840 ms**. Imagery and place names: **48
requests, ~1440 ms**. All three layers: **72 requests, ~2350 ms**. The satellite
view is three stacked layers, so every zoom pays three times over.
Commit: (this commit)

**A-051 · Roads only where a street can be read**
What: The `World_Transportation` overlay now loads from zoom 9 rather than
always.
Status: `Done`
Evidence: Street geometry across a whole country is a grey haze that says
nothing, and it costs 900 ms of the 2350. Measured after: country view (zoom 6)
**~1276 ms, 48 requests** — down from ~2350 ms, a **46%** reduction at the zoom
levels a world threat map spends most of its time at. Street level (zoom 13) is
unchanged at 72 requests with roads present, confirmed by counting tiles per
service. Place names stay at every zoom: they are what makes photography
legible at all.
Commit: (this commit)

**A-079 - The mail list rebuilt as a packet analyser, and a self-inflicted wound**
What: Answered the geolocation question, then rebuilt "All emails" as a
Wireshark-style flow list with a real display-filter language.
Status: `Done` - 394 backend + 20 console + 37 desktop tests passing
Evidence:

**Geolocation, answered by reading the code.** TShark provides *no* geolocation
here - verified, no geo reference in `connectionEvidence.js` or
`networkObserver.js`. Wireshark can do MaxMind lookups; PhishLens does not use
it that way and does not need to. Geolocation comes from `geoIntelAdapter.js`
(ipwho.is, free): country, country_code, region, city, latitude, longitude, ASN,
ISP, organization. So the capability exists and nothing needed adding. Two
honest gaps recorded rather than papered over: **no accuracy radius** (ipwho.is
does not return one) and **it is a remote call**, so each address is sent to a
third party - which sits awkwardly with the local-only constraint. A
downloadable local database would fix both; not done unasked, since it means a
new ~60 MB data file and an attribution obligation.

**The flow list.** New `mailTransportFlow.js` projects each case into a
transport row at *read time* via `GET /api/flow`, so every case ever stored gets
the view with no migration. New `MailFlowList.jsx` replaces `ThreatFeed.jsx`
(deleted; nothing else imported it). Columns in the order asked for: **No.**
carrying the coloured ball (red / yellow / green from the verdict), Time, Email,
Source, S.Port, Destination, D.Port, Protocol, Len, **Info** last - which is also
where Wireshark puts it. Selecting a row expands the hop chain beneath, the way
Wireshark expands a frame into layers.

The layout had to change: `investigations` was a `320px 1fr` grid, and a
ten-column table of addresses and ports cannot live in 320px. Now list above,
detail below - which is Wireshark's own arrangement.

**The honesty problem this shape creates.** A packet list implies every column
was observed. A `Received:` header is free text and the great majority never
record a port. So every field resolves to a real value or to null, null renders
as a dash, and `column_provenance` travels with the payload so the UI can say
which columns are legitimately empty and why. Filling the port column for every
row would have been trivial and would have looked far more complete - and
somebody would have quoted a number that was never real.

**The display filter**, `displayFilter.js`, modelled on Wireshark's: `field op
value`, `&&`/`||`/`!`, brackets, `contains`, `matches` for regex, and a bare
field name meaning "present". Bar is green when valid, red when not, with the
reason and character position beneath it. **It never fails open** - the test
suite pins that down, because a typo like `verdict == HIGH_RSK` quietly matching
nothing would render an empty list that reads as "no dangerous mail".

Its own test caught a real bug: `Number(null)` is `0`, and `0` is finite, so the
`Number.isFinite` guard let a missing port straight through and `sport < 1024`
was true for every message that never recorded one. Emptiness is now checked
before coercion.

**A self-inflicted wound, recorded because it reached a commit.** While
verifying the installed package I ran `npx asar extract-file ... package.json`
from the desktop directory. `extract-file` writes to the current directory, so it
**overwrote the repo's `package.json` with the trimmed copy from inside the
asar** - losing `build`, `scripts`, `dependencies`, everything. I then committed
it in `dd1744a` without re-running the desktop suite. Restored from `c524655`
with the version bump re-applied.

Two things worth keeping from it: the packaging test *did* catch it (three
failures the moment it ran), and `npm test` produced no output at all beforehand
because npm itself could not parse the manifest - which I read as an empty result
rather than as the signal it was. The installer was built before the clobber, so
the install is unaffected.

**Not yet visible to the user:** the flow view is in the console bundle, and the
installed 1.7.11 carries the bundle built before it existed. It needs another
build and install to appear.
Commit: (this commit)


**A-078 - 1.7.11 built and installed**
What: Version bump, console build, NSIS installer, install, and verification of
the installed artefact.
Status: `Done` - **1.7.11 installed and running**; 381 backend + 37 desktop + 5
console tests passing
Evidence: Built to `dist-1711` (never `dist`, which stays locked). Installer
`PhishLens Setup 1.7.11.exe`, 124,968,274 bytes. "building block map" was the
final log line, as it always is.

Checked before the install rather than trusting it: all 15 backend runtime
dependencies present in `build-staging/backend-deps`, no major-version drift,
and no dev-only package (`nodemon`, `pdf-parse`, `qrcode`, `jsdom`) leaked in.
The staging's mtime was *older* than `package-lock.json`, which looked stale -
checking the dependency list directly showed nothing was actually missing, so
the lockfile had been touched without a dependency change.

Verified in the **installed** copy, not the build output: seven new backend
modules present, the console bundle is the one just built (hashes match), and
`threatNotifier.js` inside `app.asar`. In the packaged extension: the backlog
UI, `examineHistorical`, `BACKLOG_PACE_MS`, `pageHash`, `startBacklogScan`. In
the console bundle: "What was checked", "Does not rule out", "This machine
connected here", "Uniform 2024", "Analysed after the fact".

Registry reads `PhishLens 1.7.11`; the backend answers `OPERATIONAL` on 3001,
running inside `PhishLens.exe` as packaged Node rather than a separate process.

**A fault the whole test suite would have missed.** Poking the running install,
`/api/cases` returned **401** to the machine API key - which would have meant
the notifier polls, is refused, logs once, and never raises a single
notification. Silent, permanent, in a log nobody reads.

Reasoning was not enough to settle it: the supervisor hands the same `apiKey`
field to the backend's environment and to the notifier, so on paper they cannot
differ. New `tests/notifierAccess.test.js` starts a real backend with a known
`PHISHLENS_API_KEY`, in its own temporary data directory, and makes exactly the
call the notifier makes. **200, with a case list** - the access path is sound. A
wrong key is still refused, so the endpoint is not open.

The external 401 therefore means the key *file* probed is not the one the running
app loaded; the notifier never reads that file, so it is unaffected. Recorded
honestly: the mechanism is proven, a live notification has **not** been seen
fire.

The same test also covers a trap found by reading: `requireAuth` gives a
service-key request the synthetic identity `{ organization_id: 'org_dev' }`, and
`/api/cases` filters by organisation - so the notifier could authenticate
perfectly and be handed an empty list forever. The filter lets a case with no
organisation through, which is what a single-user desktop install produces.

Superseded build output still on disk: `dist` (2.59 GB) plus `dist-171`
through `dist-1711` (0.52 GB each) - about 7.7 GB. Not deleted without asking.
Commit: (this commit)


**A-077 - Proof behind a clean verdict, notification on this machine, and the truth about map recency**
What: Addressed the restated objective in three parts.
Status: `Done` - 379 backend + 37 desktop + 5 console tests passing
Evidence:

**1. A clean verdict had nothing behind it.** Measured: a message with SPF,
DKIM and DMARC all passing produced *verdict SAFE, evidence items 0,
contributions 0*. A green label with literally nothing to read, which is
indistinguishable from an analysis that fell over - and the reassuring reading
is the more common one. New `assuranceEvidence.js` records ten checks with, for
each, what it concluded and **what passing it does not rule out**. A clean
message now shows nine substantiated checks.

**It must never reduce a threat score**, and several tests exist only to hold
that line. This system already detects phishing sent through real platforms and
compromised accounts - all of which passes every authentication check because
nothing about it is forged. Netting assurance off against suspicion would mean
the better an attacker's infrastructure, the safer their mail looked. It runs
*after* `confidenceEngine.calculate`, touches neither `confidence` nor
`detection`, and a test asserts the pipeline order.

A check that did not run is never reported as one that passed. The feed check
says so explicitly - an empty match list from feeds never loaded looks identical
to one from feeds that were.

**2. Notification was webhook-only.** `SOC_WEBHOOK_URL` is right for a security
team and does nothing for somebody watching their own mail on their own laptop -
a verdict reached them only if they went and looked. New
`phishlens-desktop/threatNotifier.js`: native OS notification on HIGH_RISK and
SUSPICIOUS, clicking one focuses the window and opens the case through the
`phishlens:navigate` route the deep-link handler already had. Never says a
message is safe (that would train trust in the absence of one, which also
happens when the backend is down); never shows body text (a notification is
rendered by the OS and can appear on a lock screen); never fires for historical
cases, and summarises a burst rather than firing individually - a mailbox scan
would otherwise produce hundreds of toasts about mail from years ago and get
notifications switched off entirely.

The desktop packaging test caught that `threatNotifier.js` was absent from
`build.files`, which would have shipped an installer that died on launch.

**3. Map recency - measured, and the answer is not what was asked for.**
Followed the Esri Clarity endpoint, found it redirects to Esri **Wayback**
(versioned imagery releases), fetched Esri's release config (196 releases; the
keys are *not* date-ordered - 64776 is 2023, 64001 is 2026) and found the newest
release: **26334, dated 2026-08-05**.

Then compared four tiles from that newest release against the standard World
Imagery layer already in use: **byte-identical, all four.** The map already
serves the newest photography Esri publishes. Wayback also measured **~1600 ms
against ~450-720 ms** for the same twelve tiles across three runs - 3x slower
for identical pixels, because of a 301 per tile. Not adopted.

So the honest improvements were different from the request:
- Added **Sentinel-2 cloudless 2024** (EOX, free) as a basemap. Not sharper -
  10 m/px, stops at zoom 14, no buildings - but *uniformly* recent everywhere.
  Where Esri's mosaic has nothing newer than 2012 (parts of Siberia), this is
  genuinely the more current picture.
- **Split the caption.** Streets, boundaries and place names are vector data and
  are current (OSM edits appear within days). Photography is whenever it was
  last flown. One caption was blurring the two, so "recent" could not be
  correctly attributed to either half.
Commit: (this commit)


**A-076 - Wireshark network intelligence, wired in at last**
What: Made the TShark capability actually run, and reach a verdict.
Status: `Done` - 368 backend + 5 console + 33 desktop tests passing
Evidence: **Most of the requested spec already existed.** Inspected first, as
the spec itself required. Already present: TShark backend with no GUI
(`connectionEvidence.js` - dst address, ports, TLS SNI, DNS question, protocol,
timing), GeoIP with lat/long/ASN/org/city/region (`geoIntelAdapter.js`, ipwho.is,
free), IP extraction, relay/protocol forensics, private/reserved/loopback/IPv6
handling (`ipClassifier.js`), the world map fed from `infrastructure.geo_points`,
severity colours, reports, notifications, campaign analysis.

**The real gap: `connectionEvidence.js` was dead code.** It was `require`d in
server.js solely to answer `availability()` for the tools panel. It never ran on
a message. A well-written packet-analysis module that had never analysed
anything.

**And it could not simply be called.** `capture()` is a bounded one-shot, and
the ordering defeats it: a case is scored *as the message arrives*, before
anybody has read it, so at that instant no link has been clicked. Correlating at
analysis time finds nothing, every time - it would have shipped as a feature
incapable of firing once. The useful question is asked minutes later: *did this
machine go there after the warning?*

So three new modules:
- **`networkObserver.js`** - a long-running TShark process, line-buffered (`-l`,
  without which output blocks up and the observer looks alive holding nothing),
  streamed into a rolling memory bounded by age *and* count. Reuses
  `connectionEvidence.parseFields` and its capture filter, so one place knows
  what the fields mean and the narrow field set is enforced rather than intended.
- **`connectionWatchlist.js`** - the cases waiting for an answer. **Only
  HIGH_RISK and SUSPICIOUS, and only the hosts those messages named.** That
  limit is the difference between a security tool and surveillance: enrolling
  everything would mean holding every destination every message ever mentioned
  and matching it against everywhere the machine goes, for no benefit.
- **`connectionFollowUp.js`** - sweeps one against the other, and on a match
  reopens the case: evidence appended, destination geolocated onto the existing
  map as role `CONTACTED`, re-fused, re-scored, audit entry written. Same case
  id - one incident learning something new, not a second case.

New `CONNECTION` family at cap 0.35 with the strongest, and the finding marked
decisive. No MQL rule was written for it: the observation already enters through
fusion, and a rule asserting the same fact would be one event counted twice.

An ordering bug caught while wiring: I first set `connection_evidence` *after*
`caseManager.saveCase()`, so the stored case would not have carried it. But
enrolling before the save risks keying the watchlist to a case id `saveCase`
reassigns on collision. Split `decide()` from `enrol()`: decide and record
before the write, enrol with the id that survived. Guarded by a test asserting
the order.

Three honesty properties, each with a test:
1. **Watching and seeing nothing produces no evidence at all.** Not even a weak
   positive. A link opened on a phone, a DNS-over-HTTPS resolver, a VPN and
   nobody clicking produce identical silence; "we watched and saw nothing" would
   read as exoneration.
2. **A window nobody watched is recorded as a gap**, at LOW/0.1 - present in the
   evidence because a gap belongs there, weighted at nearly nothing because not
   knowing is no reason to raise a verdict.
3. **It never claims to identify a person.** The capture observes the machine,
   not a browser or an account, and the case says so in its own text.

Not done, stated rather than faked: **accuracy radius is not captured** -
ipwho.is does not return one, and inventing a number for a field called
"accuracy" would be worse than leaving it out. Observation is **off by default**
(`ENABLE_NETWORK_OBSERVER=true`): capturing needs a driver and administrator
rights, and a tool that silently began recording every destination a machine
contacts because it was installed would be doing something nobody asked for.
Commit: (this commit)


**A-075 - Making the honesty visible, and attributing techniques properly**
What: Surfaced historical-scan caveats in the console and the forensic report,
and gave every rule an explicit MITRE technique list.
Status: `Done` - 349 backend + 5 console tests passing, console builds
Evidence: **A correction to A-074 first.** I told the user the console "renders
it differently" for a backlog case. It did not. `analysis_mode` existed on the
ThreatObject and *nothing* read it - not the console, not the forensic PDF. So a
historical SAFE, resting on five fewer checks, looked identical to a live one.
The backend refusing to score a check it could not honestly perform is only half
the job; rendering the result the same way throws that half away at the last
step. New `AnalysisModeNotice.jsx` (badge beside the verdict, full notice
**above** the confidence card - a qualification printed after the score is read
after the score is believed) and `renderAnalysisMode()` in the report, placed
before the disposition for the same reason.

The new detection facts needed no new UI: the rules' `matched_because` strings
already carry the phone number, the character counts and the platform name, and
those flow into the evidence list through the existing path.

**A second correction.** I told the user 26 of 43 rules lacked the `mitre` field
so the report "under-reports". Partly wrong: `mitreFromSource()` already parsed
technique IDs out of the prose citation, so rules whose source named a T-number
were attributed fine. The real gap was ~23 rules whose citation named only
APWG/CISA/RFC/abuse.ch - those had *no* attribution at all. All 51 rules now
declare techniques explicitly; 21 distinct techniques cited, and four names
added to `TECHNIQUE_NAMES` so none renders as a bare number.

**Then a test caught me over-claiming.** Giving all 27 rules techniques in one
pass broke "a clean message attributes no techniques at all" - a colleague
sending a BBC link now attributed T1566, because I had given *Missing
Message-ID* the Phishing technique. The rule's own description concedes
misconfigured legitimate senders omit it. Three rules had their attribution
removed and now deliberately carry none: `MQL-AUTH-103` (missing Message-ID),
`MQL-URL-104` (many links in a short message - newsletters do this),
`MQL-ATT-104` (archive attachment - an archive is not obfuscation).

Principle written into the module and guarded by a test: **attribute a technique
where the rule observes the technique being performed, not where it observes
something that often accompanies it.** An attribution hung on a weak correlate
turns "MITRE ATT&CK T1566" into decoration, and decoration on a security report
is worse than silence.

**A latent bug in the console test suite**, found because my component tripped
it: `every React hook a component uses is imported` matched only
`^import React[^;]*;`. A file using `import { useState } from 'react'` - valid
under the modern JSX transform - was reported broken, and worse, a hook
genuinely missing from such a file could never have been caught, because the
line being searched came back empty. Widened to all react imports and verified
by removing a real import and watching it fail.
Commit: (this commit)


**A-074 - Scanning the mail that was already there**
What: The backlog scanner, plus the historical-analysis mode that makes its
verdicts honest.
Status: `Done` - 347 backend + 33 desktop tests passing
Evidence: The scanner itself is the small half. Fetching a message by its id
never needed the row on screen, so the work was paging the list to collect ids
(`provider.pageHash()`, Gmail's `#inbox/p2` fragment), pacing, resume, and a
tab of its own so it does not yank the page out from under someone reading.

The larger half was that **running old mail through the live pipeline is
wrong**, and in one place actively harmful. New `historicalMode.js`:

1. **The DKIM trap.** PhishLens re-verifies DKIM itself and the key comes from
   DNS at check time. Domains rotate selectors as routine maintenance, so an old
   message often names one that is gone: the header says `dkim=pass`, live
   verification finds nothing, and the disagreement fires **MQL-AUTH-102 at
   CRITICAL / 0.85** - a rule written for headers forged to mislead filters. A
   retired key is not a forged header. Untreated this would have flagged a large
   share of ordinary old mail, and a scan that cries wolf across two thousand
   messages gets switched off and buries the real findings with it. Suppressed
   only for the exact shape (`claimed pass` + `none/unknown/temperror`); a
   signature that actively *fails* against a key still published survives,
   because age does not explain that.
2. **Live enrichment is not run at all.** Domain age inverts outright - a domain
   three days old when it attacked you is two years old now, so the signal that
   would have caught it is the one that cannot fire. Feeds have delisted what
   was listed. Addresses have changed hands. Marked `NOT_APPLICABLE_HISTORICAL`
   with a reason each, rather than run and recorded as finding nothing.
3. **Remediation suppressed.** The decision is computed and recorded so a case
   says what *would* have happened; nothing is done to a mailbox for mail
   somebody dealt with two years ago.
4. **Adaptive learning gated off**, so the model does not learn from a
   mailbox-sized batch of reduced-evidence verdicts. The behavioural baseline
   deliberately still runs - recording what a sender's mail looks like is
   exactly what history is good for, and it is why the scan goes oldest first.

Verified rather than assumed: **SPF and DMARC need no special handling.**
`authAnalyzer` already takes them from the receiving server's
Authentication-Results header because it cannot re-derive SPF after delivery
without the live connecting IP. That header was written at delivery, which makes
it *more* authoritative for old mail, not less.

The asymmetry is stated on every backlog case: a HIGH_RISK means what it always
means, because every decisive finding is time-independent; a SAFE rests on less
than a live one, and says so.

Refusals recorded rather than papered over: `pageHash` is implemented for Gmail
only. Outlook pages differently, and a guess would be the worst outcome - the
scan would re-read page one and report a whole mailbox examined. The scanner
checks for the function and refuses out loud.
Commit: (this commit)


**A-073 - Detection for the four attacks that leave nothing to detect**
What: Researched current phishing tradecraft, compared it against the 43 MQL
rules, and built detection for the gaps found. Nine new rules, two new modules,
two extended modules, two new evidence families.
Status: `Done` - 338 backend tests passing, up from 323
Evidence: The gaps were found by research rather than guessed:

- **Callback phishing (TOAD).** Email whose only payload is a phone number. No
  link, no attachment, and it usually passes SPF and DMARC because it is sent
  from a real account. Zero prior coverage - there is nothing for a gateway to
  inspect, which is the design. New `payloadChannel.js` + MQL-TOAD-101/102.
- **Text-in-image bodies.** The most prevalent body-obfuscation technique
  measured in the literature (47.0%, arXiv 2506.20228) and one of two measured
  as significantly evading antispam. Every text-reading check here scored it at
  zero. Detected by ratio, not by reading the image - OCR would mean a new
  dependency and a new class of wrong answer. MQL-IMG-101/102.
- **Authentication-passing platform abuse (LOTS).** Real Dropbox, DocuSign,
  SharePoint and form-builder links. The AUTHENTICATION family is capped 0.30
  and contributes *nothing* to these, correctly, because nothing about the
  delivery is forged. New `trustedServiceAbuse.js` + MQL-LOTS-101/102/103.
  MQL-LOTS-101 (credentials via a public form builder) is decisive.
- **CSS-hidden bulk text.** Distinct from the zero-width characters already
  covered: this hides whole paragraphs from the reader to move a classifier.
  Extended `textDeception.js` + MQL-DECEPT-105.
- **SVG attachments.** Roughly fiftyfold growth into the third most common
  malicious attachment type, often declared `text/plain` to route around
  scanning. Extended `attachmentInspector.js` with six findings.

Two defects found while wiring it:

1. **`MQL_AUTHFLOW` was never mapped to a family.** The rules carried a comment
   placing them in URL_RISK; `confidenceEngine.evidenceFamily()` had no case for
   them, so they fell through to the default and formed a family of their own -
   counting as independent of the URL findings they are not independent of.
   Fixed, with `MQL_QR` mapped the same way and `MQL_THREAD`/`MQL_ARC` declared
   explicitly rather than left to the fallthrough.
2. **`prose()` in payloadChannel.** A mail parser handed HTML with no text part
   generates one, and for an image-only message it is almost entirely the URLs
   written out in full. Measuring that as readable content inverts the answer:
   the emptier the message, the longer its addresses loom. A single CDN URL
   carried a wordless body over the threshold by one character. Found by my own
   test, not by reading the code.

Two judgements recorded rather than made silently:

- **Only `SVG_EVENT_HANDLER` was made decisive**, not `SVG_SCRIPT_ELEMENT`.
  Carrying code is not the act of running it unprompted, an interactive graphic
  sent as mail is rare but real, and the existing YARA rule already treats
  script-in-SVG as non-decisive. One fact judged two ways by two parts of one
  system is worse than a signal weighed slightly low. The decisive-list guard
  test caught the drift and was updated with that reasoning.
- **PAYLOAD_CHANNEL and TRUSTED_SERVICE capped at 0.30, not 0.35.** Both reason
  from shape rather than hard fact - a message can legitimately be a picture,
  and a real brand can legitimately use a bulk sender. Neither should reach a
  verdict wholly alone; the one case that must (form-builder credentials) is
  decisive and reaches 0.70 through the visible floor instead.

Half the new tests assert the detection does **not** fire: a phone number in a
signature, an image-led newsletter with real text, an ordinary preheader, a
catering form on the same platform as the phishing one, a brand sending its own
mail, a plain logo SVG. Those are the tests that matter - the first two written
both failed and exposed the two defects above.
Commit: (this commit)


**A-072 - A document that explains the tool to somebody who has not seen it**
What: Wrote `PhishLens - How It Works.pdf` (26 pages) covering the architecture,
the seven ingestion channels, all sixteen pipeline stages, evidence fusion and
the scoring constants, attachment inspection, the twelve rules, the optional
open-source tools, the data-locality guarantees, the full dependency versions,
and the open items.
Status: `Done`
Evidence: Every figure in it was read out of the repository rather than
remembered - the family caps and the 0.70/0.35 thresholds from
`confidenceEngine.js`, the stage order and its stated reasons from `server.js`,
the channel descriptions from `ingestionRegistry.js`, the finding codes from
`attachmentInspector.js`, the rule names from `rules/*.yar`, the counts from the
directories themselves (54 modules, 14 adapters, 28 test files, 23 console
panels), and the dependency versions from the lockfiles.

The open items are stated as open in the document, in their own table, including
that `browser_watch` is receiving nothing. A document that described the browser
channel as working would be the same failure this project has a rule against.

Generator script kept out of the repository: it is a one-shot, and the PDF is
the artefact. The source is pure ASCII on purpose - reportlab's built-in fonts
have no glyph for arrows or Unicode sub/superscripts and render them as solid
black boxes, so `->`, `>=` and `<sub>` tags were used instead. Verified: 26
pages, 66.8 KB, no non-ASCII in the source.
Commit: (this commit)


**A-071 · "Still 0 analyzed" — the popup now says why**
What: After reloading the extension, nothing was examined. The backend showed
`browser_watch` at **0 examined and 0 failures**.
Status: `Done` — cause narrowed, and the popup now names it
Evidence: Zero *failures* was the informative number. Had the watcher been
submitting and being rejected, that count would be non-zero; nothing was
reaching the backend at all. Ruled out from this side: the backend answers, the
provisioned key still authenticates, and the content script loads cleanly when
run the way Chrome loads it — no throw, the single-run guard sets, the providers
export. So the code is fine and something in the browser is not running it.

Chrome could not be inspected from here (no browser is connected to this
session), and asking for the popup's line twice had not produced it. So the
popup now answers the question itself. It asks the worker, which counts mail
tabs and pings each for a watcher, and says which of these applies:

- the permission to watch tabs was not granted
- no Gmail or Outlook tab is open
- a mail tab is open but has no watcher yet — press refresh, or reload the tab
- watching, but nothing examined yet

"The page watcher has not reported yet" was true and useless: those four need
four different things done about them, and it is what left somebody reloading
the extension repeatedly with a tab open that had no watcher in it.
Commit: (this commit)

**A-070 · A refresh button that actually checks the mail**
What: Added a refresh control to the popup header.
Status: `Done`
Evidence: It would have been easy to make it re-read the summary, which looks
like a refresh and changes nothing — the summary only moves once a sweep has
examined something. So pressing it does three things: starts a watcher in any
mail tab that has none (the case it most often exists for, per A-068), nudges
the tabs that have one to sweep immediately rather than waiting out the
four-second poll, and clears any backoff, so an earlier failure cannot leave the
button doing nothing for up to a minute.

The button turns while it works. Without that the only feedback is the counts
changing, which is exactly what does not happen when nothing new was found — and
then it reads as a dead button. Motion is dropped for anyone who prefers reduced
motion, but the disabled state still shows.

The whole chain is asserted — popup, worker, watcher, the backoff reset and the
injection — because any one link missing leaves a button that looks like it
works.
Commit: (this commit)

**A-068 · Reloading the extension did not start watching an open Gmail tab**
What: The popup said "The page watcher has not reported yet" with Gmail plainly
open in another tab.
Status: `Done`
Evidence: A content script is injected when a page loads. Reloading an extension
does **not** re-run it in tabs that are already open, so reloading with Gmail
already open produced nothing at all — and the only hint was a popup saying the
watcher had not reported. Expecting somebody to know they must also reload the
mail tab is expecting them to know how extensions are loaded.

The worker now finds already-open mail tabs and injects into them itself, on
install, on update and on browser startup. That needed the `scripting` and
`tabs` permissions. A guard was added at the same time: the script can now
arrive twice on one page — once from the manifest, once from the worker — and a
second copy would sweep the same list in parallel and submit every message
twice.
Commit: (this commit)

**A-069 · What "analyse existing mail" can and cannot mean**
What: Asked to analyse existing mail as well as incoming.
Status: `Done (partly)` — the rest needs a channel that can enumerate a mailbox
Evidence: The watcher already examines existing mail: it keeps a `seen` set, so
it progresses through the list rather than re-examining the same messages, and
anything scrolled into view is examined. What it cannot do is reach mail that
Gmail has not rendered — a content script sees the page, not the mailbox. For a
2,239-message inbox that means browsing it, not one sweep.

Enumerating a whole mailbox is what the IMAP poller and the Gmail API are for,
and both need a credential only the account holder can create. Raising
MAX_PER_SWEEP would not help: the limit is what Gmail renders, around fifty
rows, not the twenty-five the sweep takes.
Commit: —

**A-065 · My own probe messages were sitting in the user's app**
What: The popup showed "17 messages analyzed" with five entries titled "probe",
all SAFE. The user read this, correctly, as the tool scanning invented mail
rather than theirs.
Status: `Done`
Evidence: Every one was mine, from diagnosing the 500. I had cleared
`cases.json` **while the application was running**, so the backend rewrote it
from memory — the same class of mistake as measuring a build that was not
running (A-052). Cleared properly this time: application stopped first, then
cases, the dedup ledger, the thread index, the sender baselines, the audit log
and the knowledge graph, which had 104 KB of probe nodes and now rebuilds empty.
Backup at `data-backup-before-probe-purge`. Verified after restart: total 0,
all counts 0, recent list empty.

The sender baselines mattered most: leaving them would have taught the detector
what "normal" looks like from senders I invented.
Commit: (this commit)

**A-066 · The popup opened too tall**
What: The recent list and the two buttons made the popup long enough to need
scrolling.
Status: `Done`
Evidence: Both now sit inside a `<details>` drawer that starts closed, so the
popup opens to the counts and the watcher state — which is what it is read for —
and grows only when asked. Asserted: the list and buttons are inside the drawer,
and the drawer has no `open` attribute.
Commit: (this commit)

**A-067 · The three counts do something when pressed**
What: High risk, Suspicious and Legitimate were text that looked pressable and
was not.
Status: `Done`
Evidence: They are buttons now, and pressing one filters the recent list to that
verdict, opens the drawer so the filtering is visible, and marks itself pressed.
Pressing the same one again clears the filter, so there is a way back without
remembering which was pressed. The drawer title says what is being shown and how
many. Asserted in the page tests, which also confirm the filter actually
re-renders rather than only looking pressed.
Commit: (this commit)

**A-061 · The browser reader now finds real Gmail messages**
What: After the reload, the popup changed from "found no messages in the list"
to "Watching mail.google.com, but the last sweep stopped".
Status: `Done`
Evidence: The identifier fix (A-035) works against live Gmail — the reader is
finding rows, reading them, and submitting them. The three-way diagnostic
(A-036) is what made this legible rather than a guess.
Commit: (this commit)

**A-062 · Rows Gmail publishes no id for are no longer dropped**
What: `identify()` now derives a stable id from sender, subject and time when
Gmail publishes none, rather than discarding the row.
Status: `Done`
Evidence: Dropping such rows is what silently reported a 2,241-message inbox as
empty. The derived id is marked `derived-` so it is never mistaken for Gmail's
own, is stable across sweeps, and differs between messages — all asserted. The
backend still deduplicates properly on the raw message afterwards.
Commit: (this commit)

**A-063 · A 500 that could not be reproduced, made self-reporting**
What: The sweep stopped with "PhishLens returned 500".
Status: `Done` — cause **not found**; the failure now reports itself
Evidence: Could not be reproduced. Tested against the running instance:
duplicate submissions, six concurrent submissions, 1/4/12 MB attachments, lone
surrogates, replacement characters, null bytes, undeclared MIME boundaries,
malformed multipart, a header with no colon, a 500,000-character line — every
one returned 200. The original error was gone by the time it was looked for:
the registry keeps failures in memory and the application had been restarted.

So rather than guess, the failure now carries its own diagnosis. The backend
already returned the reason in the 500 body and the extension was discarding
it, reporting only the status code — the one thing already obvious. It now
shows what the backend said, and the backend logs the stack for that path.
**If it happens again the popup will name the cause.**
Commit: (this commit)

**A-064 · Two console hints were wrong**
What: The browser channel said "paste your API key into its options"; the Gmail
API said it needs "a public address Google can reach".
Status: `Done`
Evidence: The key has been written in automatically since the provisioning work
— nothing to paste. And a public address is only needed for Pub/Sub **push**;
without one the adapter still collects mail on each sync, which the backend's
own `limitation` field already said correctly. The console was telling people
they needed infrastructure they do not.
Commit: (this commit)

**A-058 · Street-level 3D view — evaluated, not built**
What: Asked for a Street View equivalent.
Status: `Abandoned` — blocked on both a source and a truthfulness problem.
Evidence: Every street-level source was tested. Google Street View is a paid API
("You must use an API key"). Mapillary needs an OAuth token. KartaView is
keyless but returned **0 photographs** within 500 m of Hyderabad or rural
Rajasthan. OSM Buildings has required registration since 2024-04-03. Overpass is
keyless (with a User-Agent — 406 without one) and returns footprints, but only
**1 of 99** buildings carried a height, so any 3D would be invented.

The stronger objection is not technical. This map plots IP geolocation, which
resolves to a city or an ISP's service area — `8.8.8.8` returns a San Jose
centroid, not a building. Dropping somebody into a street-level view at those
coordinates would show a specific house and imply the message came from it. For
a tool whose whole discipline is not reporting unchecked things as known, that
is the same error as reporting "no macros found" when nothing looked.
Commit: —

**A-059 · detectRetina — measured, broke deep zoom, reverted**
What: Enabled retina tiles to counter the softness from 125% display scaling.
Status: `Reverted`
Evidence: It did sharpen imagery (1.25 to 0.63 device pixels per image pixel) at
a cost of 81 to 117 requests and ~1685 to ~2360 ms. But it also produced **no
imagery at all at zooms 19, 20 and 21**: it requests one level deeper than
exists, and the placeholder detection correctly hides what comes back. Far worse
than slight softness, and the same reason detectRetina was removed earlier in
this project. The first measurement of it was also wrong — it read the
OpenStreetMap fallback tile rather than the imagery layer, and reported no
change at all.
Commit: —

**A-060 · Stopped magnifying five times over**
What: The map allowed two zoom levels past the deepest real imagery.
Status: `Done`
Evidence: Measured per level on this display: zoom 19 draws imagery at 1.25
device pixels per image pixel, zoom 20 at 2.5, zoom 21 at **5.0** — a building
as a handful of coloured squares. The second level bought nothing but the
impression the map had gone out of focus. Capped at one level, and the caption
now says "Magnified past the available detail" when the view has passed real
detail. Verified: the note appears at zoom 20 and not at 18 or 19.

What could not be improved: the residual 1.25x softness is **Windows display
scaling at 125%**, which affects everything on screen, not the map. The display
is 1920x1080, not 4K. And the imagery's own resolution — 0.46 m/pixel in
Hyderabad — is the real limit on detail; no setting adds information that was
never photographed.
Commit: (this commit)

**A-055 · Imagery coverage is not uniform, and cannot be made so**
What: Measured resolution, capture date and maximum zoom across every continent,
after a report that only India had been updated.
Status: `Done`
Evidence: Nothing had been updated anywhere — PhishLens hosts no map data. India
is unremarkable in Esri's global product: **New York is 0.15 m/pixel against
Hyderabad's 0.46 m**, and every major city sampled reaches zoom 19. What does
vary is the edge of coverage: deserts and forest stop near **17**, and open
ocean, Greenland and Antarctica have nothing better than **15 m/pixel** and stop
at **11**. Siberia's most recent imagery is from **2012**. None of that is
fixable from here — nobody photographs the open sea at half a metre.
Commit: (this commit)

**A-056 · Nowhere is blank any more**
What: Past the edge of coverage Esri returns a grey "Map data not yet available"
tile, and because it arrives as a valid JPEG with HTTP 200 Leaflet drew it like
any other tile.
Status: `Done`
Evidence: Three facts made a fix possible, each verified rather than assumed:
Esri send `Access-Control-Allow-Origin: *`; the placeholders are byte-identical
(1652 and 2521 bytes, stable hashes); and OpenStreetMap has coverage exactly
where Esri does not. An ordinary map now sits beneath the photography, and tiles
smaller than 3500 bytes are left transparent so it shows through. Measured
after: Pacific, Greenland and Antarctica went from blank to drawn, with 24, 15
and 24 placeholder tiles correctly hidden, and cities unchanged with zero hidden.
Commit: (this commit)

**A-057 · The fallback map capped at zoom 12**
What: The map underneath was being fetched to zoom 19 as well, doubling tiles
for a layer that is invisible wherever imagery exists.
Status: `Done`
Evidence: Street level went from **97 to 81 requests**. Coverage is unchanged —
Leaflet scales the shallower tiles where photography is missing, which is
slightly soft in the few deep-zoomed places with none, and free everywhere else.
Net against the start of the day: country view **2350 → ~1290 ms**, street level
**2350 → ~1685 ms**, with complete global coverage rather than grey squares.
Commit: (this commit)

**A-054 · A test changed the user's saved basemap and left it changed**
What: Verifying that the imagery caption hides on a non-photographic basemap
switched the selector to Standard — which is persisted to localStorage, so it
survived a reinstall.
Status: `Done` — restored to satellite
Evidence: The next measurement then read 145 ms and no caption, both of which
looked like features failing. They were not: the map was on OpenStreetMap, which
is one layer and has no photography to date. A test that alters a stored
preference must put it back; this one now does. Verified restored, and the
packaged build re-measured on satellite: country view **~1380 ms / 49 requests**,
street level **~1264 ms / 73 requests**. The extra single request in each is the
imagery-date lookup — once per settled view, not per tile.
Commit: (this commit)

**A-053 · The map now says how old its photography is**
What: The caption under the map states when the imagery beneath the current view
was captured, and at what resolution.
Status: `Done`
Evidence: Answers the question in the product rather than only in conversation.
Satellite imagery is a photograph with a date, and the date varies enormously —
about ten months for Indian cities, two and a half years for the United States
sample. For a tool whose job is to say where a message came from, showing a
location on imagery of unstated vintage invites reading it as current. Verified
in the running application: "Photography here taken November 2025 (10 months
ago) · 0.46 m per pixel", and correctly absent on the OpenStreetMap basemaps,
which have no photography to date. Asked once per settled view, not per tile,
through the same free keyless Esri service; a failed or slow lookup shows
nothing rather than a guess.
Commit: (this commit)

**A-052 · Measured a build that was not running**
What: Deployed the new console and measured without restarting the application.
Status: `Abandoned` — the numbers described the previous build.
Evidence: Zoom 13 reported 48 requests when it should have been 72, and the
layer count gave it away: two panes, not three. The bundle had been replaced on
disk and the running window still held the old one. Deploying is not loading.
Commit: —

## 2026-09-22 — full verification pass

**A-041 · Detection battery through the real SMTP channel**
What: Eight messages — five techniques, three ordinary — sent through the
enabled gateway and checked against expected verdicts.
Status: `Done`
Evidence: 7 of 8 correct on the first run. Credential form, HTML smuggling and
paste-to-run all `HIGH_RISK` at 0.70; macro document `SUSPICIOUS` at 0.37;
ordinary note, newsletter and PDF all `SAFE`. One genuine miss, below.
Commit: (this commit)

**A-042 · A program disguised as a PDF came back SAFE**
What: `statement.pdf.exe`, declared `application/pdf`, with an `MZ` header.
Status: `Done`
Evidence: Detection was **correct** — it reported the double extension, the
executable attachment and the declared/actual mismatch, and matched two MQL
rules. The failure was in scoring: all of it falls in one family, that family is
capped at 0.20, and the total reached 0.30 against a 0.35 threshold. Four
inspector findings are now decisive — the ones describing a deliberate disguise
or code set to run on open. `EXECUTABLE_ATTACHMENT` and `OFFICE_MACROS_PRESENT`
are deliberately **not** decisive: both have legitimate uses. Now `HIGH_RISK` at
0.70, with ordinary files unchanged at 0.07.
Commit: (this commit)

**A-043 · False alarm: "each message is recorded twice"**
What: Reported 16 cases from 8 sent messages.
Status: `Abandoned` — the diagnosis was wrong, no change made.
Evidence: The Message-IDs were twelve seconds apart in two batches. My battery
script sent all eight messages and *then* crashed on a file write, so I re-ran
it and sent eight more. Deduplication correctly kept them separate because they
were genuinely different messages. My harness, not the product.
Commit: —

**A-044 · Enabling SMTP hid the browser extension's setup steps**
What: The setup panel was shown only when no live-mail channel was watching.
Status: `Done`
Evidence: Caused by A-038. Switching on the SMTP gateway hid the instructions
for the browser extension — and the SMTP gateway cannot see somebody's Gmail.
The steps for a channel that is not set up must not disappear because a
different one is. Now keyed to the browser channel's own status.
Commit: (this commit)

**A-045 · Whole-console render check**
What: Clicked through all eleven pages, checking none blanks the application.
Status: `Done`
Evidence: 11 of 11 render, none blank it, map loads 54/54 tiles with 0 broken,
12 rules reported in the panel. This is what the error boundary and the console
source tests were added for.
Commit: (this commit)

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
