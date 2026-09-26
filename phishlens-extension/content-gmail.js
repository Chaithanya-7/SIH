/**
 * Watches webmail in the browser and examines messages before they are opened.
 *
 * This exists because connecting a mail account is the wrong shape for the
 * problem. It asks for credentials, it covers only the account somebody
 * remembered to add, and it sees a message no sooner than a poll allows. A
 * content script sees whatever mail the person is actually looking at, in
 * whichever account they are signed into, with no credential anywhere.
 *
 * ## Why it fetches the original rather than reading the page
 *
 * A rendered row yields a subject, a display name and a snippet. It does *not*
 * yield the headers, and the headers are most of what decides whether a message
 * is phishing: SPF, DKIM and DMARC results, the Received chain, Return-Path,
 * Reply-To, the References that expose thread hijacking.
 *
 * Webmail already exposes the original to the signed-in user - it is what "Show
 * original" downloads. This runs in the page's own origin, so it can fetch that
 * with the session already in the browser. No password, no OAuth client, no
 * token stored anywhere.
 *
 * When the original cannot be had, the message is still submitted but marked
 * `BODY_ONLY`, so the backend knows the authentication signals are absent
 * rather than negative. A message whose authentication was never visible must
 * not reach the same verdict as one that failed it.
 *
 * How each provider is read lives in mail-providers.js.
 */

(() => {
    // Run once per page, however the script arrived.
    //
    // It is injected by the manifest when a mail page loads, and injected again
    // by the worker into tabs that were already open when the extension loaded.
    // Both can happen to the same page, and a second copy would sweep the same
    // list in parallel with the first - submitting every message twice and
    // doubling the requests for nothing.
    if (window.__phishlensWatcherRunning) return;
    window.__phishlensWatcherRunning = true;

    'use strict';

    const ext = globalThis.browser || globalThis.chrome;
    const POLL_MS = 4000;
    const MAX_PER_SWEEP = 25;
    const MAX_SEEN = 2000;
    // Long enough for a slow mailbox, short enough that a hung request does not
    // hold up the messages queued behind it.
    const FETCH_TIMEOUT_MS = 8000;
    // Gmail and Outlook both refuse messages beyond 25MB; the allowance covers
    // base64 overhead on top of that.
    const MAX_MESSAGE_BYTES = 35 * 1024 * 1024;
    // The ceiling on that widening gap: a minute is long enough to stop being a
    // burden and short enough that nobody notices the delay after a restart.
    const MAX_BACKOFF_MS = 60000;

    const seen = new Set();
    let enabled = true;
    let inboxKey = null;
    // One sweep at a time.
    //
    // A sweep examines up to twenty-five messages, each a network round trip,
    // so it routinely outlasts the four-second interval that starts the next
    // one. Overlapping sweeps did not duplicate work - `seen` is claimed before
    // the first await - but they did multiply the in-flight requests against
    // both the mail provider and the local backend, without ever examining a
    // message sooner.
    let sweeping = false;
    // Backing off when PhishLens is not answering.
    //
    // A failed submission un-remembers its message so it is tried again, which
    // is right for a single hiccup and wrong for a backend that is simply not
    // running: twenty-five messages retried every four seconds is a steady six
    // requests a second against something that is not there, plus a re-fetch of
    // each original from the mail provider. Nobody sees it, and it continues
    // for as long as the tab is open.
    let consecutiveFailures = 0;
    let quietUntil = 0;

    const provider = globalThis.PhishLensMailProviders?.forHostname(location.hostname) || null;
    if (!provider) return;

    function remember(key) {
        seen.add(key);
        if (seen.size > MAX_SEEN) {
            const excess = seen.size - MAX_SEEN;
            let removed = 0;
            for (const old of seen) {
                seen.delete(old);
                if (++removed >= excess) break;
            }
        }
    }

    /**
     * The original message, if this provider offers one and the session is live.
     *
     * Returns null rather than throwing on every failure path, because a
     * message that cannot be fetched in full is still worth examining from what
     * the row shows.
     */
    async function originalMessage(id) {
        if (inboxKey === null) inboxKey = provider.inboxKey(document);
        const url = provider.rawUrl(id, location, inboxKey);
        if (!url) return null;

        // Abandoned if it does not answer.
        //
        // A fetch with no deadline can hang for as long as the connection stays
        // open, and this one is awaited inside a sequential loop, so a single
        // unanswered request stopped that sweep permanently - every message
        // behind it went unexamined, silently, with the extension still
        // appearing to run.
        const controller = new AbortController();
        const deadline = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

        try {
            const response = await fetch(url, { credentials: 'include', signal: controller.signal });
            if (!response.ok) return null;

            // A mail provider serves what a mailbox holds, and an attachment
            // can be large. Reading it whole into a string before deciding
            // anything is how a 30MB message becomes a stalled tab.
            const length = Number(response.headers.get('content-length') || 0);
            if (length > MAX_MESSAGE_BYTES) return null;

            const text = await response.text();
            if (text.length > MAX_MESSAGE_BYTES) return null;

            return provider.looksLikeRawMessage(text) ? text : null;
        } catch (e) {
            // An abort lands here too, which is the intended path rather than
            // an error worth reporting.
            return null;
        } finally {
            clearTimeout(deadline);
        }
    }

    /**
     * Handed to the service worker rather than posted from here.
     *
     * A content script's fetch carries the mail site's origin, so a request to
     * localhost is cross-origin and blocked unless the backend allows
     * mail.google.com - a wide hole opened for a narrow need. The worker holds
     * the host permission and is not bound by the page's CORS, and it keeps the
     * API key out of a script injected into a page.
     */
    function submit(payload) {
        return new Promise((resolve, reject) => {
            ext.runtime.sendMessage({ type: 'phishlens:examine', payload }, response => {
                if (ext.runtime.lastError) return reject(new Error(ext.runtime.lastError.message));
                if (!response || !response.ok) return reject(new Error(response?.error || 'No answer from PhishLens.'));
                resolve(response.result);
            });
        });
    }

    /**
     * Marks a row whose verdict came back dangerous.
     *
     * Deliberately an annotation and nothing more: it does not hide, move or
     * click anything. A tool that silently rearranges somebody's inbox is one
     * they uninstall, and being wrong about a single message would then mean
     * losing it.
     */
    function flag(row, verdict, confidence) {
        if (!row || row.querySelector('.phishlens-flag')) return;

        const styles = {
            HIGH_RISK: { text: 'Dangerous', background: '#b4232a' },
            SUSPICIOUS: { text: 'Suspicious', background: '#a9701d' }
        };
        const style = styles[verdict];
        if (!style) return;

        const tag = document.createElement('span');
        tag.className = 'phishlens-flag';
        tag.textContent = `PhishLens: ${style.text}`;
        tag.title = `PhishLens examined this before you opened it — ${Math.round((confidence || 0) * 100)}% confident.`;
        tag.style.cssText = [
            `background:${style.background}`, 'color:#fff', 'font-size:10px', 'font-weight:700',
            'padding:1px 6px', 'border-radius:3px', 'margin-right:6px',
            'vertical-align:middle', 'letter-spacing:0.02em', 'white-space:nowrap'
        ].join(';');

        const anchor = provider.labelAnchor(row);
        if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(tag, anchor);
    }

    async function examine(entry) {
        const key = `${location.hostname}:${entry.id}`;
        if (seen.has(key)) return;
        remember(key);

        const raw = await originalMessage(entry.id);
        const payload = raw
            ? { source: location.hostname, provider_message_id: entry.id, raw, evidence: 'FULL_HEADERS' }
            : { source: location.hostname, provider_message_id: entry.id, evidence: 'BODY_ONLY', ...provider.fallback(entry) };

        try {
            const result = await submit(payload);
            consecutiveFailures = 0;
            if (result?.verdict) flag(entry.row, result.verdict, result.confidence);
        } catch (e) {
            // Forgotten again so it is retried, and silent: a backend that is
            // not running must not fill the console of somebody's mail client
            // with an error every four seconds.
            seen.delete(key);
            noteFailure();
            throw e;
        }
    }

    /**
     * Widens the gap between attempts while PhishLens stays unreachable.
     *
     * Doubling from one sweep to at most a minute, so a backend that is merely
     * restarting is picked up within seconds while one that is switched off
     * costs a request a minute rather than six a second. Any success resets it.
     */
    function noteFailure() {
        consecutiveFailures += 1;
        const backoff = Math.min(POLL_MS * Math.pow(2, consecutiveFailures - 1), MAX_BACKOFF_MS);
        quietUntil = Date.now() + backoff;
    }

    async function sweep() {
        if (!enabled || sweeping || Date.now() < quietUntil) return;
        sweeping = true;

        try {
            await sweepOnce();
        } finally {
            sweeping = false;
        }
    }

    /**
     * Tells the worker what this sweep actually saw.
     *
     * The watcher was designed to fail quietly, so that a backend which is not
     * running could not fill the console of somebody's mail client. That was
     * right, and it left no way to answer the only question anybody asks of it:
     * is this looking at my mail? "Not running", "running but recognising
     * nothing on the page", and "running with nothing new to examine" all
     * produced exactly the same silence.
     *
     * So each sweep reports what it saw. Nothing here is message content - it is
     * counts, a timestamp, and the last error, which is what distinguishes those
     * three cases from each other.
     */
    function report(status) {
        try {
            ext.runtime.sendMessage({
                type: 'phishlens:watch-status',
                status: { ...status, host: location.hostname, at: new Date().toISOString() }
            }, () => void ext.runtime.lastError);
        } catch (e) {
            // The worker is gone or the page is unloading. Nothing to do.
        }
    }

    async function sweepOnce() {
        const visible = provider.listVisible(document);
        // Reported before anything is examined, because finding no rows at all
        // is the failure that matters most: it means the page is not the one
        // this reader understands, or its markup has moved.
        // Rows on the page and rows that could be identified are reported
        // separately. They used to be the same number, and when every row was
        // dropped for lacking an id the result was "no messages in the list" -
        // which reads as the reader not matching the page, when in fact it
        // matched every row and threw them all away.
        const rowsOnPage = typeof provider.countRows === 'function' ? provider.countRows(document) : visible.length;

        // When the reader finds nothing, what it *can* see is the only useful
        // thing to send. "No messages in the list" reads as an empty inbox and
        // is the one report that actually means the reader no longer matches
        // the page - so it travels with a census of what the page carries.
        const reader = (rowsOnPage === 0 && typeof provider.describeReader === 'function')
            ? provider.describeReader(document)
            : null;

        report({
            rowsSeen: rowsOnPage,
            identified: visible.length,
            provider: provider.id || 'unknown',
            reader,
            phase: 'listed'
        });
        // Unread first. Those are the ones not yet opened, which is the whole
        // reason for watching the list rather than the open message.
        visible.sort((a, b) => Number(b.unread) - Number(a.unread));

        let examined = 0;
        for (const entry of visible.slice(0, MAX_PER_SWEEP)) {
            try {
                await examine(entry);
                examined++;
            } catch (e) {
                report({ rowsSeen: rowsOnPage, identified: visible.length, examined, phase: 'error', error: String(e && e.message || e).slice(0, 200) });
                // Whatever stopped this message will stop the next twenty-four
                // in exactly the same way, so the sweep ends here and the
                // backoff decides when to try again.
                return;
            }
        }

        report({ rowsSeen: rowsOnPage, identified: visible.length, examined, phase: 'done' });
    }

    // ======================================================================
    // The backlog scan
    //
    // Everything above watches what arrives. This reads what is already there.
    //
    // ## Why it is a separate thing rather than a bigger sweep
    //
    // The watcher can only see rows the mail client has rendered, and a webmail
    // list is virtualised: roughly fifty rows exist in the page at any moment,
    // however many the mailbox holds. A sweep therefore covers what somebody
    // has scrolled past, not the thousands behind it.
    //
    // What makes a backlog scan possible at all is that fetching a message by
    // its identifier does not need the row to be on screen. So the scan pages
    // through the list to collect identifiers, and fetches each message exactly
    // the way the watcher does.
    //
    // ## Why it is slow on purpose
    //
    // A full mailbox is thousands of requests to the mail provider from the
    // signed-in session. Issued quickly that is indistinguishable from
    // scraping, and the realistic outcomes are throttling or a security
    // challenge on the person's own account. A tool that gets somebody's
    // mailbox flagged has done more damage than the phishing it was looking
    // for. So there is a deliberate pause between messages and the scan is
    // measured in hours running quietly, not minutes running hard.
    //
    // ## What it does to the tab it runs in
    //
    // It navigates that tab through the pages of the list, which is visible and
    // disruptive if it is the tab somebody is reading. Opening a separate tab
    // for it is the worker's job; this code only refuses to start a second scan
    // in a tab already running one.
    //
    // ## Resuming
    //
    // Progress is the page number, kept in extension storage, so closing the
    // tab loses at most one page. Messages already examined are deliberately
    // not tracked across sessions: the backend deduplicates on the message
    // itself and returns the existing case, which is a stronger guarantee than
    // any list kept here, and it means a resumed scan costs repeated fetches
    // rather than duplicate cases.
    // ======================================================================

    /** Between messages. Slow deliberately - see above. */
    const BACKLOG_PACE_MS = 1500;
    /** After moving to a new page, before reading rows from it. */
    const BACKLOG_SETTLE_MS = 2600;
    /** How long to wait for a page to actually change before giving up on it. */
    const BACKLOG_PAGE_TIMEOUT_MS = 15000;
    /** A stop, so an unusual list cannot loop forever. */
    const BACKLOG_MAX_PAGES = 400;
    /** Consecutive pages yielding nothing new before concluding the end was reached. */
    const BACKLOG_EMPTY_PAGES_BEFORE_STOP = 2;

    const backlog = {
        running: false,
        cancelled: false,
        page: 0,
        examined: 0,
        failed: 0,
        pagesWithNothingNew: 0,
        startedAt: null,
        finishedAt: null,
        lastError: null
    };

    function backlogReport(phase) {
        report({
            phase: `backlog:${phase}`,
            backlog: {
                running: backlog.running,
                page: backlog.page,
                examined: backlog.examined,
                failed: backlog.failed,
                startedAt: backlog.startedAt,
                finishedAt: backlog.finishedAt,
                lastError: backlog.lastError
            }
        });
        try {
            ext.storage?.local.set({
                phishlensBacklog: {
                    host: location.hostname,
                    running: backlog.running,
                    page: backlog.page,
                    examined: backlog.examined,
                    failed: backlog.failed,
                    startedAt: backlog.startedAt,
                    finishedAt: backlog.finishedAt,
                    lastError: backlog.lastError,
                    updatedAt: new Date().toISOString()
                }
            });
        } catch (e) {
            // Storage being unavailable loses the resume point, not the scan.
        }
    }

    const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

    /** A cheap fingerprint of what is listed, used to tell that a page really changed. */
    function listSignature() {
        return provider.listVisible(document).map(r => r.id).join(',');
    }

    /**
     * Moves to a page of the list and waits for it to become a different page.
     *
     * Navigation in a webmail client is a hash change and an asynchronous
     * re-render, so there is no load event to wait on. A fixed wait would
     * either be too short on a slow connection - reading the old page twice and
     * concluding the end had been reached - or needlessly slow on a fast one.
     */
    async function goToPage(pageNumber, previousSignature) {
        if (typeof provider.pageHash !== 'function') return false;

        const hash = provider.pageHash(pageNumber);
        if (!hash) return false;

        location.hash = hash;

        const until = Date.now() + BACKLOG_PAGE_TIMEOUT_MS;
        while (Date.now() < until) {
            await pause(400);
            if (backlog.cancelled) return false;
            const signature = listSignature();
            if (signature && signature !== previousSignature) {
                // Rendered, but rows can still be settling into place.
                await pause(BACKLOG_SETTLE_MS);
                return true;
            }
        }
        return false;
    }

    /**
     * Examines one message as part of a backlog scan.
     *
     * Separate from examine() for one reason: the submission is labelled
     * HISTORICAL. That is what tells the backend not to run the checks that
     * would describe today's infrastructure rather than the state when the
     * message arrived, and not to act on mail the recipient dealt with long
     * ago.
     */
    async function examineHistorical(entry) {
        const key = `${location.hostname}:${entry.id}`;
        const raw = await originalMessage(entry.id);

        const payload = raw
            ? { source: location.hostname, provider_message_id: entry.id, raw, evidence: 'FULL_HEADERS', analysis_mode: 'HISTORICAL' }
            : { source: location.hostname, provider_message_id: entry.id, evidence: 'BODY_ONLY', analysis_mode: 'HISTORICAL', ...provider.fallback(entry) };

        const result = await submit(payload);
        remember(key);
        if (result?.verdict) flag(entry.row, result.verdict, result.confidence);
        return result;
    }

    async function runBacklog(startPage) {
        if (backlog.running) return { ok: false, error: 'A backlog scan is already running in this tab.' };
        if (typeof provider.pageHash !== 'function') {
            // Said plainly rather than silently doing nothing. Paging is
            // provider-specific and only claimed where it is known to work.
            return { ok: false, error: `Backlog scanning is not implemented for ${provider.id || 'this provider'} yet. The live watcher still runs here.` };
        }

        backlog.running = true;
        backlog.cancelled = false;
        backlog.page = Number(startPage) > 0 ? Number(startPage) : 1;
        backlog.examined = 0;
        backlog.failed = 0;
        backlog.pagesWithNothingNew = 0;
        backlog.startedAt = new Date().toISOString();
        backlog.finishedAt = null;
        backlog.lastError = null;
        backlogReport('started');

        try {
            let signature = listSignature();

            while (!backlog.cancelled && backlog.page <= BACKLOG_MAX_PAGES) {
                if (backlog.page > 1) {
                    const moved = await goToPage(backlog.page, signature);
                    // Either the end of the list or a page that would not
                    // render. Both mean stopping; neither is an error.
                    if (!moved) break;
                }

                signature = listSignature();
                const rows = provider.listVisible(document);

                // A reader that matches nothing will match nothing on page two
                // as well. Paging on regardless spends fifteen seconds per page
                // waiting for a list that will never appear, and reports
                // "scanning" throughout - which looks like progress and is not.
                if (backlog.page === 1 && rows.length === 0 && (provider.countRows?.(document) || 0) === 0) {
                    backlog.lastError = 'The reader found no messages on this page, so there is nothing to scan. This means the page layout no longer matches what the reader expects, not that the mailbox is empty.';
                    break;
                }

                const fresh = rows.filter(r => !seen.has(`${location.hostname}:${r.id}`));

                if (!fresh.length) {
                    backlog.pagesWithNothingNew += 1;
                    if (backlog.pagesWithNothingNew >= BACKLOG_EMPTY_PAGES_BEFORE_STOP) break;
                } else {
                    backlog.pagesWithNothingNew = 0;
                }

                for (const entry of fresh) {
                    if (backlog.cancelled) break;
                    try {
                        await examineHistorical(entry);
                        backlog.examined += 1;
                        consecutiveFailures = 0;
                    } catch (e) {
                        backlog.failed += 1;
                        backlog.lastError = String(e && e.message || e).slice(0, 200);
                        noteFailure();
                        // A backend that is down will refuse the next thousand
                        // messages exactly as it refused this one. Wait out the
                        // backoff rather than burning through a mailbox
                        // failing, and give up if it never comes back.
                        if (consecutiveFailures >= 5) throw new Error(`Stopped after 5 consecutive failures: ${backlog.lastError}`);
                        await pause(Math.max(0, quietUntil - Date.now()));
                    }
                    await pause(BACKLOG_PACE_MS);
                    if (backlog.examined % 10 === 0) backlogReport('running');
                }

                backlog.page += 1;
                backlogReport('page');
            }
        } catch (e) {
            backlog.lastError = String(e && e.message || e).slice(0, 200);
        } finally {
            backlog.running = false;
            backlog.finishedAt = new Date().toISOString();
            backlogReport(backlog.cancelled ? 'cancelled' : 'finished');
        }

        return { ok: true, examined: backlog.examined, failed: backlog.failed, pages: backlog.page, error: backlog.lastError };
    }

    // Sweep on request, not only on the timer.
    //
    // Without this the refresh button could only promise "it will look within
    // four seconds", which is not what pressing a button should mean.
    if (ext.runtime?.onMessage) {
        ext.runtime.onMessage.addListener((request, sender, sendResponse) => {
            // Answers "is a watcher in this tab", which is how the popup tells
            // a tab with no content script from one that simply found nothing.
            if (request?.type === 'phishlens:ping') { sendResponse({ ok: true }); return false; }

            if (request?.type === 'phishlens:backlog-start') {
                // Deliberately not awaited: this runs for hours, and a message
                // handler that does not answer promptly is treated as a dead
                // one by the caller.
                runBacklog(request.startPage);
                sendResponse({ ok: true, started: true, pace_ms: BACKLOG_PACE_MS });
                return false;
            }

            if (request?.type === 'phishlens:backlog-stop') {
                backlog.cancelled = true;
                sendResponse({ ok: true, stopping: backlog.running });
                return false;
            }

            if (request?.type === 'phishlens:backlog-status') {
                sendResponse({ ok: true, backlog: { ...backlog } });
                return false;
            }

            if (request?.type !== 'phishlens:sweep-now') return;
            // Clear any backoff: the person is asking now, and an earlier
            // failure should not make them wait out its penalty.
            quietUntil = 0;
            consecutiveFailures = 0;
            sweep();
            sendResponse({ ok: true });
            return false;
        });
    }

    function start() {
        ext.storage?.local.get(['browserWatchEnabled'], stored => {
            enabled = stored.browserWatchEnabled !== false;
            sweep();
            setInterval(sweep, POLL_MS);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
