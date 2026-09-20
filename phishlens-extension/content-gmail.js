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

    async function sweepOnce() {
        const visible = provider.listVisible(document);
        // Unread first. Those are the ones not yet opened, which is the whole
        // reason for watching the list rather than the open message.
        visible.sort((a, b) => Number(b.unread) - Number(a.unread));

        for (const entry of visible.slice(0, MAX_PER_SWEEP)) {
            try {
                await examine(entry);
            } catch (e) {
                // Whatever stopped this message will stop the next twenty-four
                // in exactly the same way, so the sweep ends here and the
                // backoff decides when to try again.
                return;
            }
        }
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
