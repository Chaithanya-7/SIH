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

    const seen = new Set();
    let enabled = true;
    let inboxKey = null;

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

        try {
            const response = await fetch(url, { credentials: 'include' });
            if (!response.ok) return null;
            const text = await response.text();
            return provider.looksLikeRawMessage(text) ? text : null;
        } catch (e) {
            return null;
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
            if (result?.verdict) flag(entry.row, result.verdict, result.confidence);
        } catch (e) {
            // Forgotten again so it is retried, and silent: a backend that is
            // not running must not fill the console of somebody's mail client
            // with an error every four seconds.
            seen.delete(key);
        }
    }

    async function sweep() {
        if (!enabled) return;

        const visible = provider.listVisible(document);
        // Unread first. Those are the ones not yet opened, which is the whole
        // reason for watching the list rather than the open message.
        visible.sort((a, b) => Number(b.unread) - Number(a.unread));

        for (const entry of visible.slice(0, MAX_PER_SWEEP)) {
            await examine(entry);
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
