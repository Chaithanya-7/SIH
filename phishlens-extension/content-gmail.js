/**
 * Watches webmail in the browser and examines messages before they are opened.
 *
 * This exists because connecting a mail account is the wrong shape for the
 * problem. It asks for credentials, it only covers the one account somebody
 * remembered to add, and it sees a message no sooner than a poll allows. A
 * content script sees whatever mail the person is actually looking at, in
 * whichever account they are signed into, with no credential anywhere.
 *
 * ## Why it fetches the raw message rather than reading the page
 *
 * Scraping the rendered DOM yields a subject, a display name and some body
 * text. It does *not* yield the headers, and the headers are most of what
 * decides whether a message is phishing: SPF, DKIM and DMARC results, the
 * Received chain, Return-Path, Reply-To, the References that expose thread
 * hijacking. A verdict without them is a guess wearing a confidence score.
 *
 * Webmail already exposes the original message to the signed-in user - it is
 * what "Show original" downloads. A content script runs in the page's own
 * origin, so it can fetch that with the session already in the browser. No
 * password, no OAuth client, no token stored anywhere.
 *
 * ## When the raw message cannot be had
 *
 * Providers change these endpoints. If the fetch fails, the message is still
 * submitted, but marked `evidence: 'BODY_ONLY'` so the backend knows the
 * authentication signals are absent rather than negative - an unauthenticated
 * message and a message whose authentication was never visible must not reach
 * the same verdict.
 */

(() => {
    'use strict';

    const SEEN = new Set();
    const MAX_SEEN = 2000;
    const POLL_MS = 4000;

    let settings = { apiBaseUrl: 'http://localhost:3001', apiKey: '', enabled: true };

    const ext = typeof browser !== 'undefined' ? browser : chrome;

    function remember(id) {
        SEEN.add(id);
        if (SEEN.size > MAX_SEEN) {
            // Oldest first; a long webmail session must not grow this forever.
            const drop = SEEN.size - MAX_SEEN;
            let i = 0;
            for (const key of SEEN) {
                SEEN.delete(key);
                if (++i >= drop) break;
            }
        }
    }

    // ---------------------------------------------------------------- Gmail

    const gmail = {
        matches: () => location.hostname === 'mail.google.com',

        /**
         * Message ids visible in the current list.
         *
         * Gmail marks each row with a legacy message id in `data-legacy-message-id`
         * (or the thread id in `data-legacy-thread-id`). Reading the attribute is
         * far steadier than matching class names, which are generated and change.
         */
        listVisible() {
            const rows = document.querySelectorAll('tr.zA, div[role="listitem"]');
            const found = [];
            rows.forEach(row => {
                const id = row.getAttribute('data-legacy-message-id')
                    || row.getAttribute('data-legacy-thread-id')
                    || row.getAttribute('data-thread-id');
                if (!id) return;
                const unread = row.classList.contains('zE') || row.getAttribute('aria-label')?.includes('unread');
                found.push({ id: String(id).replace(/^#/, ''), unread: !!unread, row });
            });
            return found;
        },

        /** The account index in the URL, so a second signed-in account is not read as the first. */
        userIndex() {
            const m = location.pathname.match(/\/mail\/u\/(\d+)/);
            return m ? m[1] : '0';
        },

        /**
         * The original message, as "Show original" would download it.
         *
         * `view=om` returns the full RFC 822 source. It needs the `ik` value
         * Gmail puts in the page, which is why this reads it out of the loaded
         * scripts rather than guessing.
         */
        async rawMessage(id) {
            const ik = this.inboxKey();
            if (!ik) return null;
            const url = `${location.origin}/mail/u/${this.userIndex()}/?ik=${encodeURIComponent(ik)}&view=om&permmsgid=msg-f:${encodeURIComponent(id)}`;
            const res = await fetch(url, { credentials: 'include' });
            if (!res.ok) return null;
            const text = await res.text();
            // The endpoint answers with the sign-in page when the session has
            // lapsed, which parses as a message with no headers and would be
            // analysed as one.
            if (!/^[\w-]+:\s/m.test(text) || /<html/i.test(text.slice(0, 200))) return null;
            return text;
        },

        inboxKey() {
            if (this._ik) return this._ik;
            const html = document.documentElement.innerHTML;
            const m = html.match(/["']ik["']\s*:\s*["']([^"']+)["']/) || html.match(/ik=([A-Za-z0-9]+)/);
            this._ik = m ? m[1] : null;
            return this._ik;
        },

        /** What can be read from the row itself, when the original cannot be fetched. */
        fallback(entry) {
            const row = entry.row;
            const subject = row.querySelector('.bog')?.textContent?.trim() || '';
            const senderEl = row.querySelector('.yW span[email], .gD');
            const sender = senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || '';
            const snippet = row.querySelector('.y2')?.textContent?.trim() || '';
            return { subject, sender, snippet };
        }
    };

    // ------------------------------------------------------------ Outlook Web

    const outlook = {
        matches: () => /outlook\.(live|office|office365)\.com$/.test(location.hostname),

        listVisible() {
            const rows = document.querySelectorAll('div[role="option"][data-convid], div[aria-label][data-convid]');
            return Array.from(rows).map(row => ({
                id: row.getAttribute('data-convid'),
                unread: (row.getAttribute('aria-label') || '').toLowerCase().includes('unread'),
                row
            })).filter(r => r.id);
        },

        // Outlook Web exposes no equivalent of "show original" at a stable URL,
        // so this reports what the row carries and says so.
        async rawMessage() { return null; },

        fallback(entry) {
            const row = entry.row;
            const spans = row.querySelectorAll('span');
            return {
                subject: spans[1]?.textContent?.trim() || '',
                sender: spans[0]?.textContent?.trim() || '',
                snippet: row.textContent?.slice(0, 400) || ''
            };
        }
    };

    const PROVIDERS = [gmail, outlook];

    function provider() {
        return PROVIDERS.find(p => p.matches()) || null;
    }

    // ---------------------------------------------------------------- submit

    /**
     * Handed to the background worker rather than posted from here.
     *
     * A content script's fetch carries the page's origin, so a request to
     * localhost is a cross-origin one that the browser blocks unless the
     * backend allows mail.google.com - which would be a wide hole opened for a
     * narrow need. The service worker holds the host permission and is not
     * subject to the page's CORS, so the request belongs there.
     *
     * Fetching the original message stays here, because that one is
     * same-origin and needs the session this page already has.
     */
    function submit(payload) {
        return new Promise((resolve, reject) => {
            ext.runtime.sendMessage({ type: 'phishlens:examine', payload }, response => {
                if (ext.runtime.lastError) return reject(new Error(ext.runtime.lastError.message));
                if (!response || !response.ok) return reject(new Error(response?.error || 'No response from PhishLens.'));
                resolve(response.result);
            });
        });
    }

    /**
     * Marks a row whose verdict came back dangerous.
     *
     * Deliberately an annotation and nothing more: it does not hide, move or
     * click anything. A tool that silently rearranges somebody's inbox is a
     * tool they will uninstall, and being wrong about one message would then
     * mean losing it.
     */
    function flag(row, verdict, confidence) {
        if (!row || row.querySelector('.phishlens-flag')) return;
        const styles = {
            HIGH_RISK: { text: 'Dangerous', bg: '#b4232a' },
            SUSPICIOUS: { text: 'Suspicious', bg: '#a9701d' }
        };
        const style = styles[verdict];
        if (!style) return;

        const tag = document.createElement('span');
        tag.className = 'phishlens-flag';
        tag.textContent = `PhishLens: ${style.text}`;
        tag.title = `PhishLens examined this before you opened it — ${Math.round((confidence || 0) * 100)}% confident.`;
        tag.style.cssText = [
            `background:${style.bg}`, 'color:#fff', 'font-size:10px', 'font-weight:700',
            'padding:1px 6px', 'border-radius:3px', 'margin-right:6px',
            'vertical-align:middle', 'letter-spacing:0.02em', 'white-space:nowrap'
        ].join(';');

        const subject = row.querySelector('.bog') || row.querySelector('span');
        if (subject && subject.parentNode) subject.parentNode.insertBefore(tag, subject);
    }

    async function examine(entry, current) {
        const key = `${location.hostname}:${entry.id}`;
        if (SEEN.has(key)) return;
        remember(key);

        let raw = null;
        try {
            raw = await current.rawMessage(entry.id);
        } catch (e) {
            raw = null;
        }

        const payload = raw
            ? { source: location.hostname, provider_message_id: entry.id, raw, evidence: 'FULL_HEADERS' }
            : { source: location.hostname, provider_message_id: entry.id, evidence: 'BODY_ONLY', ...current.fallback(entry) };

        try {
            const result = await submit(payload);
            if (result && result.verdict) flag(entry.row, result.verdict, result.confidence);
        } catch (e) {
            // A backend that is not running must not fill the console of
            // somebody's mail client with noise on every poll.
            SEEN.delete(key);
        }
    }

    async function sweep() {
        if (!settings.enabled) return;
        const current = provider();
        if (!current) return;

        const visible = current.listVisible();
        // Unread first: those are the ones not yet opened, which is the whole
        // point of watching the list rather than the open message.
        visible.sort((a, b) => Number(b.unread) - Number(a.unread));

        for (const entry of visible.slice(0, 25)) {
            await examine(entry, current);
        }
    }

    function start() {
        ext.storage?.local.get(['browserWatchEnabled'], stored => {
            settings.enabled = stored.browserWatchEnabled !== false;
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
