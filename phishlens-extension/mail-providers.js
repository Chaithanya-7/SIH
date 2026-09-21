/**
 * How to read each webmail: where the messages are, and how to get the original.
 *
 * Kept apart from the watcher that drives it for two reasons. Reading a message
 * list and deciding when to sweep are genuinely different jobs, and separating
 * them means the reading can be exercised against a fixture without pretending
 * to be Gmail - the watcher only runs when the hostname matches, which made the
 * part most likely to be wrong the part hardest to test.
 *
 * These selectors are the assumption this whole channel rests on. Providers
 * change their markup without notice, so each provider reports what it found
 * and the watcher treats "no rows" as a condition worth surfacing rather than
 * as an empty inbox.
 */

(() => {
    'use strict';

    const gmail = {
        id: 'gmail',
        label: 'Gmail',
        matches: hostname => hostname === 'mail.google.com',

        /**
         * Message rows in the current list.
         *
         * Gmail marks each row with `data-legacy-message-id`, falling back to a
         * thread id. Reading an attribute is far steadier than matching class
         * names, which are generated and change between releases - though `zA`
         * for a row and `zE` for unread have been stable for years.
         */
        listVisible(doc) {
            const rows = doc.querySelectorAll('tr.zA, div[role="listitem"][data-legacy-message-id]');
            const found = [];
            rows.forEach(row => {
                const id = this.identify(row);
                if (!id) return;
                const label = row.getAttribute('aria-label') || '';
                found.push({
                    id,
                    unread: row.classList.contains('zE') || /(^|,\s*)unread/i.test(label),
                    row
                });
            });
            return found;
        },

        /**
         * The identifier for one row, wherever Gmail has put it.
         *
         * This looked only at the row element, and Gmail carries these
         * attributes on a span *inside* the row. Every row was therefore found
         * and then silently dropped for having no id, so a full inbox reported
         * as an empty list - which is indistinguishable from the reader not
         * matching the page at all.
         */
        identify(row) {
            const ATTRIBUTES = ['data-legacy-message-id', 'data-legacy-thread-id', 'data-thread-id'];

            for (const attribute of ATTRIBUTES) {
                const own = row.getAttribute(attribute);
                if (own) return String(own).replace(/^#/, '').replace(/^thread-[fa]:/, '');
            }

            // Then anywhere inside it.
            const carrier = row.querySelector('[' + ATTRIBUTES.join('],[') + ']');
            if (carrier) {
                for (const attribute of ATTRIBUTES) {
                    const value = carrier.getAttribute(attribute);
                    if (value) return String(value).replace(/^#/, '').replace(/^thread-[fa]:/, '');
                }
            }

            // Gmail also puts a thread id on the row's own id attribute in some
            // views, as ":123" or "thread-f:456".
            const elementId = row.getAttribute('id');
            if (elementId && /\d/.test(elementId)) return elementId.replace(/^#/, '').replace(/^thread-[fa]:/, '');

            return null;
        },

        /** How many rows were on the page, regardless of whether any could be identified. */
        countRows(doc) {
            return doc.querySelectorAll('tr.zA, div[role="listitem"][data-legacy-message-id]').length;
        },

        /** The account index in the URL, so a second signed-in account is not read as the first. */
        userIndex(loc) {
            const m = (loc.pathname || '').match(/\/mail\/u\/(\d+)/);
            return m ? m[1] : '0';
        },

        /**
         * Gmail's own "show original" address for one message.
         *
         * Built rather than fetched here so it can be checked without a session.
         */
        rawUrl(id, loc, ik) {
            if (!ik) return null;
            return `${loc.origin}/mail/u/${this.userIndex(loc)}/?ik=${encodeURIComponent(ik)}`
                + `&view=om&permmsgid=msg-f:${encodeURIComponent(id)}`;
        },

        /** The per-session key Gmail embeds in the page, needed by the address above. */
        inboxKey(doc) {
            const html = doc.documentElement.innerHTML;
            const m = html.match(/["']ik["']\s*:\s*["']([^"']+)["']/) || html.match(/[?&]ik=([A-Za-z0-9_-]+)/);
            return m ? m[1] : null;
        },

        /**
         * Whether a response is really an RFC 822 message.
         *
         * The endpoint answers with a sign-in page once the session lapses, and
         * that parses as a message with no headers - which would be analysed as
         * one, and would look like mail that failed every authentication check.
         */
        looksLikeRawMessage(text) {
            if (!text || text.length < 40) return false;
            if (/^\s*<(!doctype|html)/i.test(text.slice(0, 200))) return false;
            return /^(from|received|message-id|subject|return-path):/im.test(text);
        },

        /** What the row itself carries, when the original cannot be fetched. */
        fallback(entry) {
            const row = entry.row;
            const senderEl = row.querySelector('span[email]') || row.querySelector('.gD') || row.querySelector('.yW span');
            return {
                subject: row.querySelector('.bog')?.textContent?.trim() || '',
                sender: senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || '',
                snippet: row.querySelector('.y2')?.textContent?.replace(/^\s*-\s*/, '').trim() || ''
            };
        },

        /** Where to put a warning label on the row. */
        labelAnchor(row) {
            return row.querySelector('.bog') || row.querySelector('span');
        }
    };

    const outlook = {
        id: 'outlook',
        label: 'Outlook Web',
        matches: hostname => /^outlook\.(live|office|office365)\.com$/.test(hostname),

        listVisible(doc) {
            const rows = doc.querySelectorAll('div[data-convid]');
            return Array.from(rows).map(row => ({
                id: row.getAttribute('data-convid'),
                unread: /unread/i.test(row.getAttribute('aria-label') || ''),
                row
            })).filter(entry => entry.id);
        },

        // Outlook Web exposes no equivalent of "show original" at a stable
        // address, so this channel works from the row alone and says so.
        rawUrl() { return null; },
        inboxKey() { return null; },
        looksLikeRawMessage() { return false; },

        fallback(entry) {
            const row = entry.row;
            const spans = Array.from(row.querySelectorAll('span')).map(s => s.textContent.trim()).filter(Boolean);
            return {
                subject: spans[1] || '',
                sender: spans[0] || '',
                snippet: (spans[2] || row.textContent || '').slice(0, 400).trim()
            };
        },

        labelAnchor(row) {
            return row.querySelector('span');
        }
    };

    const providers = [gmail, outlook];

    globalThis.PhishLensMailProviders = {
        all: providers,
        forHostname: hostname => providers.find(p => p.matches(hostname)) || null,
        gmail,
        outlook
    };
})();
