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
            const found = [];
            const seen = new Set();

            for (const row of this.findRows(doc)) {
                const id = this.identify(row);
                if (!id || seen.has(id)) continue;
                seen.add(id);
                const label = row.getAttribute('aria-label') || '';
                found.push({
                    id,
                    unread: row.classList.contains('zE') || /(^|,\s*)unread/i.test(label),
                    row
                });
            }
            return found;
        },

        /**
         * The message rows on the page, found without depending on a class name.
         *
         * The reader used to search for `tr.zA`, the class Gmail had used for a
         * row for years. It stopped matching, and the result was a 2,267-message
         * inbox reported as "found no messages in the list" - which reads as an
         * empty inbox rather than as a broken reader.
         *
         * A class name is the wrong thing to depend on. Gmail generates most of
         * them and is free to change any of them in a release nobody announces.
         *
         * So the search is inverted. Rather than finding rows and then looking
         * for an identifier inside each, it finds the elements *carrying* a
         * message or thread identifier - which Gmail must publish somewhere for
         * its own code to work - and climbs to the row that contains each. That
         * survives every class rename, and it fails only if Gmail stops
         * publishing identifiers in the DOM at all, which would be a far larger
         * change than a restyle.
         *
         * The class-based selector is kept as a first pass because it is exact
         * and cheap when it works.
         */
        findRows(doc) {
            const byClass = Array.from(doc.querySelectorAll('tr.zA, div[role="listitem"][data-legacy-message-id]'));
            if (byClass.length) return byClass;

            const ID_ATTRIBUTES = ['data-legacy-message-id', 'data-legacy-thread-id', 'data-thread-id'];
            const carriers = doc.querySelectorAll('[' + ID_ATTRIBUTES.join('],[') + ']');

            const rows = [];
            const seen = new Set();

            for (const carrier of carriers) {
                // The row that holds this identifier. A table row or an
                // explicit list item where one exists, and otherwise the
                // nearest ancestor that looks like a row of a list.
                const row = carrier.closest('tr, [role="listitem"], [role="row"]') || carrier.parentElement || carrier;
                if (!row || seen.has(row)) continue;

                // A carrier in the reading pane or a menu is not a list row.
                // Requiring an ancestor list keeps those out without naming a
                // single class.
                if (!row.closest('[role="list"], [role="grid"], [role="main"], table')) continue;

                seen.add(row);
                rows.push(row);
            }

            if (rows.length) return rows;

            // Last resort: find the rows by shape.
            //
            // Both strategies above assume Gmail publishes an identifier in the
            // DOM. It always has, and if it ever stops, everything above finds
            // nothing and the inbox reads as empty again - the exact failure
            // this reader has already had once.
            //
            // A message list has a shape no restyle changes: many sibling
            // elements, of the same kind, inside the main region, each carrying
            // several pieces of text. That is enough to find the rows; the
            // identifier is then derived from what each row displays, which
            // `identify()` already falls back to.
            return this.findRowsByShape(doc);
        },

        /**
         * Rows found by structure alone, for when no identifier is published.
         *
         * Deliberately conservative. It takes the largest group of same-kind
         * siblings inside the main region, and only when there are at least
         * three of them - a list of one or two is far more likely to be a
         * toolbar or a banner than an inbox.
         */
        findRowsByShape(doc) {
            const containers = doc.querySelectorAll('[role="main"] [role="list"], [role="main"] [role="grid"], [role="main"] table, [role="list"], [role="grid"]');
            let best = [];

            for (const container of containers) {
                const groups = new Map();

                for (const child of container.querySelectorAll('tr, [role="listitem"], [role="row"]')) {
                    // Grouped by parent and tag, so rows of one list are not
                    // mixed with rows of another that happens to be nested.
                    const key = `${child.tagName}:${child.getAttribute('role') || ''}`;
                    const parent = child.parentElement;
                    if (!parent) continue;

                    const groupKey = key + ':' + (parent.id || parent.className || '') + ':' + Array.from(container.children).indexOf(parent);
                    if (!groups.has(groupKey)) groups.set(groupKey, []);
                    groups.get(groupKey).push(child);
                }

                for (const group of groups.values()) {
                    // A row shows several things: who it is from, what it is
                    // about, when it arrived. One text node is a heading.
                    const substantial = group.filter(row => {
                        const text = (row.textContent || '').trim();
                        return text.length > 12 && row.children.length >= 2;
                    });
                    if (substantial.length >= 3 && substantial.length > best.length) best = substantial;
                }
            }

            return best;
        },

        /**
         * What the reader can see, for when it can see nothing.
         *
         * "Found no messages in the list" gives nobody anything to act on, and
         * it is the report that matters most because it means the reader no
         * longer matches the page. This says which strategy matched, and when
         * none did, what identifier-bearing attributes exist on the page at all
         * - which is the fact needed to widen the reader without guessing.
         */
        describeReader(doc) {
            const byClass = doc.querySelectorAll('tr.zA, div[role="listitem"][data-legacy-message-id]').length;
            const ID_ATTRIBUTES = ['data-legacy-message-id', 'data-legacy-thread-id', 'data-thread-id'];
            const carriers = doc.querySelectorAll('[' + ID_ATTRIBUTES.join('],[') + ']').length;
            const rows = this.findRows(doc).length;

            // A short census of data-attributes actually present, so a reader
            // that matches nothing can still report what the page does carry.
            const attributes = new Map();
            let scanned = 0;
            for (const el of doc.querySelectorAll('[role="listitem"], [role="row"], tr')) {
                if (scanned++ > 400) break;
                for (const attribute of el.getAttributeNames ? el.getAttributeNames() : []) {
                    if (!attribute.startsWith('data-')) continue;
                    attributes.set(attribute, (attributes.get(attribute) || 0) + 1);
                }
            }

            return {
                matched_by: byClass ? 'class selector' : (rows ? 'identifier attributes' : 'nothing'),
                rows_by_class: byClass,
                identifier_carriers: carriers,
                rows_found: rows,
                row_like_elements: scanned,
                data_attributes_seen: Array.from(attributes.entries())
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 8)
                    .map(([name, count]) => `${name} (${count})`)
            };
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

            // Nothing Gmail publishes as an identifier is here any more.
            //
            // Rather than drop the row - which is what silently emptied a full
            // inbox once - derive one from what the row says. Sender, subject
            // and time together identify a message well enough to deduplicate
            // it across sweeps, which is all this id is for; the backend
            // deduplicates properly on the raw message afterwards.
            //
            // Marked so it is never mistaken for Gmail's own id.
            const derived = this.deriveId(row);
            return derived ? 'derived-' + derived : null;
        },

        /** A stable identifier built from what the row displays, when Gmail publishes none. */
        deriveId(row) {
            const text = [
                row.querySelector('span[email]')?.getAttribute('email') || '',
                row.querySelector('.bog')?.textContent || '',
                row.querySelector('.xW span')?.getAttribute('title') || row.querySelector('.xW span')?.textContent || ''
            ].join('|').trim();

            if (text.length < 3) return null;

            // A small, stable hash. Not cryptographic - it only has to be the
            // same string every sweep and different between messages.
            let hash = 5381;
            for (let i = 0; i < text.length; i++) hash = ((hash * 33) ^ text.charCodeAt(i)) >>> 0;
            return hash.toString(36);
        },

        /** How many rows were on the page, regardless of whether any could be identified. */
        countRows(doc) {
            return this.findRows(doc).length;
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

        /**
         * The address of a numbered page of the list, for a backlog scan.
         *
         * Gmail pages the list through the fragment - `#inbox` is the first
         * page and `#inbox/p2` onward are the rest - which is what makes
         * walking a whole mailbox possible without touching an internal API or
         * scrolling a virtualised list fifty rows at a time.
         *
         * Only implemented here. Outlook Web pages differently, and a
         * `pageHash` that guessed at it would produce a scan that silently
         * read the first page over and over and reported a whole mailbox
         * examined. The backlog scanner checks for this function and says
         * plainly that it cannot scan a provider that lacks one.
         */
        pageHash(pageNumber) {
            const n = Number(pageNumber);
            if (!Number.isFinite(n) || n < 1) return null;
            return n === 1 ? '#inbox' : `#inbox/p${n}`;
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
