const fs = require('fs');
const { dataFile } = require('./dataPaths');
const publicSuffix = require('./publicSuffix');

/**
 * Checks whether a message that presents itself as part of a conversation
 * really is one.
 *
 * This is the one detection that AI fluency cannot help an attacker with,
 * because the text is not the problem. In a hijacked thread the prose is
 * genuinely perfect - it is a real conversation, quoted verbatim, with real
 * names and real history. Nothing a language model reads will find fault with
 * it, and nothing about urgency or tone applies. What is wrong is structural:
 * the reply arrives from somewhere the conversation was never held, or
 * continues a thread this installation has never seen.
 *
 * Three shapes, in descending order of how often they are what they look like:
 *
 *   1. A reply whose sending identity differs from every earlier message in the
 *      thread. Either the account was compromised, or somebody is inserting
 *      themselves into a conversation they read elsewhere.
 *   2. A `Re:` subject with no thread headers at all. Real replies carry
 *      In-Reply-To; a client that writes "Re:" without one is rare, an attacker
 *      forging the appearance of history is not.
 *   3. A reply referencing a thread with no root this installation has ever
 *      observed. Weak on its own - PhishLens may simply not have been watching
 *      when the thread began - and it is scored accordingly.
 *
 * What the store holds is deliberately minimal: message ids, the sending
 * identity, and how that message authenticated. No subjects and no bodies. It
 * is an index for answering "has this conversation happened here", not a second
 * copy of the mail.
 */

const MAX_THREADS = 5000;

class ThreadIntegrity {
    constructor() {
        this.storageFile = dataFile('thread_index.json');
        /** message-id -> { thread, sender, senderDomain, auth, at } */
        this.messages = new Map();
        /** thread root id -> { participants: Set, messageIds: [], firstSeen } */
        this.threads = new Map();
        this.load();
    }

    load() {
        try {
            if (!fs.existsSync(this.storageFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '{}');
            (stored.messages || []).forEach(m => this.messages.set(m.id, m));
            (stored.threads || []).forEach(t => this.threads.set(t.root, {
                participants: new Set(t.participants || []),
                messageIds: t.messageIds || [],
                firstSeen: t.firstSeen
            }));
            console.log(`[ThreadIntegrity] Indexed ${this.messages.size} message(s) across ${this.threads.size} thread(s).`);
        } catch (e) {
            console.error('[ThreadIntegrity] Could not read the thread index:', e.message);
        }
    }

    save() {
        try {
            // Oldest threads are dropped first. An index that grows without
            // limit would eventually cost more to load than the signal is worth.
            const threads = [...this.threads.entries()]
                .sort((a, b) => new Date(b[1].firstSeen) - new Date(a[1].firstSeen))
                .slice(0, MAX_THREADS);

            const keep = new Set();
            threads.forEach(([, t]) => t.messageIds.forEach(id => keep.add(id)));

            fs.writeFileSync(this.storageFile, JSON.stringify({
                messages: [...this.messages.values()].filter(m => keep.has(m.id)),
                threads: threads.map(([root, t]) => ({
                    root,
                    participants: [...t.participants],
                    messageIds: t.messageIds,
                    firstSeen: t.firstSeen
                })),
                updated_at: new Date().toISOString()
            }, null, 2), 'utf8');
        } catch (e) {
            console.error('[ThreadIntegrity] Could not persist the thread index:', e.message);
        }
    }

    /**
     * Whether one domain is pretending to be another.
     *
     * Compares the registrable label rather than the whole domain, because
     * that is where the impersonation lives. `supplier.example` answered by
     * `supplier-invoices.test` is eleven edits apart as full domains - the
     * whole suffix differs - and the first version of this check therefore
     * missed the most obvious hijack shape there is. As labels, `supplier` and
     * `supplier-invoices`, one plainly contains the other.
     *
     * Two ways to resemble: one label contains the other (the common
     * `<brand>-invoices`, `<brand>-secure` pattern), or they are a small number
     * of edits apart (a typosquat or a character substitution).
     */
    resemblance(candidateDomain, knownDomain) {
        const candidate = this.registrableLabel(candidateDomain);
        const known = this.registrableLabel(knownDomain);
        if (!candidate || !known || candidate === known) {
            // Identical labels on different suffixes are still worth noting:
            // supplier.example answered by supplier.test is the same trick.
            if (candidate && candidate === known) {
                return { resembles: true, distance: 0, reason: 'uses the same name as' };
            }
            return { resembles: false };
        }

        const longer = candidate.length >= known.length ? candidate : known;
        const shorter = candidate.length >= known.length ? known : candidate;

        // Containment only counts when the contained label is substantial -
        // otherwise every domain containing "it" or "hr" matches something.
        if (shorter.length >= 4 && longer.includes(shorter)) {
            return { resembles: true, distance: longer.length - shorter.length, reason: 'is built around the name in' };
        }

        const distance = this.editDistance(candidate, known);
        const allowed = Math.max(1, Math.floor(known.length * 0.25));
        if (distance > 0 && distance <= allowed) {
            return { resembles: true, distance, reason: `is ${distance} character(s) from` };
        }

        return { resembles: false };
    }

    /**
     * The registered label - `supplier` from `supplier.co.uk` - using the
     * Public Suffix List so multi-label suffixes resolve correctly.
     */
    registrableLabel(domain) {
        if (!domain) return null;
        const registrable = publicSuffix.registrableDomain(domain);
        if (!registrable) return null;
        return registrable.split('.')[0] || null;
    }

    /** Levenshtein distance, for comparing a sender's domain with the thread's. */
    editDistance(a, b) {
        const rows = a.length + 1;
        const cols = b.length + 1;
        const dist = Array.from({ length: rows }, (_, i) => [i, ...Array(cols - 1).fill(0)]);
        for (let j = 0; j < cols; j++) dist[0][j] = j;
        for (let i = 1; i < rows; i++) {
            for (let j = 1; j < cols; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                dist[i][j] = Math.min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost);
            }
        }
        return dist[rows - 1][cols - 1];
    }

    normaliseId(id) {
        if (!id) return null;
        const trimmed = String(id).trim();
        return trimmed ? trimmed.replace(/^<|>$/g, '').toLowerCase() : null;
    }

    domainOf(address) {
        const match = String(address || '').match(/@([^\s@>]+)$/);
        return match ? match[1].toLowerCase() : null;
    }

    /**
     * The thread a message belongs to: the first entry in References, falling
     * back to In-Reply-To. Per RFC 5322 §3.6.4 the References chain runs oldest
     * first, so its head is the conversation's root.
     */
    threadRoot(parsedEmail) {
        const references = (parsedEmail?.references || []).map(r => this.normaliseId(r)).filter(Boolean);
        if (references.length) return references[0];
        return this.normaliseId(parsedEmail?.inReplyTo);
    }

    analyze(threatObject, parsedEmail) {
        const messageId = this.normaliseId(parsedEmail?.messageId);
        const inReplyTo = this.normaliseId(parsedEmail?.inReplyTo);
        const references = (parsedEmail?.references || []).map(r => this.normaliseId(r)).filter(Boolean);
        const subject = String(parsedEmail?.subject || threatObject?.message?.subject || '');
        const sender = String(parsedEmail?.from?.address || '').toLowerCase();
        const senderDomain = this.domainOf(sender);

        const claimsReply = /^\s*(re|fw|fwd)\s*:/i.test(subject);
        const hasThreadHeaders = !!(inReplyTo || references.length);
        const root = this.threadRoot(parsedEmail);

        const findings = [];
        let knownThread = null;

        if (root && this.threads.has(root)) {
            knownThread = this.threads.get(root);
            const participants = [...knownThread.participants];
            const isKnownParticipant = sender && knownThread.participants.has(sender);

            // A new participant is not by itself remarkable. In any two-party
            // exchange the second message is from somebody new, and the first
            // version of this check flagged exactly that - a supplier's
            // perfectly ordinary first reply. What matters is *which* new
            // participant.
            //
            // The strong case is an address whose domain closely resembles one
            // already in the conversation: sam@supplier.example answered by
            // sam@supplier-invoices.test is not a new correspondent joining,
            // it is one being impersonated.
            if (sender && !isKnownParticipant && senderDomain) {
                const impersonated = participants
                    .map(p => ({ address: p, domain: this.domainOf(p) }))
                    .filter(p => p.domain && p.domain !== senderDomain)
                    .map(p => ({ ...p, ...this.resemblance(senderDomain, p.domain) }))
                    .filter(p => p.resembles)
                    .sort((a, b) => a.distance - b.distance)[0];

                if (impersonated) {
                    findings.push({
                        type: 'LOOKALIKE_IDENTITY_IN_THREAD',
                        severity: 'HIGH',
                        detail: `This reply comes from ${sender}, whose domain ${impersonated.reason} ${impersonated.domain} - an address already in this conversation (${impersonated.address}). A correspondent being impersonated inside their own thread.`,
                        resembles: impersonated.address
                    });
                } else if (knownThread.messageIds.length >= 3 && participants.length >= 2) {
                    // Only once the conversation is established. Weaker, and
                    // deliberately so: people are added to threads all the time.
                    findings.push({
                        type: 'NEW_IDENTITY_IN_ESTABLISHED_THREAD',
                        severity: 'MEDIUM',
                        detail: `${sender} has not appeared in this thread before, which has run to ${knownThread.messageIds.length} messages between ${participants.slice(0, 3).join(', ')}. People are added to conversations routinely, so this is context rather than an accusation.`,
                        previous_participants: participants
                    });
                }
            }

            // Authentication that changes partway through a conversation.
            //
            // Compared against this sender's own earlier messages, not against
            // every message in the thread. The first version required *all*
            // prior messages to have passed, so a single unauthenticated
            // participant - or one injected message that got recorded -
            // disabled the check permanently.
            const senderHistory = knownThread.messageIds
                .map(id => this.messages.get(id))
                .filter(m => m && m.sender === sender && m.auth && m.auth !== 'unknown');

            const currentAuth = threatObject?.forensics?.authentication?.dmarc || 'unknown';
            if (senderHistory.length && currentAuth !== 'unknown'
                && senderHistory.some(m => m.auth === 'pass') && currentAuth !== 'pass') {
                findings.push({
                    type: 'AUTHENTICATION_CHANGED_MID_THREAD',
                    severity: 'HIGH',
                    detail: `Mail from ${sender} in this thread has authenticated before (dmarc=pass), and this message does not (dmarc=${currentAuth}). A correspondent whose mail normally passes does not usually start failing mid-conversation; a reply injected from outside it does.`
                });
            }
        }

        // A subject that says "Re:" with no In-Reply-To and no References.
        // Real mail clients write the headers; forging the appearance of
        // history without them is a deliberate act.
        if (claimsReply && !hasThreadHeaders) {
            findings.push({
                type: 'REPLY_WITHOUT_THREAD_HEADERS',
                severity: 'MEDIUM',
                detail: `The subject "${subject.slice(0, 60)}" presents this as a reply, but the message carries no In-Reply-To or References header. Genuine replies carry them; this borrows the credibility of a conversation that left no trace.`
            });
        }

        // Deliberately weak: the installation may simply not have been running
        // when the thread began. It corroborates, it does not convict.
        if (hasThreadHeaders && root && !knownThread) {
            findings.push({
                type: 'THREAD_NOT_PREVIOUSLY_SEEN',
                severity: 'LOW',
                detail: `This message continues a thread (${root.slice(0, 48)}) that PhishLens has not observed. That is expected for mail predating deployment, so it is recorded rather than treated as suspicious on its own.`
            });
        }

        threatObject.thread = {
            message_id: messageId,
            in_reply_to: inReplyTo,
            references,
            root,
            claims_to_be_reply: claimsReply,
            has_thread_headers: hasThreadHeaders,
            thread_known: !!knownThread,
            known_participants: knownThread ? [...knownThread.participants] : [],
            findings,
            limitation: 'Thread history covers only what this installation has observed. A newly deployed system knows no conversations, so these signals strengthen over time.'
        };

        return threatObject;
    }

    /**
     * Records the message so later replies can be checked against it.
     *
     * Called after a verdict, and deliberately not for high-risk mail: learning
     * a hijacker's address as a legitimate participant would make the next
     * message in that thread look normal.
     */
    record(threatObject, parsedEmail) {
        const messageId = this.normaliseId(parsedEmail?.messageId);
        if (!messageId) return;
        if (threatObject?.detection?.verdict === 'HIGH_RISK') return;

        const sender = String(parsedEmail?.from?.address || '').toLowerCase();
        const root = this.threadRoot(parsedEmail) || messageId;

        this.messages.set(messageId, {
            id: messageId,
            thread: root,
            sender,
            senderDomain: this.domainOf(sender),
            auth: threatObject?.forensics?.authentication?.dmarc || 'unknown',
            at: new Date().toISOString()
        });

        if (!this.threads.has(root)) {
            this.threads.set(root, { participants: new Set(), messageIds: [], firstSeen: new Date().toISOString() });
        }
        const thread = this.threads.get(root);
        if (sender) thread.participants.add(sender);
        if (!thread.messageIds.includes(messageId)) thread.messageIds.push(messageId);

        this.save();
    }

    state() {
        return {
            threads_indexed: this.threads.size,
            messages_indexed: this.messages.size,
            storage: this.storageFile
        };
    }
}

module.exports = new ThreadIntegrity();
