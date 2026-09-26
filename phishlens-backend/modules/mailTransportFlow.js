/**
 * Each message projected as a transport flow, the way a packet analyser lists
 * traffic: a sequence number, where it came from, where it went, the ports and
 * protocol involved, and a one-line summary.
 *
 * ## The honesty problem this shape creates
 *
 * A Wireshark-style list carries an implicit promise: every column is something
 * actually observed on the wire. Mail is not packets, and most of a message's
 * journey happened before PhishLens existed - so several of those columns have
 * no honest value for most messages.
 *
 * Ports are the sharpest case. A `Received:` header is free text written by
 * whichever MTA handled the message, and the overwhelming majority do not record
 * a port at all. Some Exchange builds write `port 25`; Google does not. So a port
 * column filled in for every row would be fabricated for most of them, and
 * fabricated data in a forensic view is worse than a blank - somebody would
 * quote it.
 *
 * Every field here therefore resolves to a real value or to null, and null
 * renders as a dash. What *is* genuinely known:
 *
 *   - **Source**: the origin address the relay reconstruction selected, with the
 *     hostname the sending MTA announced.
 *   - **Destination**: the receiving gateway that accepted the message, taken
 *     from the trusted-receiver hop, or the recipient's domain when no hop
 *     identifies one.
 *   - **Protocol**: from the `with` clause of the Received header (SMTP, ESMTP,
 *     ESMTPS, LMTP...) where present, otherwise from how the message reached
 *     this installation, which is a fact this system owns.
 *   - **Destination port**: the port PhishLens itself listened on for that
 *     channel. For the SMTP gateway that is a real number; for a message read
 *     out of a browser there is no port and the field stays empty.
 *   - **Source port**: only ever from a header that stated one.
 *   - **Length**: the raw message size where it was recorded.
 *
 * ## Why this is computed here and not stored on the case
 *
 * Projecting at read time means every case gets this view, including the
 * thousands already stored, with no migration and no re-analysis. It is a
 * different presentation of facts already held, not a new finding, so it has no
 * business being written into the evidence.
 */

/** What each ingestion channel actually is, in transport terms. */
const CHANNEL_TRANSPORT = {
    SMTP_GATEWAY: { protocol: 'SMTP', port: 2525, note: 'Delivered to the PhishLens SMTP listener' },
    BROWSER: { protocol: 'HTTPS', port: null, note: 'Read from webmail in the browser, over the session already signed in' },
    IMAP: { protocol: 'IMAP', port: 993, note: 'Fetched from an IMAP mailbox' },
    GMAIL_API: { protocol: 'HTTPS', port: 443, note: 'Pulled through the Gmail API' },
    REST: { protocol: 'HTTP', port: null, note: 'Submitted to the analysis API' },
    FILE: { protocol: 'FILE', port: null, note: 'Uploaded as a message file' }
};

/** Verdict to the three colours a row can carry. */
const VERDICT_COLOUR = {
    HIGH_RISK: { colour: 'RED', severity: 'HIGH', label: 'Dangerous' },
    SUSPICIOUS: { colour: 'YELLOW', severity: 'MEDIUM', label: 'Suspicious' },
    SAFE: { colour: 'GREEN', severity: 'LOW', label: 'Legitimate' }
};

class MailTransportFlow {
    /** Which channel a case arrived by, from the source label the pipeline recorded. */
    channelOf(caseItem) {
        const source = String(caseItem.message?.source || caseItem.mailbox_provenance?.provider || '').toUpperCase();

        if (source.includes('SMTP')) return 'SMTP_GATEWAY';
        if (source.includes('BROWSER')) return 'BROWSER';
        if (source.includes('IMAP')) return 'IMAP';
        if (source.includes('GMAIL')) return 'GMAIL_API';
        if (source.includes('FILE') || source.includes('UPLOAD')) return 'FILE';
        return 'REST';
    }

    /**
     * The protocol and port a Received header actually stated.
     *
     * Returns nulls rather than guesses. `with ESMTPS` is common and real;
     * `port 25` is written by some MTAs and by no means all.
     */
    fromReceivedHeader(caseItem) {
        const hops = caseItem.forensics?.smtp_relay || [];
        const raw = hops.map(h => h.raw || h.trust_explanation || '').join(' ');

        const withClause = raw.match(/\bwith\s+(E?SMTPS?A?|LMTP|HTTP|HTTPS|MAPI|ESMTPSA)\b/i);
        const portClause = raw.match(/\bport\s+(\d{1,5})\b/i);

        return {
            protocol: withClause ? withClause[1].toUpperCase() : null,
            port: portClause ? Number(portClause[1]) : null
        };
    }

    /** The gateway that accepted the message, or the recipient's domain. */
    destinationOf(caseItem) {
        const hops = caseItem.forensics?.smtp_relay || [];
        const receiver = hops.find(h => h.classification === 'TRUSTED_RECEIVER');

        if (receiver) {
            return {
                address: receiver.ip && receiver.ip !== 'UNAVAILABLE' ? receiver.ip : null,
                host: receiver.hostname || receiver.host || null,
                from: 'the receiving gateway named in the message headers'
            };
        }

        const recipient = String(caseItem.message?.recipient || '');
        const domain = recipient.split('@')[1]?.replace(/[>,\s].*$/, '') || null;
        return {
            address: null,
            host: domain,
            from: domain ? "the recipient's domain, since no hop identified a receiving gateway" : 'not determinable from this message'
        };
    }

    /** Where the message came from, as the relay reconstruction selected it. */
    sourceOf(caseItem) {
        const ip = caseItem.infrastructure?.origin_ip
            || caseItem.infrastructure?.origin?.origin_ip
            || null;

        const hops = caseItem.forensics?.smtp_relay || [];
        const originHop = hops.find(h => h.ip && h.ip === ip) || hops.find(h => h.is_public);

        const geo = (caseItem.infrastructure?.geo_points || []).find(p => p.ip === ip);

        return {
            address: ip && ip !== 'UNAVAILABLE' ? ip : null,
            host: originHop?.hostname || originHop?.host || null,
            country: geo?.country || caseItem.infrastructure?.geo?.country || null,
            country_code: geo?.country_code || null,
            asn: geo?.asn || null
        };
    }

    /**
     * The summary line, built the way a packet analyser builds one: the most
     * consequential thing about this row, in the fewest words.
     */
    infoOf(caseItem, verdict) {
        const parts = [];

        const rules = caseItem.detection?.matched_rules || [];
        const evidence = (caseItem.evidence || [])
            .slice()
            .sort((a, b) => (b.signal_strength || 0) - (a.signal_strength || 0));

        if (verdict === 'SAFE') {
            const passed = caseItem.assurance?.passed;
            parts.push(passed ? `${passed} checks clean` : 'No findings');
        } else if (evidence[0]?.finding) {
            parts.push(evidence[0].finding);
        } else if (rules[0]?.name) {
            parts.push(rules[0].name);
        } else {
            parts.push(verdict === 'HIGH_RISK' ? 'High risk' : 'Suspicious');
        }

        if (rules.length > 1) parts.push(`+${rules.length - 1} more rule(s)`);

        const attachments = (caseItem.attachments || []).length;
        if (attachments) parts.push(`${attachments} attachment(s)`);

        // A confirmed connection is the single most important thing that can be
        // on a row, so it goes last where a reader's eye finishes.
        if (caseItem.connection_evidence?.status === 'OBSERVED') {
            parts.push('CONNECTION OBSERVED');
        }

        return parts.join(' · ');
    }

    /**
     * The hop chain, for the detail view a packet analyser opens beneath the
     * list. One entry per relay, in the order the message travelled.
     */
    framesOf(caseItem) {
        const hops = caseItem.forensics?.smtp_relay || [];

        const frames = hops.map((hop, index) => ({
            index: index + 1,
            address: hop.ip && hop.ip !== 'UNAVAILABLE' ? hop.ip : null,
            host: hop.hostname || hop.host || null,
            classification: hop.classification || null,
            trust_level: hop.trust_level ?? null,
            explanation: hop.trust_explanation || null,
            at: hop.timestamp || null,
            is_public: hop.is_public ?? null
        }));

        // The last leg is the one this system witnessed itself, and it is the
        // only one whose protocol and port are not somebody else's claim.
        const channel = CHANNEL_TRANSPORT[this.channelOf(caseItem)];
        frames.push({
            index: frames.length + 1,
            address: null,
            host: 'PhishLens',
            classification: 'INGESTED_HERE',
            trust_level: 1,
            explanation: channel.note,
            protocol: channel.protocol,
            port: channel.port,
            at: caseItem.timestamps?.ingested_at || null,
            observed_by_us: true
        });

        return frames;
    }

    /** One row. */
    project(caseItem, sequence) {
        const verdict = caseItem.detection?.verdict || 'UNKNOWN';
        const colour = VERDICT_COLOUR[verdict] || { colour: 'GREY', severity: 'UNKNOWN', label: 'Not scored' };

        const channelKey = this.channelOf(caseItem);
        const channel = CHANNEL_TRANSPORT[channelKey];
        const header = this.fromReceivedHeader(caseItem);
        const source = this.sourceOf(caseItem);
        const destination = this.destinationOf(caseItem);

        return {
            no: sequence,
            case_id: caseItem.case_id,
            // The coloured ball: red, yellow or green, from the verdict.
            colour: colour.colour,
            severity: colour.severity,
            verdict,
            verdict_label: colour.label,
            time: caseItem.message?.delivered_at || caseItem.timestamps?.ingested_at || null,
            name: caseItem.message?.subject || '(no subject)',
            sender: caseItem.message?.sender || null,
            recipient: caseItem.message?.recipient || null,

            source: source.address,
            source_host: source.host,
            source_country: source.country,
            source_country_code: source.country_code,
            source_asn: source.asn,
            // Only ever from a header that stated one. Most do not.
            source_port: header.port,

            destination: destination.address,
            destination_host: destination.host,
            destination_basis: destination.from,
            // The port this installation listened on, which is a fact it owns.
            destination_port: channel.port,

            // The header's own word for it where there is one, otherwise the
            // transport this system actually used.
            protocol: header.protocol || channel.protocol,
            protocol_basis: header.protocol ? 'stated in the message headers' : 'how the message reached PhishLens',
            channel: channelKey,

            length: caseItem.message?.size_bytes ?? null,
            confidence: caseItem.confidence?.threat ?? null,
            info: this.infoOf(caseItem, verdict),

            // Extra columns worth having, since they are the reason this is a
            // mail tool and not a packet analyser.
            attachments: (caseItem.attachments || []).length,
            rules_matched: (caseItem.detection?.matched_rules || []).length,
            connection_observed: caseItem.connection_evidence?.status === 'OBSERVED',
            analysis_mode: caseItem.analysis_mode?.mode || 'LIVE',

            frames: this.framesOf(caseItem)
        };
    }

    /**
     * Every case as a flow list, oldest first so sequence numbers run the way
     * they do in a capture: number one is the first thing seen.
     */
    projectAll(cases) {
        return cases
            .slice()
            .sort((a, b) => {
                const at = Date.parse(a.timestamps?.ingested_at || a.message?.delivered_at || 0) || 0;
                const bt = Date.parse(b.timestamps?.ingested_at || b.message?.delivered_at || 0) || 0;
                return at - bt;
            })
            .map((caseItem, index) => this.project(caseItem, index + 1));
    }

    /** What the columns mean and where each value came from, for the UI to show. */
    columnProvenance() {
        return {
            source_port: 'Only shown when a Received header stated one. Most mail servers do not record it, so this is usually empty - it is never inferred.',
            destination_port: 'The port PhishLens itself listened on for this channel. Empty where the channel has no port, such as mail read in a browser.',
            protocol: 'From the "with" clause of a Received header where present, otherwise the transport this message actually arrived over.',
            destination: 'The receiving gateway named in the headers, or the recipient domain when no hop identifies one.',
            length: 'The raw message size where it was recorded.',
            colour: 'Red is high risk, yellow is suspicious, green is legitimate.'
        };
    }
}

module.exports = new MailTransportFlow();
module.exports.MailTransportFlow = MailTransportFlow;
module.exports.CHANNEL_TRANSPORT = CHANNEL_TRANSPORT;
module.exports.VERDICT_COLOUR = VERDICT_COLOUR;
