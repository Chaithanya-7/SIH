const fs = require('fs');
const { dataFile } = require('./dataPaths');

/**
 * Cases waiting to find out whether anybody followed the link.
 *
 * ## Why this exists at all
 *
 * A case is scored when the message arrives, which is before it has been read.
 * So the interesting fact - *this machine then went to the place the message
 * pointed at* - does not exist yet at the moment the verdict is written, and a
 * check performed at that moment can only ever come back empty.
 *
 * This holds the small number of cases where the answer would change what
 * somebody does, and the network observer's rolling memory is checked against
 * them until their window closes. A match turns "this looked dangerous" into
 * "this looked dangerous and, six minutes later, this machine connected to it",
 * which is the difference between a warning and an incident.
 *
 * ## What is deliberately not watched
 *
 * Only cases that came back HIGH_RISK or SUSPICIOUS, and only the hosts and
 * addresses those particular messages contained.
 *
 * That limit is the difference between a security tool and surveillance.
 * Enrolling every case would mean holding a list of every destination every
 * message ever mentioned and matching all of it against everywhere the machine
 * goes - which is a record of somebody's browsing, assembled for no benefit,
 * since a connection to a host from a message that was already judged safe
 * tells nobody anything.
 *
 * ## What a match does and does not mean
 *
 * It means traffic from this machine went to a destination this message named,
 * inside the window. It does not identify who, or which application: the capture
 * observes the machine, not the browser, and a shared machine has more than one
 * person on it. So a match is recorded as a connection observed, never as "the
 * user clicked the link".
 *
 * And absence means nothing at all. An entry that expires unmatched is recorded
 * as unmatched, not as safe - the observer may not have been running, the
 * resolver may be using DNS-over-HTTPS, the link may have been opened on a
 * phone.
 */

/** Cases stop being interesting once nothing could still be caused by them. */
const DEFAULT_WINDOW_MS = 30 * 60 * 1000;

/** A bound, so a burst of mail cannot turn this into an unbounded list. */
const MAX_ENTRIES = 500;

/** Verdicts worth following up. A safe case's destinations are nobody's business. */
const WATCHED_VERDICTS = new Set(['HIGH_RISK', 'SUSPICIOUS']);

class ConnectionWatchlist {
    constructor() {
        this.storageFile = dataFile('connection_watchlist.json');
        /** case_id -> entry */
        this.entries = new Map();
        this.load();
    }

    load() {
        try {
            if (!fs.existsSync(this.storageFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '{}');
            (stored.entries || []).forEach(entry => {
                if (entry?.case_id) this.entries.set(entry.case_id, entry);
            });
            // Anything already past its window is dropped on the way in rather
            // than being carried forward to be swept later.
            this.expire();
            console.log(`[ConnectionWatchlist] ${this.entries.size} case(s) awaiting a connection check.`);
        } catch (e) {
            console.error('[ConnectionWatchlist] Could not read the watchlist:', e.message);
        }
    }

    save() {
        try {
            fs.writeFileSync(this.storageFile, JSON.stringify({
                entries: Array.from(this.entries.values()),
                saved_at: new Date().toISOString()
            }, null, 2));
        } catch (e) {
            console.error('[ConnectionWatchlist] Could not write the watchlist:', e.message);
        }
    }

    /**
     * The hosts and addresses worth watching for, from one case.
     *
     * Hostnames rather than full URLs: what a capture can see is a DNS question
     * and a TLS server name, so a path would never match anything.
     */
    indicatorsFor(threatObject) {
        const indicators = new Set();

        for (const url of (threatObject.iocs?.urls || [])) {
            try {
                const host = new URL(url).hostname.toLowerCase();
                if (host) indicators.add(host);
            } catch (e) {
                // Not a parseable URL; the domain list below covers the rest.
            }
        }
        for (const domain of (threatObject.iocs?.domains || [])) {
            const value = String(domain || '').trim().toLowerCase();
            if (value) indicators.add(value);
        }
        for (const ip of (threatObject.iocs?.ips || [])) {
            const value = String(ip || '').trim();
            if (value) indicators.add(value);
        }

        return Array.from(indicators);
    }

    /**
     * Whether a case is worth following up, decided without inserting it.
     *
     * Split from `enrol` because of an ordering problem. The case has to carry
     * the decision *before* it is written to storage, or the stored case shows
     * nothing about whether a connection check is pending. But the entry has to
     * be keyed on the case id that was actually stored - `saveCase` can reassign
     * one on collision, and an entry keyed to an id no case has would quietly
     * never resolve.
     *
     * So the pipeline decides here, records the status on the case, saves, and
     * then enrols with the id that survived.
     *
     * Returns the reason when the answer is no, so the case can say "no
     * destinations to watch for" rather than leaving a silence that reads as a
     * check having happened.
     */
    decide(threatObject) {
        const verdict = threatObject.detection?.verdict;
        if (!WATCHED_VERDICTS.has(verdict)) {
            return { watch: false, reason: `Only high-risk and suspicious cases are followed up; this one is ${verdict || 'unscored'}.` };
        }

        const indicators = this.indicatorsFor(threatObject);
        if (!indicators.length) {
            return { watch: false, reason: 'The message named no host or address that a connection could be matched against.' };
        }

        return { watch: true, verdict, indicators };
    }

    /** Adds a decided case to the list, keyed on the id it was stored under. */
    enrol(threatObject, decision, { windowMs = DEFAULT_WINDOW_MS } = {}) {
        const resolved = decision && decision.watch ? decision : this.decide(threatObject);
        if (!resolved.watch) return { enrolled: false, reason: resolved.reason };

        const { verdict, indicators } = resolved;

        const receivedAt = threatObject.message?.delivered_at
            || threatObject.timestamps?.ingested_at
            || new Date().toISOString();

        const entry = {
            case_id: threatObject.case_id,
            verdict,
            indicators,
            received_at: receivedAt,
            enrolled_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + windowMs).toISOString(),
            window_ms: windowMs,
            checks: 0,
            matched: false
        };

        this.entries.set(entry.case_id, entry);

        // Oldest first, so a burst of mail evicts what was already nearly
        // expired rather than what just arrived.
        if (this.entries.size > MAX_ENTRIES) {
            const ordered = Array.from(this.entries.values())
                .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));
            for (const stale of ordered.slice(0, this.entries.size - MAX_ENTRIES)) {
                this.entries.delete(stale.case_id);
            }
        }

        this.save();
        return { enrolled: true, indicators: indicators.length, expires_at: entry.expires_at };
    }

    /** Drops entries whose window has closed, and reports which they were. */
    expire() {
        const now = Date.now();
        const expired = [];
        for (const [caseId, entry] of this.entries) {
            if (Date.parse(entry.expires_at) <= now) {
                expired.push(entry);
                this.entries.delete(caseId);
            }
        }
        return expired;
    }

    pending() {
        return Array.from(this.entries.values());
    }

    remove(caseId) {
        const had = this.entries.delete(caseId);
        if (had) this.save();
        return had;
    }

    state() {
        return {
            awaiting_check: this.entries.size,
            window_minutes: Math.round(DEFAULT_WINDOW_MS / 60000),
            watched_verdicts: Array.from(WATCHED_VERDICTS),
            storage: this.storageFile,
            scope: 'Only hosts and addresses named by messages already judged high-risk or suspicious. Nothing else is matched against.'
        };
    }
}

module.exports = new ConnectionWatchlist();
module.exports.ConnectionWatchlist = ConnectionWatchlist;
module.exports.DEFAULT_WINDOW_MS = DEFAULT_WINDOW_MS;
module.exports.WATCHED_VERDICTS = WATCHED_VERDICTS;
