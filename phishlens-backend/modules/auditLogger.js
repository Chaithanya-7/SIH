const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AuditEvent = require('../models/AuditEvent');

/**
 * Tamper-evident audit ledger.
 *
 * Each entry carries a SHA-256 over its own contents plus the hash of the entry
 * before it, so the log forms a chain. Altering or removing any historical
 * entry breaks every hash after it, and the break is detectable without needing
 * a copy of the original. This does not make the log tamper-*proof* - anyone
 * who can write the file can also recompute the whole chain - but it does mean
 * a quiet edit of one record cannot pass unnoticed, which is what an audit
 * trail is for.
 *
 * Two changes were needed to make chaining meaningful:
 *
 *   Entries are appended in chronological order rather than prepended, because
 *   a chain has to run in the direction it was written.
 *
 *   Old entries are archived rather than discarded. The previous
 *   implementation dropped the oldest record once 500 had accumulated, which
 *   silently destroyed the earliest history - exactly the part an investigator
 *   is most likely to need - and would have severed the chain.
 */

const GENESIS_HASH = '0'.repeat(64);
const ACTIVE_LIMIT = 2000;

class AuditLogger {
    constructor() {
        this.logFile = path.join(__dirname, '../data/audit_log.json');
        this.archiveFile = path.join(__dirname, '../data/audit_log_archive.jsonl');
        this.events = [];
        this.initStorage();
    }

    initStorage() {
        try {
            const dataDir = path.dirname(this.logFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.logFile)) return;

            const raw = fs.readFileSync(this.logFile, 'utf8');
            const stored = JSON.parse(raw || '[]');

            // A log written before chaining existed has no hashes. It is kept and
            // chained from here on rather than discarded, and reported as
            // unverifiable for the period before chaining began.
            this.events = Array.isArray(stored) ? stored : [];
            const unchained = this.events.filter(e => !e.entry_hash).length;
            if (unchained) {
                console.warn(`[AuditLogger] ${unchained} pre-existing event(s) carry no chain hash and cannot be verified. Chaining applies to entries recorded from now on.`);
            }

            const verification = this.verifyChain();
            if (!verification.intact && verification.checked > 0) {
                console.error(`[AuditLogger] AUDIT CHAIN BROKEN at entry ${verification.broken_at}: ${verification.reason}`);
            }
        } catch (e) {
            console.error('[AuditLogger] Storage init error:', e.message);
        }
    }

    /** The canonical serialisation a hash is taken over. Field order is fixed. */
    canonicalForm(event, previousHash) {
        return JSON.stringify({
            sequence: event.sequence,
            timestamp: event.timestamp,
            case_id: event.case_id,
            event_type: event.event_type,
            source: event.source,
            description: event.description,
            previous_hash: previousHash
        });
    }

    computeHash(event, previousHash) {
        return crypto.createHash('sha256').update(this.canonicalForm(event, previousHash)).digest('hex');
    }

    lastHash() {
        for (let i = this.events.length - 1; i >= 0; i--) {
            if (this.events[i].entry_hash) return this.events[i].entry_hash;
        }
        return GENESIS_HASH;
    }

    nextSequence() {
        for (let i = this.events.length - 1; i >= 0; i--) {
            if (Number.isInteger(this.events[i].sequence)) return this.events[i].sequence + 1;
        }
        return 1;
    }

    log(eventData) {
        const auditEvent = new AuditEvent(eventData);
        const previousHash = this.lastHash();

        auditEvent.sequence = this.nextSequence();
        auditEvent.previous_hash = previousHash;
        auditEvent.entry_hash = this.computeHash(auditEvent, previousHash);

        console.log(`[AuditLogger] [${auditEvent.timestamp}] [${auditEvent.case_id}] ${auditEvent.event_type}: ${auditEvent.description}`);

        this.events.push(auditEvent);
        this.rotateIfNeeded();
        this.persistToDisk();
        return auditEvent;
    }

    /**
     * Moves the oldest entries to an append-only archive once the active log
     * grows large, so history is bounded in memory without being destroyed.
     */
    rotateIfNeeded() {
        if (this.events.length <= ACTIVE_LIMIT) return;
        const overflow = this.events.splice(0, this.events.length - ACTIVE_LIMIT);
        try {
            fs.appendFileSync(this.archiveFile, overflow.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
        } catch (e) {
            // Rather than lose the records, keep them in memory if archiving fails.
            console.error('[AuditLogger] Archive write failed, retaining events in the active log:', e.message);
            this.events.unshift(...overflow);
        }
    }

    /**
     * Recomputes the chain and reports the first entry that does not match.
     * Entries predating chaining are skipped and counted separately rather than
     * being reported as tampering.
     */
    verifyChain() {
        let previousHash = GENESIS_HASH;
        let checked = 0;
        let skipped = 0;

        for (const event of this.events) {
            if (!event.entry_hash) { skipped++; continue; }

            if (event.previous_hash !== previousHash) {
                return {
                    intact: false,
                    checked,
                    skipped,
                    broken_at: event.sequence ?? checked,
                    reason: 'Entry does not link to the preceding entry, so a record was altered, inserted or removed.'
                };
            }

            const expected = this.computeHash(event, previousHash);
            if (expected !== event.entry_hash) {
                return {
                    intact: false,
                    checked,
                    skipped,
                    broken_at: event.sequence ?? checked,
                    reason: 'Entry contents do not match its recorded hash, so the entry was modified after it was written.'
                };
            }

            previousHash = event.entry_hash;
            checked++;
        }

        return { intact: true, checked, skipped, broken_at: null, reason: null };
    }

    getIntegrityStatus() {
        const verification = this.verifyChain();
        let archived = 0;
        try {
            if (fs.existsSync(this.archiveFile)) {
                archived = fs.readFileSync(this.archiveFile, 'utf8').split('\n').filter(Boolean).length;
            }
        } catch (e) {
            archived = 0;
        }

        return {
            chain_intact: verification.intact,
            entries_verified: verification.checked,
            entries_unverifiable: verification.skipped,
            broken_at_sequence: verification.broken_at,
            reason: verification.reason,
            active_entries: this.events.length,
            archived_entries: archived,
            latest_hash: this.lastHash(),
            model: 'Each entry is hashed together with the hash of the entry before it. Altering or removing a record breaks every hash that follows, making the change detectable.',
            limitation: 'This detects tampering; it does not prevent it. Anyone able to write the log file could recompute the whole chain. Export the latest hash to external storage to detect that case.'
        };
    }

    getEventsForCase(caseId) {
        return this.events.filter(e => e.case_id === caseId);
    }

    /** Newest first for display; the stored order remains chronological. */
    getAllEvents() {
        return this.events.slice().reverse();
    }

    persistToDisk() {
        try {
            const tmp = `${this.logFile}.tmp`;
            fs.writeFileSync(tmp, JSON.stringify(this.events, null, 2), 'utf8');
            fs.renameSync(tmp, this.logFile);
        } catch (e) {
            console.error('[AuditLogger] Persistence error:', e.message);
        }
    }
}

module.exports = new AuditLogger();
