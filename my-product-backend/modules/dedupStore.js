const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class DedupStore {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/processed_messages.json');
        this.records = new Map();
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            if (fs.existsSync(this.storageFile)) {
                const raw = fs.readFileSync(this.storageFile, 'utf8');
                const list = JSON.parse(raw || '[]');
                list.forEach(r => {
                    if (r.message_key) {
                        this.records.set(r.message_key, r);
                    }
                });
                console.log(`[DedupStore] Loaded ${this.records.size} persistent message deduplication record(s) from disk.`);
            }
        } catch (e) {
            console.error('[DedupStore] Storage initialization error:', e.message);
        }
    }

    saveStorage() {
        try {
            const list = Array.from(this.records.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
        } catch (e) {
            console.error('[DedupStore] Error persisting deduplication records:', e.message);
        }
    }

    /**
     * Compute a stable, deterministic message key.
     * Priority: RFC Message-ID -> Raw Content SHA-256 Hash -> Mailbox + Provider ID
     */
    computeMessageKey(rfcMessageId, rawEmailString, mailbox = '') {
        if (rfcMessageId && rfcMessageId.trim().length > 3) {
            const cleanRfcId = rfcMessageId.trim().toLowerCase().replace(/^<|>$/g, '');
            return `msg_rfc_${crypto.createHash('sha256').update(cleanRfcId).digest('hex').substring(0, 24)}`;
        }
        
        if (rawEmailString && rawEmailString.length > 0) {
            const rawHash = crypto.createHash('sha256').update(rawEmailString).digest('hex');
            return `msg_hash_${rawHash.substring(0, 24)}`;
        }

        return `msg_fallback_${crypto.createHash('sha256').update(`${mailbox}_${Date.now()}`).digest('hex').substring(0, 24)}`;
    }

    /**
     * Atomic Check-and-Reserve for pipeline idempotency.
     */
    reserveMessageKey(messageKey, metadata = {}) {
        const existing = this.records.get(messageKey);
        if (existing) {
            // Update observed sources if new source detected
            if (metadata.source && !existing.sources.includes(metadata.source)) {
                existing.sources.push(metadata.source);
                existing.last_seen = new Date().toISOString();
                this.saveStorage();
            }
            return { isDuplicate: true, record: existing };
        }

        const newRecord = {
            message_key: messageKey,
            case_id: metadata.case_id || null,
            sources: metadata.source ? [metadata.source] : ['MANUAL_API'],
            mailbox: metadata.mailbox || '',
            provider_message_id: metadata.provider_message_id || null,
            rfc_message_id: metadata.rfc_message_id || null,
            raw_sha256: metadata.raw_sha256 || '',
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            processing_status: 'PROCESSING'
        };

        this.records.set(messageKey, newRecord);
        this.saveStorage();
        return { isDuplicate: false, record: newRecord };
    }

    bindCaseId(messageKey, caseId) {
        const record = this.records.get(messageKey);
        if (record) {
            record.case_id = caseId;
            record.processing_status = 'COMPLETED';
            record.completed_at = new Date().toISOString();
            this.saveStorage();
        }
    }

    markFailed(messageKey, errorMsg) {
        const record = this.records.get(messageKey);
        if (record) {
            record.processing_status = 'FAILED';
            record.error = errorMsg;
            this.saveStorage();
        }
    }

    getRecord(messageKey) {
        return this.records.get(messageKey) || null;
    }

    getStats() {
        const totalObserved = Array.from(this.records.values()).reduce((sum, r) => sum + r.sources.length, 0);
        const uniqueProcessed = this.records.size;
        const duplicatesSuppressed = Math.max(0, totalObserved - uniqueProcessed);

        return {
            emails_observed: totalObserved,
            unique_emails_processed: uniqueProcessed,
            duplicates_suppressed: duplicatesSuppressed
        };
    }
}

module.exports = new DedupStore();
