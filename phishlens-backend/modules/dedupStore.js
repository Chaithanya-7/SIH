const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { dataFile } = require('./dataPaths');

class DedupStore {
    constructor() {
        this.storageFile = dataFile('processed_messages.json');
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
                const now = Date.now();
                list.forEach(r => {
                    if (r.message_key) {
                        // Recover stale PROCESSING records from previous crashes (> 5 min old)
                        if (r.processing_status === 'PROCESSING') {
                            const lastAttempt = r.last_attempt_at ? new Date(r.last_attempt_at).getTime() : 0;
                            if (now - lastAttempt > 5 * 60 * 1000) {
                                r.processing_status = 'RETRY_PENDING';
                                r.failure_reason = 'Stale PROCESSING record recovered on system startup';
                            }
                        }
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
     * Compute a durable, deterministic message key.
     * Priority: Provider Msg ID + Mailbox -> RFC Message-ID -> Raw Content SHA-256 Hash
     */
    computeMessageKey(rfcMessageId, rawEmailString, mailbox = '', providerMsgId = '') {
        if (providerMsgId && providerMsgId.trim().length > 0) {
            const cleanProviderId = `${mailbox}_${providerMsgId.trim()}`.toLowerCase();
            return `msg_prov_${crypto.createHash('sha256').update(cleanProviderId).digest('hex').substring(0, 24)}`;
        }

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
     * Atomic Check-and-Reserve for pipeline idempotency and recoverable state machine.
     */
    reserveMessageKey(messageKey, metadata = {}) {
        const existing = this.records.get(messageKey);
        const nowIso = new Date().toISOString();

        if (existing) {
            existing.observation_count = (existing.observation_count || (existing.sources ? existing.sources.length : 1)) + 1;
            if (metadata.source && !existing.sources.includes(metadata.source)) {
                existing.sources.push(metadata.source);
            }
            existing.last_seen = nowIso;

            if (existing.processing_status === 'COMPLETED') {
                this.saveStorage();
                return { isDuplicate: true, isCompleted: true, record: existing };
            }

            if (existing.processing_status === 'PROCESSING') {
                const lastAttempt = existing.last_attempt_at ? new Date(existing.last_attempt_at).getTime() : 0;
                const isStale = (Date.now() - lastAttempt) > 5 * 60 * 1000;

                if (!isStale) {
                    this.saveStorage();
                    return { isDuplicate: true, isProcessing: true, record: existing };
                }

                // Stale processing record can transition to RETRY_PENDING and proceed
                existing.processing_status = 'RETRY_PENDING';
            }

            // Retry allowed for RETRY_PENDING / FAILED or recovered stale records
            existing.processing_status = 'PROCESSING';
            existing.attempt_count = (existing.attempt_count || 0) + 1;
            existing.last_attempt_at = nowIso;
            this.saveStorage();
            return { isDuplicate: false, isRetry: true, record: existing };
        }

        const newRecord = {
            message_key: messageKey,
            case_id: metadata.case_id || null,
            sources: metadata.source ? [metadata.source] : ['MANUAL_API'],
            observation_count: 1,
            mailbox: metadata.mailbox || '',
            provider_message_id: metadata.provider_message_id || null,
            rfc_message_id: metadata.rfc_message_id || null,
            raw_sha256: metadata.raw_sha256 || '',
            first_seen: nowIso,
            last_seen: nowIso,
            processing_status: 'PROCESSING',
            attempt_count: 1,
            last_attempt_at: nowIso,
            failure_reason: null,
            completed_at: null
        };

        this.records.set(messageKey, newRecord);
        this.saveStorage();
        return { isDuplicate: false, isRetry: false, record: newRecord };
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
            record.failure_reason = errorMsg;
            record.last_attempt_at = new Date().toISOString();
            this.saveStorage();
        }
    }

    getRecord(messageKey) {
        return this.records.get(messageKey) || null;
    }

    getStats() {
        const totalObserved = Array.from(this.records.values()).reduce((sum, r) => sum + (r.observation_count || (r.sources ? r.sources.length : 1)), 0);
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
