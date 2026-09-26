const crypto = require('crypto');
const smtpListenerAdapter = require('./smtpListenerAdapter');
const imapAdapter = require('./imapAdapter');
const dedupStore = require('../modules/dedupStore');

class MailIngestionAdapter {
    constructor() {
        this.pipelineHandler = null;
    }

    startIngestion(pipelineHandler) {
        this.pipelineHandler = pipelineHandler;
        console.log('🚀 [MailIngestionAdapter] Starting Real-Time Automated Mail Ingestion Layer...');

        const handleIncomingRawEmail = async (rawEmail, source, mailbox = '', imapUid = null) => {
            if (!rawEmail || rawEmail.length === 0) return null;

            // Extract Message-ID header if present
            const rfcMatch = rawEmail.match(/^Message-ID:\s*(<[^>]+>)/mi);
            const rfcMessageId = rfcMatch ? rfcMatch[1] : null;
            const rawHash = crypto.createHash('sha256').update(rawEmail).digest('hex');

            const messageKey = dedupStore.computeMessageKey(rfcMessageId, rawEmail, mailbox);

            // Atomic Check and Reserve for Idempotency
            const dedupResult = dedupStore.reserveMessageKey(messageKey, {
                source,
                mailbox,
                imap_uid: imapUid,
                rfc_message_id: rfcMessageId,
                raw_sha256: rawHash
            });

            if (dedupResult.isDuplicate && dedupResult.isCompleted) {
                console.log(`[Dedup] DUPLICATE MESSAGE (${messageKey}) from ${source} -> Existing Case: ${dedupResult.record.case_id}. Processing skipped.`);
                return dedupResult.record;
            }

            if (dedupResult.isDuplicate && dedupResult.isProcessing) {
                console.log(`[Dedup] MESSAGE ALREADY PROCESSING (${messageKey}) from ${source}. Concurrent execution skipped.`);
                return dedupResult.record;
            }

            console.log(`⚡ [Ingestion] NEW/RETRY MESSAGE (${messageKey}) from [${source}] (Hash: ${rawHash.substring(0, 10)}...)`);

            try {
                if (this.pipelineHandler) {
                    return await this.pipelineHandler(rawEmail, source, messageKey);
                }
            } catch (err) {
                console.error(`❌ [Ingestion] Pipeline execution failed for ${messageKey}:`, err.message);
                dedupStore.markFailed(messageKey, err.message);
                throw err;
            }
        };

        // Start Local SMTP Gateway Listener on port 2525
        smtpListenerAdapter.start(handleIncomingRawEmail);

        // Start IMAP Poller if enabled in .env
        imapAdapter.start(handleIncomingRawEmail);
    }
}

module.exports = new MailIngestionAdapter();
