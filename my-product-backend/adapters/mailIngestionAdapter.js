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

        const handleIncomingRawEmail = async (rawEmail, source) => {
            if (!rawEmail || rawEmail.length === 0) return;

            // Extract Message-ID header if present
            const rfcMatch = rawEmail.match(/^Message-ID:\s*(<[^>]+>)/mi);
            const rfcMessageId = rfcMatch ? rfcMatch[1] : null;
            const rawHash = crypto.createHash('sha256').update(rawEmail).digest('hex');

            const messageKey = dedupStore.computeMessageKey(rfcMessageId, rawEmail);

            // Atomic Check and Reserve for Idempotency
            const dedupResult = dedupStore.reserveMessageKey(messageKey, {
                source,
                rfc_message_id: rfcMessageId,
                raw_sha256: rawHash
            });

            if (dedupResult.isDuplicate) {
                console.log(`[Dedup] DUPLICATE MESSAGE (${messageKey}) from ${source} -> Existing Case: ${dedupResult.record.case_id || 'PROCESSING'}. Processing skipped.`);
                return;
            }

            console.log(`⚡ [Ingestion] NEW MESSAGE (${messageKey}) from [${source}] (Hash: ${rawHash.substring(0, 10)}...)`);

            try {
                if (this.pipelineHandler) {
                    await this.pipelineHandler(rawEmail, source, messageKey);
                }
            } catch (err) {
                console.error(`❌ [Ingestion] Pipeline execution failed for ${messageKey}:`, err.message);
                dedupStore.markFailed(messageKey, err.message);
            }
        };

        // Start Local SMTP Gateway Listener on port 2525
        smtpListenerAdapter.start(handleIncomingRawEmail);

        // Start IMAP Poller if enabled in .env
        imapAdapter.start(handleIncomingRawEmail);
    }
}

module.exports = new MailIngestionAdapter();
