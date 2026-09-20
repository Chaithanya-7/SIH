const ThreatObject = require('../models/ThreatObject');
const crypto = require('crypto');

/**
 * Builds the canonical PhishLens ThreatObject.
 *
 * The message identity fields (sender/recipient/subject/date/message-id) come
 * from PhishLens' own independent MIME parsing (emailParser.js), not from an
 * external detection provider's response - the pipeline must produce a
 * correct, populated ThreatObject even when no external provider is
 * configured or reachable. If an optional external provider (e.g. Sublime)
 * was called and returned a result, that result is recorded as informational
 * `external_provider_result` metadata for analyst comparison, but it does not
 * replace or gate PhishLens' own parsing.
 */
class MQLBridge {
    normalize(parsedEmail, detectionResult, rawEmailString) {
        console.log('[MQLBridge] Building canonical PhishLens ThreatObject from independently parsed email...');

        const rawHash = crypto.createHash('sha256').update(rawEmailString || '').digest('hex');

        const senderEmail = parsedEmail.from?.address || 'unknown@domain.com';
        const senderName = parsedEmail.from?.name || '';
        const formattedSender = senderName ? `${senderName} <${senderEmail}>` : senderEmail;
        const recipients = parsedEmail.to && parsedEmail.to.length ? parsedEmail.to.join(', ') : '';

        const externalProvider = this.summarizeExternalProvider(detectionResult);

        const threatObject = new ThreatObject({
            message: {
                sender: formattedSender,
                recipient: recipients,
                subject: parsedEmail.subject || '(No Subject)',
                raw_hash: rawHash,
                message_id: parsedEmail.messageId || '',
                delivered_at: parsedEmail.date || new Date().toISOString()
            },
            detection: {
                verdict: 'UNKNOWN',
                provider: 'PHISHLENS_NATIVE_MQL',
                verification_status: 'PENDING_NATIVE_ANALYSIS',
                is_dev_fallback: false,
                matched_rules: [],
                signals: [],
                external_provider_result: externalProvider
            },
            forensics: {
                authentication: { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' },
                smtp_relay: []
            },
            _raw_data_model: (detectionResult && detectionResult.rawResponse && detectionResult.rawResponse.data_model) || {},
            _raw_email_string: rawEmailString
        });

        return threatObject;
    }

    /** External providers (e.g. Sublime), when configured, are informational only - see adapters/detectionAdapter.js. */
    summarizeExternalProvider(detectionResult) {
        if (!detectionResult) {
            return { attempted: false, provider: null, status: 'NOT_CONFIGURED' };
        }

        const rawData = detectionResult.rawResponse || {};
        const rawMatchedRules = rawData.matched_rules || rawData.flagged_rules || [];
        const matchedRules = Array.isArray(rawMatchedRules)
            ? rawMatchedRules.map(r => typeof r === 'string' ? r : (r.name || r.rule_name || r.id || JSON.stringify(r)))
            : [];

        return {
            attempted: true,
            provider: detectionResult.isDevFallback ? 'DEVELOPMENT_FALLBACK' : 'sublime',
            status: detectionResult.success ? 'RESPONDED' : 'UNAVAILABLE',
            verification_status: detectionResult.verificationStatus || null,
            claimed_verdict: rawData.status || rawData.verdict || null,
            claimed_matched_rules: matchedRules,
            note: 'Informational cross-check only. PhishLens\' own scored verdict and evidence never depend on this external provider.'
        };
    }
}

module.exports = new MQLBridge();
