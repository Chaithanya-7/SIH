const ThreatObject = require('../models/ThreatObject');
const crypto = require('crypto');

class MQLBridge {
    normalize(detectionResult, rawEmailString) {
        console.log('[MQLBridge] Normalizing raw detection data into canonical PhishLens ThreatObject...');

        const rawData = (detectionResult && detectionResult.rawResponse) ? detectionResult.rawResponse : (detectionResult || {});
        const dataModel = rawData.data_model || {};
        const preview = rawData.preview || {};

        // Explicit Fallback & Provider Verification Check
        const isDevFallback = !!(detectionResult.isDevFallback || rawData.is_dev_fallback);
        const providerName = isDevFallback ? 'DEVELOPMENT_FALLBACK' : 'sublime';
        const verificationStatus = isDevFallback ? 'DEVELOPMENT / NOT SUBLIME VERIFIED' : 'SUBLIME_MQL_VERIFIED';

        // Compute SHA-256 hash of raw email for integrity & evidence provenance
        const rawHash = crypto.createHash('sha256').update(rawEmailString || '').digest('hex');

        // Extract Sender
        const senderEmail = dataModel.sender?.email?.email || preview.sender_email_address || 'unknown@domain.com';
        const senderName = dataModel.sender?.display_name || preview.sender_display_name || '';
        const formattedSender = senderName ? `${senderName} <${senderEmail}>` : senderEmail;

        // Extract Recipients
        const recipients = preview.recipients || (dataModel.recipients?.to || []).map(r => r.email?.email).filter(Boolean);

        // Extract Subject
        const subject = dataModel.subject?.subject || preview.subject || '(No Subject)';

        // Extract Authentication Results from Hop 0 if available
        const hops = dataModel.headers?.hops || [];
        const firstHopAuth = hops[0]?.authentication_results || {};
        const auth = {
            spf: firstHopAuth.spf || 'unknown',
            dkim: firstHopAuth.dkim || 'unknown',
            dmarc: firstHopAuth.dmarc || 'unknown'
        };

        // Extract Matched Rules & Signals when provided
        const rawMatchedRules = rawData.matched_rules || rawData.flagged_rules || [];
        const matchedRules = Array.isArray(rawMatchedRules) 
            ? rawMatchedRules.map(r => typeof r === 'string' ? r : (r.name || r.rule_name || r.id || JSON.stringify(r)))
            : [];

        const rawSignals = rawData.signals || rawData.tags || [];
        const signals = Array.isArray(rawSignals) ? [...rawSignals] : [];

        if (auth.spf === 'fail' && !signals.includes('spf_fail')) signals.push('spf_fail');
        if (auth.dkim === 'fail' && !signals.includes('dkim_fail')) signals.push('dkim_fail');
        if (auth.dmarc === 'fail' && !signals.includes('dmarc_fail')) signals.push('dmarc_fail');

        const rawVerdict = (rawData.status || rawData.verdict || '').toUpperCase();
        let verdict = 'SAFE';
        if (rawVerdict === 'FLAGGED' || rawVerdict === 'MALICIOUS' || rawVerdict === 'HIGH_RISK') {
            verdict = 'HIGH_RISK';
        } else if (rawVerdict === 'SUSPICIOUS' || matchedRules.length > 0 || signals.length > 0) {
            verdict = 'SUSPICIOUS';
        } else if (rawVerdict) {
            verdict = rawVerdict;
        }

        // Instantiate canonical PhishLens ThreatObject
        const threatObject = new ThreatObject({
            message: {
                sender: formattedSender,
                recipient: Array.isArray(recipients) ? recipients.join(', ') : recipients,
                subject: subject,
                raw_hash: rawHash,
                delivered_at: rawData.created_at || new Date().toISOString()
            },
            detection: {
                verdict: verdict,
                provider: providerName,
                verification_status: verificationStatus,
                is_dev_fallback: isDevFallback,
                matched_rules: matchedRules,
                signals: signals
            },
            forensics: {
                authentication: auth,
                smtp_relay: []
            },
            _raw_data_model: dataModel,
            _raw_email_string: rawEmailString
        });

        return threatObject;
    }
}

module.exports = new MQLBridge();
