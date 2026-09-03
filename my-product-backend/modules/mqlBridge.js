const ThreatObject = require('../models/ThreatObject');
const crypto = require('crypto');

class MQLBridge {
    normalize(detectionResult, rawEmailString) {
        console.log('[MQLBridge] Normalizing raw detection data into canonical SecureMail ThreatObject...');

        const rawData = detectionResult.rawResponse || {};
        const dataModel = rawData.data_model || {};
        const preview = rawData.preview || {};

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

        // Extract Signals / Matched Rules
        const matchedRules = [];
        const signals = [];

        if (auth.spf === 'fail') signals.push('spf_fail');
        if (auth.dkim === 'fail') signals.push('dkim_fail');
        if (auth.dmarc === 'fail') signals.push('dmarc_fail');

        // Instantiate Canonical SecureMail ThreatObject
        const threatObject = new ThreatObject({
            message: {
                sender: formattedSender,
                recipient: recipients.join(', '),
                subject: subject,
                raw_hash: rawHash,
                delivered_at: rawData.created_at || new Date().toISOString()
            },
            detection: {
                verdict: rawData.status || (signals.length > 0 ? 'SUSPICIOUS' : 'SAFE'),
                provider: 'sublime_mql',
                matched_rules: matchedRules,
                signals: signals
            },
            forensics: {
                authentication: auth,
                smtp_relay: []
            },
            // Pass along raw data model and raw email string internally for downstream forensic modules
            _raw_data_model: dataModel,
            _raw_email_string: rawEmailString
        });

        return threatObject;
    }
}

module.exports = new MQLBridge();
