/**
 * Explainable local language analysis for phishing and BEC investigation.
 *
 * This deliberately produces individual, reviewable signals instead of an
 * opaque classifier score. It is a dependency-free baseline that can later be
 * supplemented by a locally hosted model behind the same `threatObject.nlp`
 * contract.
 *
 * Pattern categories are grounded in published social-engineering
 * indicators rather than an invented keyword list: APWG eCrime/phishing
 * trend reports, FBI IC3 Business Email Compromise public service
 * announcements, SANS/CISA phishing-indicator guidance, and NIST SP 800-177
 * language on email threats. Each pattern below cites its specific source.
 */
class NlpAnalyzer {
    getText(threatObject, parsedEmail) {
        const subject = threatObject.message?.subject || parsedEmail?.subject || '';
        let body = parsedEmail?.textBody || '';

        if (!body && parsedEmail?.htmlBody) {
            body = parsedEmail.htmlBody
                .replace(/<style[\s\S]*?<\/style>/gi, ' ')
                .replace(/<script[\s\S]*?<\/script>/gi, ' ')
                .replace(/<[^>]+>/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
        }

        if (!body && !parsedEmail) {
            // Defensive fallback only used if no parsed email was supplied at all.
            const raw = threatObject._raw_email_string || '';
            body = raw.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        }

        return { subject, body, combined: `${subject}\n${body}`.toLowerCase() };
    }

    analyze(threatObject, parsedEmail) {
        const { subject, body, combined } = this.getText(threatObject, parsedEmail);
        const patterns = [
            {
                type: 'URGENCY_PRESSURE', severity: 'MEDIUM', confidence: 0.70,
                terms: ['urgent', 'immediately', 'asap', 'within 24 hours', 'final notice', 'act now', 'today'],
                explanation: 'Pressure to act quickly can reduce a recipient’s ability to verify a request safely.',
                source: 'CISA phishing-indicator guidance; SANS Internet Storm Center'
            },
            {
                type: 'CREDENTIAL_REQUEST', severity: 'HIGH', confidence: 0.85,
                terms: ['verify your password', 'confirm your password', 'login to your account', 'sign in to your account', 'credential', 'reset your password'],
                explanation: 'The message asks for account access or credential-related action, a common phishing objective.',
                source: 'APWG phishing lure taxonomy'
            },
            {
                type: 'FINANCIAL_PRESSURE', severity: 'HIGH', confidence: 0.82,
                terms: ['wire transfer', 'bank account', 'gift card', 'payment attached', 'process payment', 'fund transfer', 'invoice payment'],
                explanation: 'The message contains financial-request language commonly used in business email compromise.',
                source: 'FBI IC3 Business Email Compromise (BEC) public service announcements'
            },
            {
                type: 'GIFT_CARD_REQUEST', severity: 'CRITICAL', confidence: 0.88,
                terms: ['gift card', 'itunes card', 'google play card', 'steam card', 'amazon gift card', 'purchase gift cards', 'redeem code'],
                explanation: 'Requests to purchase and send gift-card codes are one of the most consistently reported business email compromise tactics, since the codes are effectively untraceable cash.',
                source: 'FBI IC3 BEC public service announcements'
            },
            {
                type: 'IMPERSONATION_LANGUAGE', severity: 'MEDIUM', confidence: 0.72,
                terms: ['ceo', 'chief executive', 'on behalf of', 'executive office', 'management team'],
                explanation: 'The language invokes authority or organizational identity that should be verified independently.',
                source: 'FBI IC3 BEC guidance ("CEO fraud")'
            },
            {
                type: 'LINK_OR_ATTACHMENT_CALL_TO_ACTION', severity: 'MEDIUM', confidence: 0.68,
                terms: ['click here', 'open the attachment', 'download the attachment', 'review the document', 'view document'],
                explanation: 'The message directs the recipient toward a link or attachment, which requires corroborating URL or attachment analysis.',
                source: 'APWG phishing lure taxonomy'
            },
            {
                type: 'ACCOUNT_THREAT', severity: 'HIGH', confidence: 0.78,
                terms: ['account will be suspended', 'account has been locked', 'account will be closed', 'unusual activity detected', 'unauthorized access detected', 'your account will be deactivated'],
                explanation: 'The message threatens a negative account consequence to pressure quick action, a common phishing framing device.',
                source: 'CISA phishing-indicator guidance; APWG'
            },
            {
                type: 'SECRECY_PRESSURE', severity: 'HIGH', confidence: 0.80,
                terms: ['do not tell anyone', 'keep this confidential', 'between us', "don't discuss this", 'do not discuss this', 'keep this between you and me'],
                explanation: 'Asking the recipient to keep a request secret is a technique for preventing verification through a second channel, and is a strong business-email-compromise indicator on its own.',
                source: 'FBI IC3 BEC indicators'
            },
            {
                type: 'GENERIC_GREETING', severity: 'LOW', confidence: 0.40,
                terms: ['dear customer', 'dear user', 'dear valued customer', 'dear account holder', 'dear member', 'dear sir/madam'],
                explanation: 'A generic, non-personalized greeting is common in mass phishing sent to many recipients rather than a genuine individual correspondence, though some legitimate automated mail also uses it.',
                source: 'SANS/CISA phishing-indicator guidance'
            }
        ];

        const signals = patterns.map(pattern => {
            const matches = pattern.terms.filter(term => combined.includes(term));
            return matches.length ? {
                type: pattern.type,
                severity: pattern.severity,
                confidence: pattern.confidence,
                matched_terms: matches,
                explanation: pattern.explanation,
                source: pattern.source
            } : null;
        }).filter(Boolean);

        // Several independent language categories are more meaningful than a
        // repeated keyword. This score is a transparent summary, not a verdict.
        const severityWeight = { CRITICAL: 0.35, HIGH: 0.30, MEDIUM: 0.18, LOW: 0.08 };
        const score = Math.min(1, signals.reduce((total, signal) => total + (severityWeight[signal.severity] || 0.10), 0));
        threatObject.nlp = {
            status: 'ANALYZED',
            engine: 'EXPLAINABLE_LOCAL_HEURISTICS',
            analyzed_fields: { subject: Boolean(subject), body: Boolean(body) },
            score: Number(score.toFixed(2)),
            signals,
            limitation: 'Language signals are supporting evidence. They do not independently establish maliciousness.'
        };
        return threatObject;
    }
}

module.exports = new NlpAnalyzer();
