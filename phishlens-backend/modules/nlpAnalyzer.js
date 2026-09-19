/**
 * Explainable local language analysis for phishing and BEC investigation.
 *
 * This deliberately produces individual, reviewable signals instead of an
 * opaque classifier score. It is a dependency-free baseline that can later be
 * supplemented by a locally hosted model behind the same `threatObject.nlp`
 * contract.
 */
class NlpAnalyzer {
    getText(threatObject) {
        const subject = threatObject.message?.subject || '';
        const rawBody = threatObject._raw_data_model?.body?.plain?.raw || threatObject._raw_email_string || '';
        const body = rawBody
            .replace(/<style[\s\S]*?<\/style>/gi, ' ')
            .replace(/<script[\s\S]*?<\/script>/gi, ' ')
            .replace(/<[^>]+>/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
        return { subject, body, combined: `${subject}\n${body}`.toLowerCase() };
    }

    analyze(threatObject) {
        const { subject, body, combined } = this.getText(threatObject);
        const patterns = [
            {
                type: 'URGENCY_PRESSURE', severity: 'MEDIUM', confidence: 0.70,
                terms: ['urgent', 'immediately', 'asap', 'within 24 hours', 'final notice', 'act now', 'today'],
                explanation: 'Pressure to act quickly can reduce a recipient’s ability to verify a request safely.'
            },
            {
                type: 'CREDENTIAL_REQUEST', severity: 'HIGH', confidence: 0.85,
                terms: ['verify your password', 'confirm your password', 'login to your account', 'sign in to your account', 'credential', 'reset your password'],
                explanation: 'The message asks for account access or credential-related action, a common phishing objective.'
            },
            {
                type: 'FINANCIAL_PRESSURE', severity: 'HIGH', confidence: 0.82,
                terms: ['wire transfer', 'bank account', 'gift card', 'payment attached', 'process payment', 'fund transfer', 'invoice payment'],
                explanation: 'The message contains financial-request language commonly used in business email compromise.'
            },
            {
                type: 'IMPERSONATION_LANGUAGE', severity: 'MEDIUM', confidence: 0.72,
                terms: ['ceo', 'chief executive', 'on behalf of', 'executive office', 'management team'],
                explanation: 'The language invokes authority or organizational identity that should be verified independently.'
            },
            {
                type: 'LINK_OR_ATTACHMENT_CALL_TO_ACTION', severity: 'MEDIUM', confidence: 0.68,
                terms: ['click here', 'open the attachment', 'download the attachment', 'review the document', 'view document'],
                explanation: 'The message directs the recipient toward a link or attachment, which requires corroborating URL or attachment analysis.'
            }
        ];

        const signals = patterns.map(pattern => {
            const matches = pattern.terms.filter(term => combined.includes(term));
            return matches.length ? {
                type: pattern.type,
                severity: pattern.severity,
                confidence: pattern.confidence,
                matched_terms: matches,
                explanation: pattern.explanation
            } : null;
        }).filter(Boolean);

        // Several independent language categories are more meaningful than a
        // repeated keyword. This score is a transparent summary, not a verdict.
        const score = Math.min(1, signals.reduce((total, signal) => total + (signal.severity === 'HIGH' ? 0.30 : 0.18), 0));
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
