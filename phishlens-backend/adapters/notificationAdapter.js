const axios = require('axios');
const auditLogger = require('../modules/auditLogger');

/**
 * Tells a SOC that something happened, where the operator has said where to
 * send it.
 *
 * This file previously also carried a `dispatchRecipientWarning` that built a
 * message, wrote an audit entry reading "Recipient <address> notified", and
 * returned success - without sending anything to anyone. Nothing called it,
 * which is the only reason the ledger was not already carrying permanent false
 * records of people being warned. It is removed rather than fixed: warning a
 * recipient is done by marking the message where they will see it, which the
 * remediation gateway does and reports as visible only when a provider confirms
 * it on read-back.
 */
class NotificationAdapter {
    /** Whether anywhere has been configured to send to. */
    isConfigured() {
        return !!process.env.SOC_WEBHOOK_URL;
    }

    async dispatchSocAlert(threatObject, policyId) {
        if (!this.isConfigured()) {
            return { success: false, skipped: true, reason: 'No SOC_WEBHOOK_URL is configured, so there is nowhere to send an alert.' };
        }
        console.log(`[NotificationAdapter] Dispatching SOC alert for case ${threatObject.case_id} (policy: ${policyId})...`);

        const alertPayload = {
            event: 'SOC_THREAT_ALERT',
            case_id: threatObject.case_id,
            subject: threatObject.message?.subject,
            sender: threatObject.message?.sender,
            verdict: threatObject.detection?.verdict,
            threat_confidence: threatObject.confidence?.threat,
            policy_id: policyId,
            timestamp: new Date().toISOString()
        };

        // The audit entry records what actually happened, including a failure.
        // An alert nobody received must not be logged as one that was sent.
        let delivered = false;
        let failure = null;
        try {
            await axios.post(process.env.SOC_WEBHOOK_URL, alertPayload, { timeout: 5000 });
            delivered = true;
        } catch (e) {
            failure = e.message;
            console.error('[NotificationAdapter] SOC webhook delivery failed:', e.message);
        }

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: delivered ? 'SOC_ALERT_DELIVERED' : 'SOC_ALERT_FAILED',
            source: 'NOTIFICATION_ADAPTER',
            description: delivered
                ? `SOC alert delivered to the configured webhook for case ${threatObject.case_id} under policy ${policyId}.`
                : `SOC alert could not be delivered for case ${threatObject.case_id}: ${failure}`,
            confidence: threatObject.confidence?.threat
        });

        return { success: delivered, payload: alertPayload, error: failure };
    }

}

module.exports = new NotificationAdapter();
