const axios = require('axios');
const auditLogger = require('../modules/auditLogger');

class NotificationAdapter {
    async dispatchSocAlert(threatObject, policyId) {
        console.log(`[NotificationAdapter] 🔔 Dispatching SOC Alert for Case ${threatObject.case_id} (Policy: ${policyId})...`);

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

        // Webhook integration if configured
        if (process.env.SOC_WEBHOOK_URL) {
            try {
                await axios.post(process.env.SOC_WEBHOOK_URL, alertPayload, { timeout: 5000 });
                console.log(`[NotificationAdapter] Webhook notification delivered to ${process.env.SOC_WEBHOOK_URL}`);
            } catch (e) {
                console.error('[NotificationAdapter] Webhook delivery failed:', e.message);
            }
        }

        auditLogger.log({
            case_id: threatObject.case_id,
            event_type: 'SOC_ALERT_DISPATCHED',
            source: 'NOTIFICATION_ADAPTER',
            description: `SOC Alert dispatched for High-Risk Incident ${threatObject.case_id}`,
            confidence: threatObject.confidence?.threat
        });

        return { success: true, payload: alertPayload };
    }

    async dispatchRecipientWarning(threatObject, isContained) {
        console.log(`[NotificationAdapter] 📩 Dispatching Recipient Notification for Case ${threatObject.case_id}...`);

        const messageText = isContained
            ? `Security Alert: PhishLens detected a high-risk email (Case ${threatObject.case_id}). The message has been safely contained. Do not click links or respond.`
            : `Security Notice: A suspicious message (Case ${threatObject.case_id}) was detected and is under investigation by security team.`;

        auditLogger.log({
            case_id: threatObject.case_id,
            event_type: 'RECIPIENT_NOTIFIED',
            source: 'NOTIFICATION_ADAPTER',
            description: `Recipient ${threatObject.message?.recipient} notified: "${messageText}"`
        });

        return { success: true, recipient: threatObject.message?.recipient, message: messageText };
    }
}

module.exports = new NotificationAdapter();
