const EvidenceObject = require('../models/EvidenceObject');

class ExecutiveGuard {
    constructor() {
        // High-value VIP target registry
        this.vipRegistry = [
            { name: 'CEO', title: 'Chief Executive Officer', email: 'ceo@company.com' },
            { name: 'CFO', title: 'Chief Financial Officer', email: 'cfo@company.com' },
            { name: 'Finance Minister', title: 'Senior Official', email: 'minister@gov.in' },
            { name: 'Director', title: 'Managing Director', email: 'director@company.com' }
        ];
    }

    evaluateTarget(threatObject) {
        console.log(`[ExecutiveGuard] Checking VIP targeting & executive impersonation context for ${threatObject.case_id}...`);

        const senderStr = threatObject.message.sender || '';
        const recipientStr = threatObject.message.recipient || '';
        const subjectStr = threatObject.message.subject || '';

        let isExecutiveTargeted = false;
        let isExecutiveImpersonated = false;
        let matchedVip = null;

        // Check if recipient is a VIP
        this.vipRegistry.forEach(vip => {
            if (recipientStr.toLowerCase().includes(vip.email.toLowerCase()) || recipientStr.toLowerCase().includes(vip.name.toLowerCase())) {
                isExecutiveTargeted = true;
                matchedVip = vip;
            }
        });

        // Check for display-name impersonation (e.g. sender display name says "CEO" but email domain is external/mismatched)
        this.vipRegistry.forEach(vip => {
            if (senderStr.toLowerCase().includes(vip.name.toLowerCase()) || senderStr.toLowerCase().includes(vip.title.toLowerCase())) {
                if (!senderStr.toLowerCase().includes(vip.email.toLowerCase())) {
                    isExecutiveImpersonated = true;
                    matchedVip = vip;
                }
            }
        });

        if (isExecutiveImpersonated) {
            threatObject.evidence.push(new EvidenceObject({
                evidence_type: 'EXECUTIVE_IMPERSONATION',
                source: 'EXECUTIVE_GUARD',
                finding: `Executive Impersonation Attempt Detected targeting ${matchedVip?.name || 'Leadership'}`,
                severity: 'CRITICAL',
                confidence: 0.95,
                explanation: `Sender identity displays executive title (${matchedVip?.name || 'Executive'}) but originates from unaligned external domain.`,
                provenance: { source_type: 'SENDER_HEADER', source_reference: senderStr }
            }));
        }

        if (isExecutiveTargeted) {
            threatObject.evidence.push(new EvidenceObject({
                evidence_type: 'EXECUTIVE_TARGETING',
                source: 'EXECUTIVE_GUARD',
                finding: `High-Value Executive Targeted: ${matchedVip?.title} (${matchedVip?.email})`,
                severity: 'HIGH',
                confidence: 0.90,
                explanation: 'Incident targets a designated VIP/Executive profile within the organization.',
                provenance: { source_type: 'RECIPIENT_HEADER', source_reference: recipientStr }
            }));
        }

        // Attach VIP context to threat object
        threatObject.executive_context = {
            is_targeted: isExecutiveTargeted,
            is_impersonated: isExecutiveImpersonated,
            matched_vip: matchedVip
        };

        return threatObject;
    }

    getVipList() {
        return this.vipRegistry;
    }
}

module.exports = new ExecutiveGuard();
