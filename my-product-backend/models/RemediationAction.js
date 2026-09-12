class RemediationAction {
    constructor(data = {}) {
        this.action_id = data.action_id || `ACT-2026-${Math.floor(10000 + Math.random() * 90000)}`;
        this.case_id = data.case_id || null;
        this.organization_id = data.organization_id || null;
        this.mailbox_connection_id = data.mailbox_connection_id || null;
        this.campaign_id = data.campaign_id || null;
        this.type = data.type || data.action_type || 'QUARANTINE';
        this.action_type = this.type;
        
        // Status: REQUESTED | EXECUTING | COMPLETED | FAILED | REVERSED
        this.status = data.status || 'REQUESTED';
        this.requested_by = data.requested_by || 'SYSTEM';
        this.idempotency_key = data.idempotency_key || `idemp_${this.case_id}_${this.type}_${Date.now()}`;

        const now = new Date().toISOString();
        this.requested_at = data.requested_at || now;
        this.started_at = data.started_at || now;
        this.completed_at = data.completed_at || null;
        this.failure_reason = data.failure_reason || null;

        this.trigger = {
            type: data.trigger?.type || 'POLICY',
            policy_id: data.trigger?.policy_id || 'DEFAULT_POLICY'
        };

        this.reason = data.reason || 'Automated policy rule trigger';

        this.authorization = {
            mode: data.authorization?.mode || 'REQUIRE_APPROVAL',
            authorized_by: data.authorization?.authorized_by || this.requested_by,
            authorized_at: data.authorization?.authorized_at || now
        };

        this.target = {
            provider: data.target?.provider || 'GMAIL',
            mailbox: data.target?.mailbox || '',
            message_id: data.target?.message_id || '',
            rfc_message_id: data.target?.rfc_message_id || '',
            raw_hash: data.target?.raw_hash || ''
        };

        this.provider_result = {
            status: data.provider_result?.status || 'PENDING',
            provider_action_id: data.provider_result?.provider_action_id || null,
            message: data.provider_result?.message || ''
        };

        this.reversible = data.reversible !== undefined ? data.reversible : true;
        this.rollback = {
            status: data.rollback?.status || (this.reversible ? 'AVAILABLE' : 'UNAVAILABLE'),
            reversed_at: data.rollback?.reversed_at || null,
            reversed_by: data.rollback?.reversed_by || null
        };
    }
}

module.exports = RemediationAction;
