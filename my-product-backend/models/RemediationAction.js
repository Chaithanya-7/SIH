class RemediationAction {
    constructor(data = {}) {
        this.action_id = data.action_id || `ACT-2026-${Math.floor(10000 + Math.random() * 90000)}`;
        this.case_id = data.case_id || null;
        this.campaign_id = data.campaign_id || null;
        this.action_type = data.action_type || 'QUARANTINE_MESSAGE';
        
        // Status Lifecycle: POLICY_TRIGGERED -> ACTION_REQUESTED -> AUTHORIZATION_CHECKED -> ACTION_EXECUTING -> PROVIDER_CONFIRMED -> ACTION_SUCCEEDED / ACTION_FAILED / VERIFICATION_FAILED / REVERSED
        this.status = data.status || 'POLICY_TRIGGERED';

        this.trigger = {
            type: data.trigger?.type || 'POLICY',
            policy_id: data.trigger?.policy_id || 'DEFAULT_POLICY'
        };

        this.reason = data.reason || 'Automated policy rule trigger';

        this.authorization = {
            mode: data.authorization?.mode || 'REQUIRE_APPROVAL', // AUTO_EXECUTE | REQUIRE_APPROVAL | RECOMMEND_ONLY | NO_ACTION
            authorized_by: data.authorization?.authorized_by || 'SYSTEM',
            authorized_at: data.authorization?.authorized_at || new Date().toISOString()
        };

        this.target = {
            provider: data.target?.provider || 'simulation', // gmail | simulation | microsoft_graph
            mailbox: data.target?.mailbox || '',
            message_id: data.target?.message_id || '',
            rfc_message_id: data.target?.rfc_message_id || '',
            raw_hash: data.target?.raw_hash || ''
        };

        this.provider_result = {
            status: data.provider_result?.status || 'PENDING', // CONFIRMED | FAILED | SIMULATED | PENDING
            provider_action_id: data.provider_result?.provider_action_id || null,
            message: data.provider_result?.message || ''
        };

        const now = new Date().toISOString();
        this.requested_at = data.requested_at || now;
        this.executed_at = data.executed_at || null;
        this.completed_at = data.completed_at || null;

        this.reversible = data.reversible !== undefined ? data.reversible : true;
        this.rollback = {
            status: data.rollback?.status || (this.reversible ? 'AVAILABLE' : 'UNAVAILABLE'), // AVAILABLE | REVERSED | UNAVAILABLE
            reversed_at: data.rollback?.reversed_at || null,
            reversed_by: data.rollback?.reversed_by || null
        };
    }
}

module.exports = RemediationAction;
