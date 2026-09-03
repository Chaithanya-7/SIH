class PolicyEngine {
    constructor() {
        this.policies = [
            {
                id: 'CRITICAL_BEC_VIP',
                name: 'Critical VIP Impersonation & BEC Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const isVipTarget = threatObject.executive_context?.is_targeted || threatObject.executive_context?.is_impersonated;
                    const hasAuthAnomaly = threatObject.evidence.some(e => e.evidence_type === 'AUTHENTICATION_ANOMALY' || e.evidence_type === 'IDENTITY_SPOOF');
                    const hasBecUrgency = threatObject.evidence.some(e => e.evidence_type === 'BEC_KEYWORD');
                    
                    // High-impact auto-quarantine guardrail: requires Threat Confidence >= 0.85 AND Executive Context AND (Authentication Anomaly OR BEC Intent)
                    return threatConf >= 0.85 && isVipTarget && (hasAuthAnomaly || hasBecUrgency);
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'High-confidence executive impersonation with financial intent & authentication anomaly'
            },
            {
                id: 'HIGH_RISK_AUTH_FAILURE',
                name: 'High Risk Authentication & Identity Spoof Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const hasAuthAnomaly = threatObject.evidence.some(e => e.evidence_type === 'AUTHENTICATION_ANOMALY');
                    const hasSpoof = threatObject.forensics?.return_path_mismatch;
                    return threatConf >= 0.80 && hasAuthAnomaly && hasSpoof;
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'High threat confidence combined with verified SPF/DKIM authentication failure & Return-Path mismatch'
            },
            {
                id: 'CAMPAIGN_CORRELATED_APPROVAL_REQUIRED',
                name: 'Campaign Correlated Threat Approval Policy',
                authorization_mode: 'REQUIRE_APPROVAL',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const campConf = threatObject.confidence?.campaign_association || 0;
                    return threatConf >= 0.60 && campConf >= 0.40;
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'Moderate threat confidence with confirmed persistent campaign association requires analyst review'
            },
            {
                id: 'SUSPICIOUS_USER_WARNING',
                name: 'Suspicious Warning Header Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    return threatConf >= 0.40 && threatConf < 0.60;
                },
                action: 'ALERT_RECIPIENT',
                reason: 'Moderate threat anomaly warrants recipient warning header'
            }
        ];
    }

    evaluate(threatObject) {
        console.log(`[PolicyEngine] Evaluating policy rules for Case ${threatObject.case_id}...`);

        let matchedPolicy = null;

        for (const policy of this.policies) {
            if (policy.condition(threatObject)) {
                matchedPolicy = policy;
                break; // Execute highest priority matched policy
            }
        }

        const policyId = matchedPolicy ? matchedPolicy.id : 'DEFAULT_ALLOW';
        const actionType = matchedPolicy ? matchedPolicy.action : 'NO_ACTION';
        const authMode = matchedPolicy ? matchedPolicy.authorization_mode : 'NO_ACTION';
        const reason = matchedPolicy ? matchedPolicy.reason : 'No policy threshold exceeded. Default allow.';

        threatObject.remediation.policy_matched = policyId;
        threatObject.remediation.authorization_mode = authMode;

        return {
            policy_id: policyId,
            policy_name: matchedPolicy ? matchedPolicy.name : 'Default Allow Policy',
            action_type: actionType,
            authorization_mode: authMode,
            reason: reason
        };
    }
}

module.exports = new PolicyEngine();
