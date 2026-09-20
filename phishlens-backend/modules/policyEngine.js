/**
 * Decides what *should* happen to a message. Whether the machine is allowed to
 * do it unasked is a separate question, answered by containmentGuard.
 *
 * Keeping those two apart matters. A policy that says "high-risk mail should be
 * quarantined" is a statement about intent and stays readable; the conditions
 * under which PhishLens may act without a person - confidence floors,
 * corroboration, burst ceilings, never-contain entries - belong with the safety
 * controls, not scattered through policy conditions.
 *
 * That separation is also what closed a real hole. Every quarantine policy here
 * used to carry its own extra condition: executive context, or a Return-Path
 * mismatch, or campaign correlation. A message scoring 0.95 with a HIGH_RISK
 * verdict that happened to match none of them fell through to DEFAULT_ALLOW and
 * nothing happened to it at all - detection worked perfectly and the response
 * layer did nothing. The specific policies are kept because they explain
 * themselves better, but they are now refinements on top of full coverage
 * rather than the only routes to action.
 */
class PolicyEngine {
    constructor() {
        /**
         * Evaluated in order, first match wins. Specific policies come first so
         * a case gets the most informative reason available; the verdict-based
         * policies at the end guarantee nothing falls through unhandled.
         */
        this.policies = [
            {
                id: 'CRITICAL_BEC_VIP',
                name: 'Critical VIP Impersonation & BEC Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const isVipTarget = threatObject.executive_context?.is_targeted || threatObject.executive_context?.is_impersonated;
                    const hasAuthAnomaly = (threatObject.evidence || []).some(e => e.evidence_type === 'AUTHENTICATION_ANOMALY' || e.evidence_type === 'IDENTITY_SPOOF');
                    const hasBecUrgency = (threatObject.evidence || []).some(e => e.evidence_type === 'BEC_KEYWORD');
                    return threatConf >= 0.85 && isVipTarget && (hasAuthAnomaly || hasBecUrgency);
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'High-confidence executive impersonation with financial intent and an authentication anomaly'
            },
            {
                id: 'HIGH_RISK_AUTH_FAILURE',
                name: 'High Risk Authentication & Identity Spoof Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const hasAuthAnomaly = (threatObject.evidence || []).some(e => e.evidence_type === 'AUTHENTICATION_ANOMALY');
                    const hasSpoof = threatObject.forensics?.return_path_mismatch;
                    return threatConf >= 0.80 && hasAuthAnomaly && hasSpoof;
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'High threat confidence combined with verified authentication failure and a Return-Path mismatch'
            },
            {
                id: 'CAMPAIGN_CORRELATED_APPROVAL_REQUIRED',
                name: 'Campaign Correlated Threat Approval Policy',
                authorization_mode: 'REQUIRE_APPROVAL',
                condition: (threatObject) => {
                    const threatConf = threatObject.confidence?.threat || 0;
                    const campConf = threatObject.confidence?.campaign_association || 0;
                    // Deliberately below the HIGH_RISK line: a message that is
                    // individually only moderately suspicious but belongs to a
                    // campaign already seen here is worth a person's attention,
                    // and is exactly the case where an automatic decision is
                    // least defensible.
                    return threatConf >= 0.60 && threatConf < 0.70 && campConf >= 0.40;
                },
                action: 'QUARANTINE_MESSAGE',
                reason: 'Moderate threat confidence with a confirmed association to a persistent campaign, which warrants analyst review'
            },
            {
                // The catch-all that closes the hole. A HIGH_RISK verdict is the
                // system's own conclusion that this message is malicious; there
                // is no coherent reading under which the correct response to it
                // is nothing at all.
                id: 'HIGH_RISK_CONTAINMENT',
                name: 'High Risk Containment Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => threatObject.detection?.verdict === 'HIGH_RISK',
                action: 'QUARANTINE_MESSAGE',
                reason: 'The verdict for this message is HIGH_RISK, so containment is the intended response. Whether it is carried out automatically is decided by the containment safety controls'
            },
            {
                // Verdict-based rather than a numeric window. The old rule fired
                // only between 0.40 and 0.60, so a message at 0.65 - suspicious
                // by the system's own threshold - was told nothing to anybody.
                id: 'SUSPICIOUS_USER_WARNING',
                name: 'Suspicious Recipient Warning Policy',
                authorization_mode: 'AUTO_EXECUTE',
                condition: (threatObject) => threatObject.detection?.verdict === 'SUSPICIOUS',
                action: 'ALERT_RECIPIENT',
                reason: 'The message is suspicious but not conclusively malicious, so it stays delivered and the recipient is warned rather than having their mail moved'
            }
        ];
    }

    evaluate(threatObject) {
        console.log(`[PolicyEngine] Evaluating policy rules for Case ${threatObject.case_id}...`);

        const matchedPolicy = this.policies.find(policy => {
            try {
                return policy.condition(threatObject);
            } catch (e) {
                // A policy that throws must not silently swallow the case. It is
                // reported and skipped so the remaining policies still run.
                console.error(`[PolicyEngine] Policy ${policy.id} failed to evaluate: ${e.message}`);
                return false;
            }
        }) || null;

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

    /** The policy set as an operator can read it, for the console and for review. */
    describe() {
        return this.policies.map(p => ({
            id: p.id,
            name: p.name,
            action: p.action,
            authorization_mode: p.authorization_mode,
            reason: p.reason
        }));
    }
}

module.exports = new PolicyEngine();
