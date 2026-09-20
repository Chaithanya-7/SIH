const fs = require('fs');
const path = require('path');
const RemediationAction = require('../models/RemediationAction');
const remediationGateway = require('./remediationGateway');
const containmentGuard = require('./containmentGuard');
const campaignResponsePlanner = require('./campaignResponsePlanner');
const iocResponseManager = require('./iocResponseManager');
const notificationAdapter = require('../adapters/notificationAdapter');
const auditLogger = require('./auditLogger');
const caseManager = require('./caseManager');
const { dataFile } = require('./dataPaths');

const { OUTCOME } = remediationGateway;

/**
 * Turns a policy decision into something that has actually happened, and says
 * precisely which of those two things it was.
 *
 * The distinction is the whole point of this module. A decision recorded in
 * simulation, a decision that cannot be carried out because the message never
 * came from a mailbox we hold, a decision blocked by a safety control, and a
 * message genuinely moved out of somebody's inbox are four different states.
 * Reporting them as one - which is what a flat "status: QUARANTINED" used to
 * do - tells an operator their mail is protected when it is not.
 *
 * Every provider mutation goes through remediationGateway. Nothing here talks
 * to Gmail or IMAP directly, because bypassing the gateway is exactly how the
 * mode switch stopped meaning anything last time.
 */

/** What we decided and did. Distinct from mailbox.status, which is where the message is. */
const REMEDIATION_STATUS = {
    NO_ACTION: 'NO_ACTION',
    QUARANTINED: 'QUARANTINED',
    SIMULATED_QUARANTINE: 'SIMULATED_QUARANTINE',
    NOT_ACTIONABLE: 'NOT_ACTIONABLE',
    PENDING_APPROVAL: 'PENDING_APPROVAL',
    BLOCKED_BY_GUARD: 'BLOCKED_BY_GUARD',
    RECIPIENT_WARNED: 'RECIPIENT_WARNED',
    FAILED: 'FAILED'
};

class RemediationEngine {
    constructor() {
        this.storageFile = dataFile('remediation_actions.json');
        this.actions = new Map();
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            if (fs.existsSync(this.storageFile)) {
                const data = JSON.parse(fs.readFileSync(this.storageFile, 'utf8'));
                (data || []).forEach(item => {
                    this.actions.set(item.action_id, new RemediationAction(item));
                });
                console.log(`[RemediationEngine] Loaded ${this.actions.size} persistent remediation action(s) from disk.`);
            }
        } catch (e) {
            console.error('[RemediationEngine] Storage load error:', e.message);
        }
    }

    saveStorage() {
        try {
            const data = Array.from(this.actions.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(data, null, 2), 'utf8');
        } catch (e) {
            console.error('[RemediationEngine] Storage save error:', e.message);
        }
    }

    /**
     * Records the outcome on the case in a form that cannot be mistaken for
     * something stronger than it is.
     *
     * mailbox.status answers the physical question - where is the message right
     * now. In simulation the answer is INBOX, because that is the truth, and
     * any count of quarantined mail that reads this field stays correct without
     * having to know anything about modes.
     */
    applyOutcome(threatObject, result, intendedAction) {
        threatObject.remediation.mode = result.mode;
        threatObject.remediation.simulated = result.outcome === OUTCOME.SIMULATED;
        threatObject.remediation.detail = result.detail;
        threatObject.remediation.intended_action = intendedAction;

        switch (result.outcome) {
            case OUTCOME.CONTAINED:
                threatObject.mailbox.status = 'QUARANTINED';
                threatObject.provider_action.status = 'PROVIDER_CONFIRMED';
                threatObject.review.status = 'PENDING_ADMIN';
                threatObject.remediation.status = REMEDIATION_STATUS.QUARANTINED;
                threatObject.containment_context.label_id = result.label_id || null;
                threatObject.containment_context.folder = result.folder || null;
                threatObject.containment_context.contained_at = new Date().toISOString();
                break;

            case OUTCOME.RELEASED:
                threatObject.mailbox.status = 'RELEASED';
                threatObject.provider_action.status = 'PROVIDER_CONFIRMED';
                threatObject.containment_context.released_at = new Date().toISOString();
                break;

            case OUTCOME.SIMULATED:
                // The message has not moved, so the mailbox state does not change.
                threatObject.mailbox.status = 'INBOX';
                threatObject.provider_action.status = 'NOT_REQUESTED';
                threatObject.review.status = 'PENDING_ADMIN';
                threatObject.remediation.status = REMEDIATION_STATUS.SIMULATED_QUARANTINE;
                break;

            case OUTCOME.NOT_ACTIONABLE:
                threatObject.mailbox.status = 'INBOX';
                threatObject.provider_action.status = 'NOT_APPLICABLE';
                threatObject.review.status = 'PENDING_ADMIN';
                threatObject.remediation.status = REMEDIATION_STATUS.NOT_ACTIONABLE;
                break;

            default:
                threatObject.mailbox.status = 'ACTION_FAILED';
                threatObject.provider_action.status = 'FAILED';
                threatObject.review.status = 'PENDING_ADMIN';
                threatObject.remediation.status = REMEDIATION_STATUS.FAILED;
        }
        return threatObject;
    }

    recordAction(fields) {
        const action = new RemediationAction(fields);
        this.actions.set(action.action_id, action);
        this.saveStorage();
        return action;
    }

    /**
     * Automatic policy evaluation and, where every control agrees, containment.
     */
    async executePolicyDecision(threatObject, policyDecision) {
        console.log(`[RemediationEngine] Processing policy decision '${policyDecision.policy_id}' for Case ${threatObject.case_id}...`);

        iocResponseManager.processThreatIOCs(threatObject);

        if (threatObject.campaign) {
            threatObject.remediation.campaign_plan = campaignResponsePlanner.generateResponsePlan(threatObject.campaign, [threatObject]);
        }

        // Stated on every case so that a reader of a single case, or of a PDF
        // report produced from one, can see whether this installation acts on
        // mail at all - without having to know what the server was started with.
        threatObject.remediation.capability = remediationGateway.capability();

        if (policyDecision.authorization_mode === 'NO_ACTION' || policyDecision.action_type === 'NO_ACTION' || threatObject.detection?.verdict === 'SAFE') {
            threatObject.remediation.status = REMEDIATION_STATUS.NO_ACTION;
            threatObject.mailbox.status = 'INBOX';
            threatObject.review.status = 'NOT_REQUIRED';
            threatObject.provider_action.status = 'NOT_REQUESTED';
            return threatObject;
        }

        if (policyDecision.action_type === 'ALERT_RECIPIENT') {
            return await this.warnRecipient(threatObject, policyDecision);
        }

        // A policy that asks for approval has to produce something an analyst
        // can approve. Previously this decision fell through to "leave it in
        // the inbox", and /api/remediate/approve called a method that did not
        // exist, so an approval-gated policy could never be acted on at all.
        if (policyDecision.authorization_mode === 'REQUIRE_APPROVAL') {
            return this.raiseForApproval(threatObject, policyDecision);
        }

        return await this.executeAutomaticContainment(threatObject, policyDecision);
    }

    /**
     * A containment request that an analyst has to approve before anything moves.
     */
    raiseForApproval(threatObject, policyDecision) {
        const preview = remediationGateway.preview(threatObject);
        const action = this.recordAction({
            case_id: threatObject.case_id,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'QUARANTINE',
            status: 'REQUESTED',
            requested_by: 'POLICY_ENGINE',
            idempotency_key: `approval_${threatObject.case_id}`,
            reason: policyDecision.reason,
            trigger: { type: 'POLICY', policy_id: policyDecision.policy_id },
            authorization: { mode: 'REQUIRE_APPROVAL', authorized_by: null, authorized_at: null },
            target: {
                provider: preview.provider || 'UNKNOWN',
                mailbox: preview.mailbox || '',
                message_id: threatObject.mailbox_provenance?.provider_message_id || '',
                rfc_message_id: threatObject.message?.message_id || ''
            },
            provider_result: { status: 'PENDING', message: preview.explanation }
        });

        threatObject.mailbox.status = 'INBOX';
        threatObject.provider_action.status = 'NOT_REQUESTED';
        threatObject.review.status = 'PENDING_ADMIN';
        threatObject.remediation.status = REMEDIATION_STATUS.PENDING_APPROVAL;
        threatObject.remediation.pending_action_id = action.action_id;
        threatObject.remediation.detail = `${policyDecision.reason}. Held for analyst approval: ${preview.explanation}`;

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: 'CONTAINMENT_AWAITING_APPROVAL',
            source: 'REMEDIATION_ENGINE',
            description: `Policy ${policyDecision.policy_id} requires approval. Action ${action.action_id} raised; the message has not been touched.`
        });

        return threatObject;
    }

    /**
     * Marks a delivered message as suspicious where the recipient will see it.
     *
     * Stated plainly, because this is easy to overpromise: PhishLens does not
     * rewrite the body of a delivered message to add a banner. No mail provider
     * permits editing a message already sitting in somebody's mailbox, and a
     * tool claiming to inject a banner into delivered mail is either rewriting
     * at the gateway before delivery or not doing it at all. What PhishLens can
     * do, and does, is apply a visible provider label the recipient sees beside
     * the message, and record the warning and its reasons on the case.
     */
    async warnRecipient(threatObject, policyDecision) {
        const result = await remediationGateway.warn(threatObject);

        // The message stays delivered either way - that is the point of warning
        // rather than containing - so the mailbox state does not change.
        threatObject.mailbox.status = 'INBOX';
        threatObject.review.status = 'PENDING_ADMIN';
        threatObject.provider_action.status = result.outcome === OUTCOME.WARNED ? 'PROVIDER_CONFIRMED' : 'NOT_REQUESTED';
        threatObject.remediation.status = REMEDIATION_STATUS.RECIPIENT_WARNED;
        threatObject.remediation.mode = result.mode;
        threatObject.remediation.simulated = result.outcome === OUTCOME.SIMULATED;
        threatObject.remediation.warning = {
            issued_at: new Date().toISOString(),
            reason: policyDecision.reason,
            // True only when a provider confirmed the mark on read-back. Anything
            // less and the recipient sees nothing, so claiming otherwise would
            // leave an operator believing a person had been warned when they had
            // not.
            recipient_visible: result.outcome === OUTCOME.WARNED,
            headline: 'This message shows signs of a phishing attempt.',
            detail: this.warningText(threatObject),
            mechanism: result.detail
        };

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: result.outcome === OUTCOME.WARNED ? 'RECIPIENT_WARNED' : 'RECIPIENT_WARNING_RECORDED_ONLY',
            source: 'REMEDIATION_ENGINE',
            description: `Warning raised under policy ${policyDecision.policy_id}: ${policyDecision.reason}. ${result.detail}`
        });

        return threatObject;
    }

    /**
     * The warning a non-specialist can act on: what was noticed, strongest
     * first, without jargon and without a score.
     */
    warningText(threatObject) {
        const reasons = (threatObject.evidence || [])
            .slice()
            .sort((a, b) => (b.signal_strength || 0) - (a.signal_strength || 0))
            .slice(0, 3)
            .map(e => e.finding)
            .filter(Boolean);

        if (reasons.length === 0) {
            return 'Treat any links, attachments or requests in this message with caution, and confirm through a channel you already trust.';
        }
        return `${reasons.join('; ')}. Do not act on any request in this message until you have confirmed it through a channel you already trust - not a number or link taken from the message itself.`;
    }

    /**
     * Automatic containment, subject to every control agreeing.
     */
    async executeAutomaticContainment(threatObject, policyDecision) {
        const verdict = containmentGuard.evaluate(threatObject);

        if (!verdict.allowed) {
            console.warn(`[RemediationEngine] Automatic containment refused for ${threatObject.case_id} by ${verdict.control}: ${verdict.reason}`);
            threatObject.mailbox.status = 'INBOX';
            threatObject.review.status = 'PENDING_ADMIN';
            threatObject.provider_action.status = 'NOT_REQUESTED';
            threatObject.remediation.status = REMEDIATION_STATUS.BLOCKED_BY_GUARD;
            threatObject.remediation.blocked_by = verdict.control;
            threatObject.remediation.detail = verdict.reason;

            auditLogger.log({
                case_id: threatObject.case_id,
                org_id: threatObject.org_id,
                event_type: 'CONTAINMENT_REFUSED_BY_GUARD',
                source: 'CONTAINMENT_GUARD',
                description: `${verdict.control}: ${verdict.reason}`
            });
            return threatObject;
        }

        const target = remediationGateway.resolveTarget(threatObject);
        const action = this.recordAction({
            case_id: threatObject.case_id,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'QUARANTINE',
            status: 'EXECUTING',
            requested_by: 'POLICY_ENGINE',
            idempotency_key: `contain_${threatObject.case_id}`,
            started_at: new Date().toISOString(),
            reason: policyDecision.reason,
            trigger: { type: 'POLICY', policy_id: policyDecision.policy_id },
            authorization: { mode: 'AUTO_EXECUTE', authorized_by: 'POLICY_ENGINE', authorized_at: new Date().toISOString() },
            target: {
                provider: target.provider || 'UNKNOWN',
                mailbox: target.mailbox || '',
                message_id: target.message_id || '',
                rfc_message_id: threatObject.message?.message_id || '',
                raw_hash: threatObject.message?.raw_hash || ''
            }
        });

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: 'CONTAINMENT_REQUESTED',
            source: 'REMEDIATION_ENGINE',
            description: `Containment requested under policy ${policyDecision.policy_id} (${remediationGateway.mode()} mode). Guard passed: ${verdict.reason}`
        });

        const result = await remediationGateway.quarantine(threatObject);
        this.closeAction(action, result);
        this.applyOutcome(threatObject, result, 'QUARANTINE');

        if (result.outcome === OUTCOME.CONTAINED) {
            containmentGuard.recordAutomaticAction();
        }

        // Tell the SOC, if the operator has said where. Awaited rather than
        // fired and forgotten so a failed delivery is recorded as a failure
        // instead of vanishing into an unhandled rejection - the operator needs
        // to find out that their alerting is broken from the ledger, not from
        // the alert that never arrived.
        await notificationAdapter.dispatchSocAlert(threatObject, policyDecision.policy_id)
            .catch(e => console.error('[RemediationEngine] SOC alert dispatch failed:', e.message));

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: this.auditEventFor(result.outcome, 'CONTAINMENT'),
            source: 'REMEDIATION_ENGINE',
            description: result.detail
        });

        return threatObject;
    }

    auditEventFor(outcome, kind) {
        switch (outcome) {
            case OUTCOME.CONTAINED: return 'CONTAINMENT_CONFIRMED';
            case OUTCOME.RELEASED: return 'RELEASE_CONFIRMED';
            case OUTCOME.SIMULATED: return `${kind}_SIMULATED`;
            case OUTCOME.NOT_ACTIONABLE: return `${kind}_NOT_APPLICABLE`;
            default: return `${kind}_FAILED`;
        }
    }

    /**
     * A simulated or inapplicable action is a completed decision, not a failed
     * one. Only a real attempt against a real mailbox can fail, and only a real
     * change to a mailbox can be rolled back.
     */
    closeAction(action, result) {
        action.completed_at = new Date().toISOString();
        action.provider_result = {
            status: result.outcome,
            provider_action_id: result.provider_action_id || null,
            message: result.detail
        };
        action.mode = result.mode;

        if (result.outcome === OUTCOME.FAILED) {
            action.status = 'FAILED';
            action.failure_reason = result.detail;
            action.rollback.status = 'UNAVAILABLE';
        } else if (result.outcome === OUTCOME.SIMULATED || result.outcome === OUTCOME.NOT_ACTIONABLE) {
            action.status = 'COMPLETED';
            action.reversible = false;
            action.rollback.status = 'UNAVAILABLE';
        } else {
            action.status = 'COMPLETED';
            action.reversible = true;
            action.rollback.status = 'AVAILABLE';
        }

        this.actions.set(action.action_id, action);
        this.saveStorage();
        return action;
    }

    assertAdmin(adminUser, threatObject, caseId) {
        if (!adminUser || adminUser.role !== 'ADMIN') {
            throw new Error('Insufficient permissions. Admin role required.');
        }
        if (threatObject.org_id && adminUser.organization_id && adminUser.organization_id !== threatObject.org_id) {
            throw new Error(`Access denied. Case ${caseId} belongs to another organization.`);
        }
    }

    /**
     * Approve a containment that a policy raised but deliberately did not carry
     * out.
     */
    async approveAction(actionId, adminUser, reason = 'Analyst approved') {
        const action = this.actions.get(actionId);
        if (!action) throw new Error(`Remediation action ${actionId} not found.`);
        if (action.status !== 'REQUESTED') {
            throw new Error(`Action ${actionId} is ${action.status}, not awaiting approval.`);
        }

        const threatObject = caseManager.getCase(action.case_id);
        if (!threatObject) throw new Error(`Case ${action.case_id} not found.`);
        this.assertAdmin(adminUser, threatObject, action.case_id);

        action.status = 'EXECUTING';
        action.authorization = {
            mode: 'REQUIRE_APPROVAL',
            authorized_by: adminUser.email || adminUser.id,
            authorized_at: new Date().toISOString()
        };
        action.reason = reason;
        this.actions.set(actionId, action);
        this.saveStorage();

        auditLogger.log({
            case_id: action.case_id,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: 'CONTAINMENT_APPROVED',
            source: `ADMIN:${adminUser.email}`,
            description: `Admin ${adminUser.email} approved action ${actionId}: ${reason}`
        });

        const result = await remediationGateway.quarantine(threatObject);
        this.closeAction(action, result);
        this.applyOutcome(threatObject, result, 'QUARANTINE');
        threatObject.remediation.approved_by = adminUser.email || adminUser.id;
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: action.case_id,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: this.auditEventFor(result.outcome, 'CONTAINMENT'),
            source: 'REMEDIATION_ENGINE',
            description: result.detail
        });

        return action;
    }

    /**
     * Undo an action that really changed a mailbox.
     *
     * An action that was simulated, or that was never applicable, has nothing
     * to undo. Saying so is more useful than performing a no-op and reporting
     * success.
     */
    async rollbackAction(actionId, adminUser, reason = 'Analyst rollback') {
        const action = this.actions.get(actionId);
        if (!action) throw new Error(`Remediation action ${actionId} not found.`);

        const threatObject = caseManager.getCase(action.case_id);
        if (!threatObject) throw new Error(`Case ${action.case_id} not found.`);
        this.assertAdmin(adminUser, threatObject, action.case_id);

        if (action.rollback.status === 'REVERSED') {
            return action;
        }
        if (action.rollback.status !== 'AVAILABLE') {
            const because = action.provider_result?.status === OUTCOME.SIMULATED
                ? 'it was simulated, so no mailbox was changed'
                : 'no reversible provider change was made';
            throw new Error(`Action ${actionId} cannot be rolled back: ${because}.`);
        }

        const result = await remediationGateway.release(threatObject);

        if (result.outcome === OUTCOME.RELEASED) {
            action.rollback = {
                status: 'REVERSED',
                reversed_at: new Date().toISOString(),
                reversed_by: adminUser.email || adminUser.id
            };
            action.status = 'REVERSED';
            this.applyOutcome(threatObject, result, 'RELEASE');
            threatObject.review.status = 'RELEASED_BY_ADMIN';
            threatObject.containment_context.decision_reason = reason;
        } else {
            action.failure_reason = result.detail;
        }

        this.actions.set(actionId, action);
        this.saveStorage();
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: action.case_id,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: result.outcome === OUTCOME.RELEASED ? 'ACTION_ROLLED_BACK' : 'ACTION_ROLLBACK_FAILED',
            source: `ADMIN:${adminUser.email}`,
            description: `${reason}. ${result.detail}`
        });

        return action;
    }

    /**
     * An administrator acting directly, outside the policy path.
     *
     * The automatic guards are deliberately not consulted here: they exist to
     * constrain the machine acting unasked, not to overrule a person who has
     * looked at the case. Simulation mode and actionability still apply -
     * neither is a judgement call, they are facts about what can be done at all.
     */
    async adminOverride(caseId, requestedAction, adminUser) {
        const threatObject = caseManager.getCase(caseId);
        if (!threatObject) throw new Error(`Case ${caseId} not found.`);
        this.assertAdmin(adminUser, threatObject, caseId);

        const normalized = String(requestedAction || '').toUpperCase();
        const supported = ['QUARANTINE', 'RELEASE', 'ALLOW'];
        if (!supported.includes(normalized)) {
            throw new Error(`Unsupported override action '${requestedAction}'. Supported: ${supported.join(', ')}.`);
        }

        if (normalized === 'ALLOW') {
            threatObject.review.status = 'RELEASED_BY_ADMIN';
            threatObject.remediation.status = REMEDIATION_STATUS.NO_ACTION;
            threatObject.remediation.detail = `Administrator ${adminUser.email} judged that this case requires no action.`;
            caseManager.saveCase(threatObject);
            auditLogger.log({
                case_id: caseId, org_id: threatObject.org_id, user_id: adminUser.id,
                event_type: 'ADMIN_OVERRIDE_ALLOW', source: `ADMIN:${adminUser.email}`,
                description: `Administrator override: no action required for case ${caseId}.`
            });
            return { case: threatObject, outcome: 'ALLOWED' };
        }

        const action = this.recordAction({
            case_id: caseId,
            organization_id: threatObject.org_id,
            type: normalized,
            status: 'EXECUTING',
            requested_by: adminUser.email || adminUser.id,
            idempotency_key: `override_${normalized}_${caseId}_${Date.now()}`,
            trigger: { type: 'ADMIN_OVERRIDE', policy_id: 'MANUAL' },
            authorization: { mode: 'AUTO_EXECUTE', authorized_by: adminUser.email, authorized_at: new Date().toISOString() },
            target: {
                provider: threatObject.mailbox_provenance?.provider || 'UNKNOWN',
                mailbox: threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient || '',
                message_id: threatObject.mailbox_provenance?.provider_message_id || ''
            }
        });

        const result = normalized === 'QUARANTINE'
            ? await remediationGateway.quarantine(threatObject)
            : await remediationGateway.release(threatObject);

        this.closeAction(action, result);
        this.applyOutcome(threatObject, result, normalized);
        if (normalized === 'RELEASE' && result.outcome === OUTCOME.RELEASED) {
            threatObject.review.status = 'RELEASED_BY_ADMIN';
        }
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: `ADMIN_OVERRIDE_${normalized}`,
            source: `ADMIN:${adminUser.email}`,
            description: result.detail
        });

        return { case: threatObject, action, outcome: result.outcome, detail: result.detail };
    }

    /**
     * Release a case an analyst has judged a false positive.
     */
    async releaseCase(caseId, adminUser, decisionReason = 'FALSE_POSITIVE', adminNote = '') {
        const threatObject = caseManager.getCase(caseId);
        if (!threatObject) {
            throw new Error(`Case ${caseId} not found.`);
        }
        this.assertAdmin(adminUser, threatObject, caseId);

        if (threatObject.review?.status === 'CONFIRMED_THREAT') {
            throw new Error('Cannot release a case that has been confirmed as a threat by an administrator.');
        }
        if (threatObject.review?.status === 'RELEASED_BY_ADMIN') {
            console.log(`[RemediationEngine] Case ${caseId} is already released. Returning existing state (idempotent).`);
            return { success: true, case: threatObject, alreadyCompleted: true };
        }

        const idempotencyKey = `release_${caseId}`;
        const existingAction = Array.from(this.actions.values()).find(a => a.idempotency_key === idempotencyKey);
        if (existingAction && existingAction.status === 'EXECUTING') {
            throw new Error('A release action is currently executing for this case. Concurrency lock enforced.');
        }

        const action = this.recordAction({
            case_id: caseId,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'RELEASE',
            status: 'EXECUTING',
            requested_by: adminUser.id || adminUser.email,
            idempotency_key: idempotencyKey,
            started_at: new Date().toISOString(),
            reason: decisionReason,
            trigger: { type: 'ANALYST_DECISION', policy_id: 'MANUAL' },
            target: {
                provider: threatObject.mailbox_provenance?.provider || 'UNKNOWN',
                mailbox: threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient || '',
                message_id: threatObject.mailbox_provenance?.provider_message_id || ''
            }
        });

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: 'RELEASE_REQUESTED',
            source: `ADMIN:${adminUser.email}`,
            description: `Admin ${adminUser.email} requested release for Case ${caseId} (reason: ${decisionReason}).`
        });

        const result = await remediationGateway.release(threatObject);
        this.closeAction(action, result);

        // The analyst's judgement is the valuable part and it stands whatever
        // the mailbox did. A release that could not be carried out - because
        // the message was never in a mailbox we hold, or because the run is in
        // simulation - is still a human saying this was a false positive, and
        // that has to reach the review record and the learning path intact.
        threatObject.review.status = 'RELEASED_BY_ADMIN';
        threatObject.containment_context.decision_reason = decisionReason;
        threatObject.containment_context.admin_note = adminNote || '';

        if (result.outcome !== OUTCOME.FAILED) {
            this.applyOutcome(threatObject, result, 'RELEASE');
            threatObject.review.status = 'RELEASED_BY_ADMIN';
        } else {
            threatObject.provider_action.status = 'FAILED';
            threatObject.remediation.detail = result.detail;
        }

        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: this.auditEventFor(result.outcome, 'RELEASE'),
            source: `ADMIN:${adminUser.email}`,
            description: result.detail
        });

        return {
            success: result.outcome !== OUTCOME.FAILED,
            case: threatObject,
            action,
            mailbox_outcome: result.outcome,
            detail: result.detail
        };
    }

    /**
     * Confirm a case as a genuine threat. The message is left where it is -
     * quarantined if it was contained - and never deleted, so the evidence
     * stays available to an investigation.
     */
    async confirmThreat(caseId, adminUser, decisionReason = 'MALICIOUS_PHISH', adminNote = '') {
        const threatObject = caseManager.getCase(caseId);
        if (!threatObject) {
            throw new Error(`Case ${caseId} not found.`);
        }
        this.assertAdmin(adminUser, threatObject, caseId);

        if (threatObject.review?.status === 'RELEASED_BY_ADMIN') {
            throw new Error('Cannot confirm threat on a case that has already been released by an administrator.');
        }
        if (threatObject.review?.status === 'CONFIRMED_THREAT') {
            console.log(`[RemediationEngine] Case ${caseId} is already CONFIRMED_THREAT. Returning existing state (idempotent).`);
            return { success: true, case: threatObject, alreadyCompleted: true };
        }

        const action = this.recordAction({
            case_id: caseId,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'CONFIRM_THREAT',
            status: 'COMPLETED',
            requested_by: adminUser.id || adminUser.email,
            idempotency_key: `confirm_${caseId}`,
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            reason: decisionReason,
            trigger: { type: 'ANALYST_DECISION', policy_id: 'MANUAL' },
            reversible: false,
            target: {
                provider: threatObject.mailbox_provenance?.provider || 'UNKNOWN',
                mailbox: threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient || '',
                message_id: threatObject.mailbox_provenance?.provider_message_id || ''
            }
        });

        threatObject.review.status = 'CONFIRMED_THREAT';
        threatObject.containment_context.decision_reason = decisionReason;
        threatObject.containment_context.admin_note = adminNote || '';
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: 'THREAT_CONFIRMED',
            source: `ADMIN:${adminUser.email}`,
            description: `Admin ${adminUser.email} confirmed threat for Case ${caseId}. The message is retained as evidence and is not deleted.`
        });

        return { success: true, case: threatObject, action };
    }

    getAllActions() {
        return Array.from(this.actions.values());
    }

    getAction(actionId) {
        return this.actions.get(actionId);
    }

    /** Actions raised by policy and waiting on a person. */
    getPendingApprovals() {
        return Array.from(this.actions.values()).filter(a => a.status === 'REQUESTED');
    }
}

module.exports = new RemediationEngine();
module.exports.REMEDIATION_STATUS = REMEDIATION_STATUS;
