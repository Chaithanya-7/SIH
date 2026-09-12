const fs = require('fs');
const path = require('path');
const RemediationAction = require('../models/RemediationAction');
const gmailActionAdapter = require('../adapters/gmailActionAdapter');
const gmailIngestionAdapter = require('../adapters/gmailIngestionAdapter');
const mailboxConnectionManager = require('../modules/mailboxConnectionManager');
const notificationAdapter = require('../adapters/notificationAdapter');
const campaignResponsePlanner = require('./campaignResponsePlanner');
const iocResponseManager = require('./iocResponseManager');
const auditLogger = require('./auditLogger');
const caseManager = require('./caseManager');

class RemediationEngine {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/remediation_actions.json');
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
     * Automatic Policy Evaluation & Containment Execution
     */
    async executePolicyDecision(threatObject, policyDecision) {
        console.log(`[RemediationEngine] Processing policy decision '${policyDecision.policy_id}' for Case ${threatObject.case_id}...`);

        // Track IOCs
        iocResponseManager.processThreatIOCs(threatObject);

        // Generate Campaign Plan if applicable
        if (threatObject.campaign) {
            const campaignPlan = campaignResponsePlanner.generateResponsePlan(threatObject.campaign, [threatObject]);
            threatObject.remediation.campaign_plan = campaignPlan;
        }

        if (policyDecision.authorization_mode === 'NO_ACTION' || policyDecision.action_type === 'NO_ACTION' || threatObject.detection?.verdict === 'SAFE') {
            threatObject.remediation.status = 'NO_ACTION';
            threatObject.mailbox.status = 'INBOX';
            threatObject.review.status = 'NOT_REQUIRED';
            threatObject.provider_action.status = 'NOT_REQUESTED';
            return threatObject;
        }

        // Automatic containment allowed only for HIGH_RISK cases
        if (threatObject.detection?.verdict === 'HIGH_RISK') {
            return await this.executeAutomaticContainment(threatObject, policyDecision);
        } else {
            // SUSPICIOUS or other non-HIGH_RISK verdict -> visible for review, no auto-containment
            threatObject.mailbox.status = 'INBOX';
            threatObject.review.status = 'PENDING_ADMIN';
            threatObject.provider_action.status = 'NOT_REQUESTED';
            return threatObject;
        }
    }

    /**
     * Execute Automatic Containment with Dev Fallback Safety Guard
     */
    async executeAutomaticContainment(threatObject, policyDecision) {
        // 1. Mandatory Development Fallback Safety Guard
        const isDevFallback = !!(threatObject.detection?.is_dev_fallback || threatObject.detection?.verification_status?.includes('DEVELOPMENT'));
        const allowDevContainment = process.env.DEV_ALLOW_FALLBACK_CONTAINMENT === 'true';

        if (isDevFallback && !allowDevContainment) {
            console.warn(`⚠️ [RemediationEngine] DEVELOPMENT / NOT SUBLIME VERIFIED result for ${threatObject.case_id}. Automatic real Gmail containment BLOCKED by dev-safety guard.`);
            threatObject.mailbox.status = 'INBOX';
            threatObject.review.status = 'PENDING_ADMIN';
            threatObject.provider_action.status = 'NOT_REQUESTED';
            threatObject.remediation.status = 'DEV_FALLBACK_GUARD_BLOCKED';

            auditLogger.log({
                case_id: threatObject.case_id,
                org_id: threatObject.org_id,
                event_type: 'CONTAINMENT_SKIPPED_DEV_FALLBACK',
                source: 'REMEDIATION_ENGINE',
                description: `Real automatic Gmail containment blocked because detection is DEVELOPMENT / NOT SUBLIME VERIFIED.`
            });
            return threatObject;
        }

        // 2. Resolve Recipient Mailbox Provenance
        const recipientEmail = threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient;
        const providerMsgId = threatObject.mailbox_provenance?.provider_message_id;

        if (!recipientEmail || !providerMsgId) {
            console.warn(`[RemediationEngine] Cannot execute containment for ${threatObject.case_id}: Missing recipient email or provider_message_id.`);
            threatObject.mailbox.status = 'ACTION_FAILED';
            threatObject.provider_action.status = 'FAILED';
            threatObject.remediation.status = 'FAILED';
            return threatObject;
        }

        // 3. Resolve OAuth Credentials for Recipient Mailbox
        let accessToken = null;
        try {
            accessToken = await gmailIngestionAdapter.getValidAccessTokenByMailbox(recipientEmail);
        } catch (tokenErr) {
            console.warn(`[RemediationEngine] OAuth token resolution failed for mailbox ${recipientEmail}:`, tokenErr.message);
            threatObject.mailbox.status = 'ACTION_FAILED';
            threatObject.provider_action.status = 'FAILED';
            threatObject.remediation.status = 'REAUTH_REQUIRED';
            auditLogger.log({
                case_id: threatObject.case_id,
                org_id: threatObject.org_id,
                event_type: 'CONTAINMENT_FAILED',
                source: 'REMEDIATION_ENGINE',
                description: `Gmail OAuth access token resolution failed for ${recipientEmail}: ${tokenErr.message}`
            });
            return threatObject;
        }

        // 4. Create Durable RemediationAction Record
        const idempotencyKey = `contain_${threatObject.case_id}`;
        const actionRecord = new RemediationAction({
            case_id: threatObject.case_id,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'QUARANTINE',
            status: 'EXECUTING',
            requested_by: 'POLICY_ENGINE',
            idempotency_key: idempotencyKey,
            started_at: new Date().toISOString(),
            target: {
                provider: 'GMAIL',
                mailbox: recipientEmail,
                message_id: providerMsgId
            }
        });
        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();

        threatObject.mailbox.status = 'CONTAINMENT_REQUESTED';
        threatObject.provider_action.status = 'REQUESTED';

        auditLogger.log({
            case_id: threatObject.case_id,
            org_id: threatObject.org_id,
            event_type: 'CONTAINMENT_REQUESTED',
            source: 'REMEDIATION_ENGINE',
            description: `Automated Gmail containment requested for message ${providerMsgId} on recipient mailbox ${recipientEmail}`
        });

        // 5. Execute Gmail Containment & Perform Read-Back Verification
        const result = await gmailActionAdapter.containMessage(accessToken, providerMsgId);

        if (result.verified) {
            threatObject.mailbox.status = 'QUARANTINED';
            threatObject.review.status = 'PENDING_ADMIN';
            threatObject.provider_action.status = 'PROVIDER_CONFIRMED';
            threatObject.containment_context.label_id = result.labelId;
            threatObject.containment_context.contained_at = new Date().toISOString();
            threatObject.remediation.status = 'QUARANTINED';

            actionRecord.status = 'COMPLETED';
            actionRecord.completed_at = new Date().toISOString();
            actionRecord.provider_result = { status: 'PROVIDER_CONFIRMED', message: 'Gmail containment verified via API read-back.' };

            auditLogger.log({
                case_id: threatObject.case_id,
                org_id: threatObject.org_id,
                event_type: 'CONTAINMENT_CONFIRMED',
                source: 'REMEDIATION_ENGINE',
                description: `Gmail containment verified via API read-back. INBOX: absent | SecureMail/Quarantine label: present.`
            });
        } else {
            threatObject.mailbox.status = 'ACTION_FAILED';
            threatObject.provider_action.status = 'FAILED';
            threatObject.remediation.status = 'FAILED';

            actionRecord.status = 'FAILED';
            actionRecord.completed_at = new Date().toISOString();
            actionRecord.failure_reason = result.error;
            actionRecord.provider_result = { status: 'FAILED', message: result.error };

            auditLogger.log({
                case_id: threatObject.case_id,
                org_id: threatObject.org_id,
                event_type: 'CONTAINMENT_FAILED',
                source: 'REMEDIATION_ENGINE',
                description: `Gmail containment failed or provider verification mismatch: ${result.error}`
            });
        }

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();
        return threatObject;
    }

    /**
     * Admin Release Endpoint Logic (Idempotent & Concurrency Safe)
     */
    async releaseCase(caseId, adminUser, decisionReason = 'FALSE_POSITIVE', adminNote = '') {
        const threatObject = caseManager.getCase(caseId);
        if (!threatObject) {
            throw new Error(`Case ${caseId} not found.`);
        }

        // Admin Authorization & Org Isolation Enforcement
        if (!adminUser || adminUser.role !== 'ADMIN') {
            throw new Error('Insufficient permissions. Admin role required.');
        }
        if (threatObject.org_id && adminUser.organization_id && adminUser.organization_id !== threatObject.org_id) {
            throw new Error(`Access denied. Case ${caseId} belongs to another organization.`);
        }

        // Idempotency & Terminal Decision Guard
        if (threatObject.review?.status === 'CONFIRMED_THREAT') {
            throw new Error('Cannot release a case that has been confirmed as a threat by an administrator.');
        }
        if (threatObject.mailbox?.status === 'RELEASED' && threatObject.review?.status === 'RELEASED_BY_ADMIN') {
            console.log(`[RemediationEngine] Case ${caseId} is already RELEASED. Returning existing state (Idempotent).`);
            return { success: true, case: threatObject, alreadyCompleted: true };
        }

        const idempotencyKey = `release_${caseId}`;
        const existingAction = Array.from(this.actions.values()).find(a => a.idempotency_key === idempotencyKey);

        if (existingAction && existingAction.status === 'EXECUTING') {
            throw new Error('A release action is currently executing for this case. Concurrency lock enforced.');
        }

        // Create Durable RemediationAction Record for Release
        const actionRecord = new RemediationAction({
            case_id: caseId,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'RELEASE',
            status: 'EXECUTING',
            requested_by: adminUser.id || adminUser.email,
            idempotency_key: idempotencyKey,
            started_at: new Date().toISOString(),
            reason: decisionReason,
            target: {
                provider: 'GMAIL',
                mailbox: threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient,
                message_id: threatObject.mailbox_provenance?.provider_message_id
            }
        });

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();

        threatObject.mailbox.status = 'RELEASE_REQUESTED';
        threatObject.provider_action.status = 'REQUESTED';
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: 'RELEASE_REQUESTED',
            source: `ADMIN:${adminUser.email}`,
            description: `Admin ${adminUser.email} requested release for Case ${caseId} (Reason: ${decisionReason}).`
        });

        // Resolve Recipient Mailbox OAuth Access Token
        const recipientEmail = threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient;
        const providerMsgId = threatObject.mailbox_provenance?.provider_message_id;

        let accessToken = null;
        try {
            accessToken = await gmailIngestionAdapter.getValidAccessTokenByMailbox(recipientEmail);
        } catch (tokenErr) {
            actionRecord.status = 'FAILED';
            actionRecord.completed_at = new Date().toISOString();
            actionRecord.failure_reason = tokenErr.message;
            this.actions.set(actionRecord.action_id, actionRecord);
            this.saveStorage();

            threatObject.mailbox.status = 'ACTION_FAILED';
            threatObject.provider_action.status = 'FAILED';
            caseManager.saveCase(threatObject);

            auditLogger.log({
                case_id: caseId,
                org_id: threatObject.org_id,
                user_id: adminUser.id,
                event_type: 'RELEASE_FAILED',
                source: 'REMEDIATION_ENGINE',
                description: `Release failed for ${caseId}: Recipient mailbox OAuth token error: ${tokenErr.message}`
            });

            throw new Error(`Gmail release failed: ${tokenErr.message}`);
        }

        // Execute Gmail Release Action & Verification Read-Back
        const labelId = threatObject.containment_context?.label_id;
        const releaseResult = await gmailActionAdapter.releaseMessage(accessToken, providerMsgId, labelId);

        if (releaseResult.verified) {
            threatObject.mailbox.status = 'RELEASED';
            threatObject.review.status = 'RELEASED_BY_ADMIN';
            threatObject.provider_action.status = 'PROVIDER_CONFIRMED';
            threatObject.containment_context.released_at = new Date().toISOString();
            threatObject.containment_context.decision_reason = decisionReason;
            threatObject.containment_context.admin_note = adminNote || '';

            actionRecord.status = 'COMPLETED';
            actionRecord.completed_at = new Date().toISOString();
            actionRecord.provider_result = { status: 'PROVIDER_CONFIRMED', message: 'Gmail release verified via API read-back.' };

            auditLogger.log({
                case_id: caseId,
                org_id: threatObject.org_id,
                user_id: adminUser.id,
                event_type: 'RELEASE_CONFIRMED',
                source: `ADMIN:${adminUser.email}`,
                description: `Gmail release verified for Case ${caseId}. INBOX: restored | Quarantine Label: removed.`
            });
        } else {
            threatObject.mailbox.status = 'ACTION_FAILED';
            threatObject.provider_action.status = 'FAILED';

            actionRecord.status = 'FAILED';
            actionRecord.completed_at = new Date().toISOString();
            actionRecord.failure_reason = releaseResult.error;

            auditLogger.log({
                case_id: caseId,
                org_id: threatObject.org_id,
                user_id: adminUser.id,
                event_type: 'RELEASE_FAILED',
                source: 'REMEDIATION_ENGINE',
                description: `Gmail release verification failed for Case ${caseId}: ${releaseResult.error}`
            });
        }

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();
        caseManager.saveCase(threatObject);

        return {
            success: releaseResult.verified,
            case: threatObject,
            action: actionRecord
        };
    }

    /**
     * Admin Confirm Threat Endpoint Logic (Idempotent & Concurrency Safe)
     */
    async confirmThreat(caseId, adminUser, decisionReason = 'MALICIOUS_PHISH', adminNote = '') {
        const threatObject = caseManager.getCase(caseId);
        if (!threatObject) {
            throw new Error(`Case ${caseId} not found.`);
        }

        // Admin Authorization & Org Isolation Enforcement
        if (!adminUser || adminUser.role !== 'ADMIN') {
            throw new Error('Insufficient permissions. Admin role required.');
        }
        if (threatObject.org_id && adminUser.organization_id && adminUser.organization_id !== threatObject.org_id) {
            throw new Error(`Access denied. Case ${caseId} belongs to another organization.`);
        }

        // Terminal Decision Guard
        if (threatObject.review?.status === 'RELEASED_BY_ADMIN') {
            throw new Error('Cannot confirm threat on a case that has already been released by an administrator.');
        }
        if (threatObject.review?.status === 'CONFIRMED_THREAT') {
            console.log(`[RemediationEngine] Case ${caseId} threat is already CONFIRMED_THREAT. Returning existing state (Idempotent).`);
            return { success: true, case: threatObject, alreadyCompleted: true };
        }

        const idempotencyKey = `confirm_${caseId}`;

        // Create Durable RemediationAction Record
        const actionRecord = new RemediationAction({
            case_id: caseId,
            organization_id: threatObject.org_id,
            mailbox_connection_id: threatObject.mailbox_provenance?.mailbox_connection_id,
            type: 'CONFIRM_THREAT',
            status: 'COMPLETED',
            requested_by: adminUser.id || adminUser.email,
            idempotency_key: idempotencyKey,
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            reason: decisionReason,
            target: {
                provider: 'GMAIL',
                mailbox: threatObject.mailbox_provenance?.provider_account || threatObject.message?.recipient,
                message_id: threatObject.mailbox_provenance?.provider_message_id
            }
        });

        // Update Review Status & Metadata (Message remains in verified quarantine label/state; message is NOT deleted)
        threatObject.review.status = 'CONFIRMED_THREAT';
        threatObject.containment_context.decision_reason = decisionReason;
        threatObject.containment_context.admin_note = adminNote || '';

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();
        caseManager.saveCase(threatObject);

        auditLogger.log({
            case_id: caseId,
            org_id: threatObject.org_id,
            user_id: adminUser.id,
            event_type: 'THREAT_CONFIRMED',
            source: `ADMIN:${adminUser.email}`,
            description: `Admin ${adminUser.email} confirmed threat for Case ${caseId}. Review status: CONFIRMED_THREAT. Mailbox state remains verified quarantine.`
        });

        return {
            success: true,
            case: threatObject,
            action: actionRecord
        };
    }

    getAllActions() {
        return Array.from(this.actions.values());
    }

    getAction(actionId) {
        return this.actions.get(actionId);
    }
}

module.exports = new RemediationEngine();
