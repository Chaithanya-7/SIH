const fs = require('fs');
const path = require('path');
const RemediationAction = require('../models/RemediationAction');
const mailboxActionAdapter = require('../adapters/mailboxActionAdapter');
const notificationAdapter = require('../adapters/notificationAdapter');
const campaignResponsePlanner = require('./campaignResponsePlanner');
const iocResponseManager = require('./iocResponseManager');
const auditLogger = require('./auditLogger');

class RemediationEngine {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/remediation_actions.json');
        this.actions = new Map();
        this.loadStorage();
    }

    loadStorage() {
        try {
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

    async executePolicyDecision(threatObject, policyDecision) {
        console.log(`[RemediationEngine] Processing policy decision '${policyDecision.policy_id}' for Case ${threatObject.case_id}...`);

        // Track IOCs in internal response list
        iocResponseManager.processThreatIOCs(threatObject);

        // Generate Campaign Response Plan if campaign exists
        if (threatObject.campaign) {
            const campaignPlan = campaignResponsePlanner.generateResponsePlan(threatObject.campaign, [threatObject]);
            threatObject.remediation.campaign_plan = campaignPlan;
        }

        if (policyDecision.authorization_mode === 'NO_ACTION' || policyDecision.action_type === 'NO_ACTION') {
            threatObject.remediation.status = 'NO_ACTION';
            auditLogger.log({
                case_id: threatObject.case_id,
                event_type: 'POLICY_EVALUATED',
                source: 'REMEDIATION_ENGINE',
                description: `Policy ${policyDecision.policy_id} evaluated: No remediation required.`
            });
            return threatObject;
        }

        // Initialize RemediationAction Object
        const actionRecord = new RemediationAction({
            case_id: threatObject.case_id,
            campaign_id: threatObject.campaign?.campaign_id || null,
            action_type: policyDecision.action_type,
            status: 'POLICY_TRIGGERED',
            trigger: { type: 'POLICY', policy_id: policyDecision.policy_id },
            reason: policyDecision.reason,
            authorization: {
                mode: policyDecision.authorization_mode,
                authorized_by: policyDecision.authorization_mode === 'AUTO_EXECUTE' ? 'POLICY_ENGINE' : 'AWAITING_APPROVAL',
                authorized_at: new Date().toISOString()
            },
            target: {
                provider: (process.env.REMEDIATION_MODE || 'simulation') === 'live' ? (process.env.MAILBOX_PROVIDER || 'gmail') : 'simulation',
                mailbox: threatObject.message?.recipient || '',
                message_id: threatObject.message?.provider_message_id || threatObject.message?.raw_hash || threatObject.case_id,
                rfc_message_id: threatObject.message?.raw_hash || '',
                raw_hash: threatObject.message?.raw_hash || ''
            }
        });

        // Audit Policy Trigger
        auditLogger.log({
            case_id: threatObject.case_id,
            event_type: 'POLICY_TRIGGERED',
            source: 'REMEDIATION_ENGINE',
            description: `Policy ${policyDecision.policy_id} triggered action ${actionRecord.action_type} (Mode: ${actionRecord.authorization.mode})`
        });

        if (policyDecision.authorization_mode === 'AUTO_EXECUTE') {
            return await this.processExecution(actionRecord, threatObject);
        } else {
            // Require Human SOC Approval
            actionRecord.status = 'ACTION_REQUESTED';
            this.actions.set(actionRecord.action_id, actionRecord);
            this.saveStorage();

            threatObject.remediation.status = 'PENDING_APPROVAL';
            threatObject.remediation.remediation_action_id = actionRecord.action_id;

            auditLogger.log({
                case_id: threatObject.case_id,
                event_type: 'ACTION_REQUESTED',
                source: 'REMEDIATION_ENGINE',
                description: `Action ${actionRecord.action_id} (${actionRecord.action_type}) queued for SOC Analyst approval.`
            });

            return threatObject;
        }
    }

    async processExecution(actionRecord, threatObject) {
        actionRecord.status = 'ACTION_EXECUTING';
        actionRecord.executed_at = new Date().toISOString();

        auditLogger.log({
            case_id: actionRecord.case_id,
            event_type: 'ACTION_EXECUTING',
            source: 'REMEDIATION_ENGINE',
            description: `Executing action ${actionRecord.action_type} via ${actionRecord.target.provider} adapter...`
        });

        if (actionRecord.action_type === 'QUARANTINE_MESSAGE') {
            const providerResult = await mailboxActionAdapter.quarantineMessage(actionRecord.target);
            actionRecord.provider_result = {
                status: providerResult.success ? 'CONFIRMED' : 'FAILED',
                provider_action_id: providerResult.provider_action_id,
                message: providerResult.message
            };

            if (providerResult.success) {
                actionRecord.status = 'ACTION_SUCCEEDED';
                actionRecord.completed_at = new Date().toISOString();
                if (threatObject) threatObject.remediation.status = 'QUARANTINED';
            } else {
                actionRecord.status = 'ACTION_FAILED';
                if (threatObject) threatObject.remediation.status = 'FAILED';
            }
        } else if (actionRecord.action_type === 'ALERT_RECIPIENT') {
            const isContained = threatObject?.remediation?.status === 'QUARANTINED';
            const alertResult = await notificationAdapter.dispatchRecipientWarning(threatObject, isContained);
            actionRecord.status = 'ACTION_SUCCEEDED';
            actionRecord.provider_result = { status: 'CONFIRMED', message: alertResult.message };
            if (threatObject) threatObject.remediation.status = 'USER_WARNED';
        } else if (actionRecord.action_type === 'ALERT_SOC') {
            await notificationAdapter.dispatchSocAlert(threatObject, actionRecord.trigger.policy_id);
            actionRecord.status = 'ACTION_SUCCEEDED';
            actionRecord.provider_result = { status: 'CONFIRMED', message: 'SOC Alert Dispatched' };
        } else {
            actionRecord.status = 'UNSUPPORTED';
            actionRecord.provider_result = { status: 'FAILED', message: `Action type ${actionRecord.action_type} is unsupported.` };
        }

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();

        auditLogger.log({
            case_id: actionRecord.case_id,
            event_type: actionRecord.status === 'ACTION_SUCCEEDED' ? 'ACTION_SUCCEEDED' : 'ACTION_FAILED',
            source: 'REMEDIATION_ENGINE',
            description: `Remediation Action ${actionRecord.action_id} completed with status ${actionRecord.status}: ${actionRecord.provider_result.message}`
        });

        if (threatObject) {
            threatObject.remediation.remediation_action_id = actionRecord.action_id;
            threatObject.remediation.action_record = actionRecord;
        }

        return threatObject;
    }

    async approveAction(actionId, analystUser = 'SOC_ANALYST', reason = 'Manually approved by SOC Analyst') {
        const actionRecord = this.actions.get(actionId);
        if (!actionRecord) throw new Error(`Action ID ${actionId} not found.`);

        console.log(`[RemediationEngine] 👤 Action ${actionId} approved by ${analystUser}: ${reason}`);

        actionRecord.authorization.authorized_by = analystUser;
        actionRecord.authorization.authorized_at = new Date().toISOString();
        actionRecord.reason = `${actionRecord.reason} (Approved by ${analystUser}: ${reason})`;

        auditLogger.log({
            case_id: actionRecord.case_id,
            event_type: 'ACTION_APPROVED',
            source: `ANALYST:${analystUser}`,
            description: `Action ${actionId} approved by ${analystUser}`
        });

        return await this.processExecution(actionRecord, null);
    }

    async rollbackAction(actionId, analystUser = 'SOC_ANALYST', reason = 'False positive restoration requested') {
        const actionRecord = this.actions.get(actionId);
        if (!actionRecord) throw new Error(`Action ID ${actionId} not found.`);
        if (!actionRecord.reversible) throw new Error(`Action ID ${actionId} is not reversible.`);

        console.log(`[RemediationEngine] 🔄 Executing rollback for Action ${actionId} (${analystUser})...`);

        actionRecord.status = 'REVERSAL_REQUESTED';
        auditLogger.log({
            case_id: actionRecord.case_id,
            event_type: 'ROLLBACK_REQUESTED',
            source: `ANALYST:${analystUser}`,
            description: `Rollback requested for Action ${actionId} by ${analystUser}: ${reason}`
        });

        const restoreResult = await mailboxActionAdapter.restoreMessage(actionRecord.target);

        if (restoreResult.success) {
            actionRecord.status = 'REVERSED';
            actionRecord.rollback = {
                status: 'REVERSED',
                reversed_at: new Date().toISOString(),
                reversed_by: analystUser
            };

            auditLogger.log({
                case_id: actionRecord.case_id,
                event_type: 'ROLLBACK_SUCCEEDED',
                source: 'REMEDIATION_ENGINE',
                description: `Rollback completed for Action ${actionId}: Message restored to INBOX.`
            });
        } else {
            actionRecord.status = 'ACTION_FAILED';
            auditLogger.log({
                case_id: actionRecord.case_id,
                event_type: 'ACTION_FAILED',
                source: 'REMEDIATION_ENGINE',
                description: `Rollback failed for Action ${actionId}: ${restoreResult.message}`
            });
        }

        this.actions.set(actionRecord.action_id, actionRecord);
        this.saveStorage();

        return actionRecord;
    }

    getAllActions() {
        return Array.from(this.actions.values());
    }

    getAction(actionId) {
        return this.actions.get(actionId);
    }
}

module.exports = new RemediationEngine();
