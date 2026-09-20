const gmailActionAdapter = require('../adapters/gmailActionAdapter');
const imapActionAdapter = require('../adapters/imapActionAdapter');
const gmailIngestionAdapter = require('../adapters/gmailIngestionAdapter');

/**
 * Every change PhishLens makes to somebody's real mailbox passes through here.
 *
 * It exists because the alternative was demonstrably unsafe. The remediation
 * engine used to call the Gmail adapter directly, so REMEDIATION_MODE decided
 * nothing at all: the server printed "Remediation Mode: simulation" at boot,
 * /api/summary reported SIMULATION to the console, and the code underneath
 * would still have issued a real Gmail modify call. The only reason no live
 * mail was touched was that no mailbox had been connected yet. Connecting one
 * would have turned a setting that reads as a safety switch into a label on a
 * live wire.
 *
 * A single chokepoint is what makes the mode statement true rather than
 * aspirational, so the provider adapters are deliberately reached from here
 * and nowhere else.
 */

const MODE = { SIMULATION: 'simulation', LIVE: 'live' };

/**
 * Outcomes are distinguished because conflating them is how a system ends up
 * lying about itself.
 *
 *   CONTAINED / RELEASED - the provider was changed and the change was read
 *                          back and confirmed. Only these mean anything moved.
 *   SIMULATED            - the decision was made and deliberately not carried
 *                          out. It is not containment and must never be
 *                          counted as containment.
 *   NOT_ACTIONABLE       - there is no mailbox to reach into. A normal,
 *                          expected result for a message that arrived as bytes.
 *   FAILED               - we tried to change a real mailbox and could not.
 *                          This is the only one that warrants an alarm.
 */
const OUTCOME = {
    CONTAINED: 'CONTAINED',
    RELEASED: 'RELEASED',
    WARNED: 'WARNED',
    SIMULATED: 'SIMULATED',
    NOT_ACTIONABLE: 'NOT_ACTIONABLE',
    FAILED: 'FAILED'
};

class RemediationGateway {
    constructor() {
        /**
         * Keyed by the provider recorded on the message's provenance, so the
         * choice of adapter follows where the message actually came from
         * rather than a global assumption about what this installation runs.
         */
        this.providers = {
            GMAIL: {
                label: 'Gmail API',
                quarantine: (target) => this.gmailQuarantine(target),
                release: (target) => this.gmailRelease(target),
                warn: (target) => this.gmailWarn(target)
            },
            IMAP: {
                label: 'IMAP',
                quarantine: (target) => imapActionAdapter.quarantineMessage(target),
                release: (target) => imapActionAdapter.releaseMessage(target),
                warn: (target) => imapActionAdapter.markSuspicious(target)
            }
        };
    }

    mode() {
        return (process.env.REMEDIATION_MODE || MODE.SIMULATION).toLowerCase() === MODE.LIVE
            ? MODE.LIVE
            : MODE.SIMULATION;
    }

    isLive() {
        return this.mode() === MODE.LIVE;
    }

    /**
     * Whether this message can be acted on at all, and if not, why not.
     *
     * Actionability is a property of how the message reached us, not of a
     * configuration flag. A message pulled from a mailbox we hold credentials
     * for can be moved. A message posted to /api/ingest/file, or handed to the
     * SMTP listener, exists only as the bytes somebody gave us - there is no
     * mailbox on the other end to reach into, and pretending otherwise
     * produced the bug this replaces: every high-risk case was marked
     * ACTION_FAILED, so the console showed a wall of failures for messages
     * that were never actionable in the first place. Genuine provider failures
     * were indistinguishable from them.
     */
    resolveTarget(threatObject) {
        const provenance = threatObject.mailbox_provenance || {};
        const provider = String(provenance.provider || '').toUpperCase();
        const messageId = provenance.provider_message_id;
        const mailbox = provenance.provider_account || threatObject.message?.recipient || '';

        if (!messageId) {
            return {
                actionable: false,
                provider,
                mailbox,
                message_id: null,
                reason: 'NO_PROVIDER_HANDLE',
                detail: `This message was analysed from content supplied to PhishLens (${threatObject.message?.source || 'unknown source'}), not read from a connected mailbox. There is no provider message to move, so mailbox containment does not apply.`
            };
        }

        if (!this.providers[provider]) {
            return {
                actionable: false,
                provider,
                mailbox,
                message_id: messageId,
                reason: 'NO_ADAPTER_FOR_PROVIDER',
                detail: `No mailbox action adapter is implemented for provider '${provider || 'UNSPECIFIED'}', so PhishLens cannot move this message.`
            };
        }

        if (!mailbox) {
            return {
                actionable: false,
                provider,
                mailbox,
                message_id: messageId,
                reason: 'NO_MAILBOX_ACCOUNT',
                detail: 'The message carries a provider handle but no mailbox account, so the action cannot be addressed to an account.'
            };
        }

        return {
            actionable: true,
            provider,
            mailbox,
            message_id: messageId,
            rfc_message_id: threatObject.message?.message_id || null,
            mailbox_connection_id: provenance.mailbox_connection_id || null,
            uid: provenance.uid || null,
            folder: provenance.folder || null
        };
    }

    /**
     * What would happen to this message, stated before anything happens.
     *
     * The operator needs to be able to answer "what will switching to live
     * actually do to my mail?" without switching to live to find out.
     */
    preview(threatObject) {
        const target = this.resolveTarget(threatObject);
        return {
            mode: this.mode(),
            actionable: target.actionable,
            provider: target.provider || null,
            mailbox: target.mailbox || null,
            would_execute: target.actionable && this.isLive(),
            explanation: !target.actionable
                ? target.detail
                : this.isLive()
                    ? `Live mode: the message would be moved out of the inbox in ${target.mailbox} via ${this.providers[target.provider].label}, and the move read back to confirm it.`
                    : `Simulation mode: the decision is recorded, and the message in ${target.mailbox} is left exactly where it is. Set REMEDIATION_MODE=live to carry it out.`
        };
    }

    async quarantine(threatObject) {
        const target = this.resolveTarget(threatObject);

        if (!target.actionable) {
            return {
                outcome: OUTCOME.NOT_ACTIONABLE,
                mode: this.mode(),
                verified: false,
                provider: target.provider || null,
                mailbox: target.mailbox || null,
                reason: target.reason,
                detail: target.detail
            };
        }

        if (!this.isLive()) {
            console.log(`[RemediationGateway] SIMULATION: containment decided for case ${threatObject.case_id} and deliberately not carried out. ${target.mailbox} is untouched.`);
            return {
                outcome: OUTCOME.SIMULATED,
                mode: MODE.SIMULATION,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                intended_action: 'QUARANTINE',
                detail: `Simulation mode. The message was left in ${target.mailbox}. This is a recorded decision, not containment.`
            };
        }

        console.log(`[RemediationGateway] LIVE: executing containment for case ${threatObject.case_id} on ${target.mailbox} via ${target.provider}.`);
        try {
            const result = await this.providers[target.provider].quarantine(target);
            return this.interpret(result, target, OUTCOME.CONTAINED, 'QUARANTINE');
        } catch (e) {
            return {
                outcome: OUTCOME.FAILED,
                mode: MODE.LIVE,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                detail: `Provider containment call failed: ${e.message}`
            };
        }
    }

    async release(threatObject) {
        const target = this.resolveTarget(threatObject);

        if (!target.actionable) {
            return {
                outcome: OUTCOME.NOT_ACTIONABLE,
                mode: this.mode(),
                verified: false,
                provider: target.provider || null,
                mailbox: target.mailbox || null,
                reason: target.reason,
                detail: target.detail
            };
        }

        if (!this.isLive()) {
            return {
                outcome: OUTCOME.SIMULATED,
                mode: MODE.SIMULATION,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                intended_action: 'RELEASE',
                detail: `Simulation mode. Nothing was moved, because nothing was contained: the message never left ${target.mailbox}.`
            };
        }

        try {
            const enriched = { ...target, label_id: threatObject.containment_context?.label_id || null };
            const result = await this.providers[target.provider].release(enriched);
            return this.interpret(result, target, OUTCOME.RELEASED, 'RELEASE');
        } catch (e) {
            return {
                outcome: OUTCOME.FAILED,
                mode: MODE.LIVE,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                detail: `Provider release call failed: ${e.message}`
            };
        }
    }

    /**
     * A provider result only counts as success if the provider itself confirmed
     * the new state on read-back. An accepted API call is not evidence that a
     * message moved.
     */
    interpret(result, target, successOutcome, intendedAction) {
        if (result && result.verified) {
            return {
                outcome: successOutcome,
                mode: MODE.LIVE,
                verified: true,
                provider: target.provider,
                mailbox: target.mailbox,
                intended_action: intendedAction,
                label_id: result.labelId || result.label_id || null,
                folder: result.folder || null,
                detail: result.detail || `${target.provider} confirmed the change on read-back.`
            };
        }
        return {
            outcome: OUTCOME.FAILED,
            mode: MODE.LIVE,
            verified: false,
            provider: target.provider,
            mailbox: target.mailbox,
            intended_action: intendedAction,
            detail: result?.error || 'The provider did not confirm the change on read-back.'
        };
    }

    /**
     * Mark a message so its recipient sees a warning, leaving it delivered.
     *
     * Kept behind the same gate as containment even though it is far less
     * intrusive, because it is still a change to somebody's mailbox and the
     * mode statement has to cover every change without exception.
     */
    async warn(threatObject) {
        const target = this.resolveTarget(threatObject);

        if (!target.actionable) {
            return {
                outcome: OUTCOME.NOT_ACTIONABLE,
                mode: this.mode(),
                verified: false,
                provider: target.provider || null,
                mailbox: target.mailbox || null,
                reason: target.reason,
                detail: target.detail
            };
        }

        if (!this.isLive()) {
            return {
                outcome: OUTCOME.SIMULATED,
                mode: MODE.SIMULATION,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                intended_action: 'WARN',
                detail: `Simulation mode. The warning is recorded on the case; nothing was marked in ${target.mailbox}.`
            };
        }

        try {
            const result = await this.providers[target.provider].warn(target);
            return this.interpret(result, target, OUTCOME.WARNED, 'WARN');
        } catch (e) {
            return {
                outcome: OUTCOME.FAILED,
                mode: MODE.LIVE,
                verified: false,
                provider: target.provider,
                mailbox: target.mailbox,
                detail: `Provider warning call failed: ${e.message}`
            };
        }
    }

    async gmailWarn(target) {
        const accessToken = await gmailIngestionAdapter.getValidAccessTokenByMailbox(target.mailbox);
        return await gmailActionAdapter.markSuspicious(accessToken, target.message_id);
    }

    async gmailQuarantine(target) {
        const accessToken = await gmailIngestionAdapter.getValidAccessTokenByMailbox(target.mailbox);
        return await gmailActionAdapter.containMessage(accessToken, target.message_id);
    }

    async gmailRelease(target) {
        const accessToken = await gmailIngestionAdapter.getValidAccessTokenByMailbox(target.mailbox);
        return await gmailActionAdapter.releaseMessage(accessToken, target.message_id, target.label_id);
    }

    /**
     * What the console and the operator should be told about this installation's
     * ability to act, in terms that do not overstate it.
     */
    capability() {
        const live = this.isLive();
        return {
            mode: this.mode(),
            providers_implemented: Object.keys(this.providers),
            can_act_on_mail: live,
            statement: live
                ? 'Live mode. Confirmed high-risk mail in a connected mailbox will be moved out of the inbox, and every move is read back and confirmed before it is reported as contained.'
                : 'Simulation mode. PhishLens decides what it would do and records it, but does not change any mailbox. Nothing reported here has moved a message.'
        };
    }
}

module.exports = new RemediationGateway();
module.exports.OUTCOME = OUTCOME;
module.exports.MODE = MODE;
