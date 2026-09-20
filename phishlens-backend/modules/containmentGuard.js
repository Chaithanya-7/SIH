const fs = require('fs');
const path = require('path');
const { dataFile } = require('./dataPaths');

/**
 * The last thing consulted before PhishLens moves somebody's mail by itself.
 *
 * This replaces a guard that looked protective and was not. The previous one
 * refused containment when `detection.is_dev_fallback` was set or
 * `verification_status` contained "DEVELOPMENT" - fields left over from the
 * era when detection was delegated to an external service. In the current
 * pipeline is_dev_fallback is assigned the literal value false and
 * verification_status is always PHISHLENS_NATIVE_MQL_VERIFIED, so the
 * condition could never be true and the guard could never fire. It read, to
 * anyone auditing the file, as a safety interlock that was in fact inert.
 *
 * What replaces it refuses on grounds that can actually occur, and each refusal
 * names itself so an operator can see which control stopped an action.
 */

const DEFAULTS = {
    // Automatic containment needs more than the 0.70 that makes a verdict
    // HIGH_RISK. A human reviewing a queue and a machine moving mail unasked
    // are different risks and should not share a threshold.
    minimumConfidence: 0.85,
    // A rule that starts misfiring should not be able to empty an inbox before
    // anyone notices. Past this many automatic containments in the window,
    // PhishLens stops acting on its own and leaves the rest for review.
    burstLimit: 10,
    burstWindowMinutes: 60
};

class ContainmentGuard {
    constructor() {
        this.configFile = dataFile('containment_guard.json');
        this.recentAutomaticActions = [];
        this.config = { ...DEFAULTS, neverContain: [] };
        this.load();
    }

    load() {
        try {
            const dir = path.dirname(this.configFile);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            if (fs.existsSync(this.configFile)) {
                const stored = JSON.parse(fs.readFileSync(this.configFile, 'utf8') || '{}');
                this.config = {
                    minimumConfidence: Number.isFinite(stored.minimum_confidence) ? stored.minimum_confidence : DEFAULTS.minimumConfidence,
                    burstLimit: Number.isFinite(stored.burst_limit) ? stored.burst_limit : DEFAULTS.burstLimit,
                    burstWindowMinutes: Number.isFinite(stored.burst_window_minutes) ? stored.burst_window_minutes : DEFAULTS.burstWindowMinutes,
                    neverContain: Array.isArray(stored.never_contain) ? stored.never_contain.map(v => String(v).toLowerCase().trim()).filter(Boolean) : []
                };
            }
        } catch (e) {
            console.error('[ContainmentGuard] Could not read guard configuration, falling back to defaults:', e.message);
        }
    }

    save() {
        try {
            fs.writeFileSync(this.configFile, JSON.stringify({
                minimum_confidence: this.config.minimumConfidence,
                burst_limit: this.config.burstLimit,
                burst_window_minutes: this.config.burstWindowMinutes,
                never_contain: this.config.neverContain,
                updated_at: new Date().toISOString()
            }, null, 2), 'utf8');
        } catch (e) {
            console.error('[ContainmentGuard] Could not persist guard configuration:', e.message);
        }
    }

    /**
     * Senders the operator has decided must never be contained without a human
     * saying so. The realistic failure this prevents is a detection change that
     * starts quarantining payroll, a regulator, or the service desk - mail
     * whose delay costs more than the phishing it might occasionally be.
     *
     * Entries may be a full address or a bare domain.
     */
    addNeverContain(entry) {
        const value = String(entry || '').toLowerCase().trim();
        if (!value) throw new Error('An address or domain is required.');
        if (!this.config.neverContain.includes(value)) {
            this.config.neverContain.push(value);
            this.save();
        }
        return this.config.neverContain;
    }

    removeNeverContain(entry) {
        const value = String(entry || '').toLowerCase().trim();
        this.config.neverContain = this.config.neverContain.filter(v => v !== value);
        this.save();
        return this.config.neverContain;
    }

    isNeverContain(senderAddress) {
        const sender = String(senderAddress || '').toLowerCase().trim();
        if (!sender) return false;
        const domain = sender.includes('@') ? sender.split('@').pop() : sender;
        return this.config.neverContain.some(entry => entry === sender || entry === domain);
    }

    /**
     * Independent corroboration, counted by evidence family.
     *
     * Several findings inside one family are usually one fact seen from
     * different angles - SPF and DMARC fail together because the same
     * alignment is wrong. Automatic action should rest on facts that are
     * genuinely separate, so families are what gets counted.
     *
     * LEARNED_PATTERN is excluded on purpose. What the system taught itself may
     * confirm a case but must not be one of the two legs it stands on, or a
     * mistaken lesson would be able to justify acting on the next message that
     * resembles it. DECISIVE_FINDING is excluded because it is a floor applied
     * to the score, not an additional observation.
     */
    independentFamilies(threatObject) {
        const excluded = new Set(['DECISIVE_FINDING', 'LEARNED_PATTERN']);
        return (threatObject.confidence?.contributions || [])
            .map(c => c.family)
            .filter(family => !excluded.has(family));
    }

    hasDecisiveFinding(threatObject) {
        return (threatObject.evidence || []).some(e => e.decisive);
    }

    pruneBurstWindow() {
        const cutoff = Date.now() - this.config.burstWindowMinutes * 60 * 1000;
        this.recentAutomaticActions = this.recentAutomaticActions.filter(ts => ts >= cutoff);
    }

    recordAutomaticAction() {
        this.recentAutomaticActions.push(Date.now());
    }

    /**
     * Returns { allowed, control, reason }. `control` names which check
     * refused, so the audit trail records the specific control rather than a
     * generic denial.
     */
    evaluate(threatObject) {
        const confidence = threatObject.confidence?.threat || 0;
        const verdict = threatObject.detection?.verdict;

        if (verdict !== 'HIGH_RISK') {
            return {
                allowed: false,
                control: 'VERDICT_FLOOR',
                reason: `Automatic containment applies only to HIGH_RISK mail. This case is ${verdict || 'unclassified'}, so it goes to review instead.`
            };
        }

        if (confidence < this.config.minimumConfidence) {
            return {
                allowed: false,
                control: 'CONFIDENCE_FLOOR',
                reason: `Threat confidence ${confidence.toFixed(2)} is below the ${this.config.minimumConfidence} required to move mail without a human. The case is queued for review rather than contained.`
            };
        }

        const families = this.independentFamilies(threatObject);
        if (families.length < 2 && !this.hasDecisiveFinding(threatObject)) {
            return {
                allowed: false,
                control: 'CORROBORATION',
                reason: `Only one independent evidence family (${families.join(', ') || 'none'}) supports this verdict and nothing about it is individually decisive. One signal is not enough to move somebody's mail automatically.`
            };
        }

        const sender = threatObject.message?.sender || threatObject.message?.from || '';
        if (this.isNeverContain(sender)) {
            return {
                allowed: false,
                control: 'NEVER_CONTAIN_LIST',
                reason: `The sender ${sender} is on the operator's never-contain list. The case is raised for review and the message is left in place.`
            };
        }

        this.pruneBurstWindow();
        if (this.recentAutomaticActions.length >= this.config.burstLimit) {
            return {
                allowed: false,
                control: 'BURST_LIMIT',
                reason: `PhishLens has already contained ${this.recentAutomaticActions.length} message(s) automatically in the last ${this.config.burstWindowMinutes} minutes, which is the configured ceiling. Further containment is held for review in case a detection change is misfiring.`
            };
        }

        return {
            allowed: true,
            control: null,
            reason: `Confidence ${confidence.toFixed(2)} with ${families.length} independent evidence famil${families.length === 1 ? 'y' : 'ies'} (${families.join(', ')})${this.hasDecisiveFinding(threatObject) ? ' including a decisive finding' : ''}.`
        };
    }

    state() {
        this.pruneBurstWindow();
        return {
            minimum_confidence: this.config.minimumConfidence,
            burst_limit: this.config.burstLimit,
            burst_window_minutes: this.config.burstWindowMinutes,
            automatic_actions_in_window: this.recentAutomaticActions.length,
            never_contain: [...this.config.neverContain]
        };
    }
}

module.exports = new ContainmentGuard();
