/**
 * Analysing mail that arrived a long time ago.
 *
 * A backlog scan runs the same pipeline over the same evidence as a live
 * message, and that is deliberate - a second detection path would be a second
 * thing to keep correct, and it would drift. But some of the pipeline reasons
 * about the state of the world *now*, and for a message from two years ago the
 * world has moved. Those parts do not merely become less useful; several of
 * them invert, and one of them manufactures false accusations at scale.
 *
 * This module is the list of what must be treated differently, and why. It
 * decides nothing itself - it marks what cannot be honestly checked, and the
 * fusion layer leaves those out of the score rather than reading a null as
 * "nothing found".
 *
 * ## 1. DKIM re-verification, which is the dangerous one
 *
 * PhishLens re-verifies DKIM signatures itself, which is the right thing to do
 * on live mail. The signing key comes from DNS at the moment of checking, and
 * domains rotate DKIM selectors as a matter of routine. An eighteen-month-old
 * message frequently names a selector that no longer exists.
 *
 * The result: the message's own Authentication-Results header says `dkim=pass`,
 * independent verification finds nothing because the key is gone, the two
 * disagree - and that disagreement fires MQL-AUTH-102 at CRITICAL, confidence
 * 0.85, on the theory that a forged header was inserted to mislead filters.
 *
 * A retired signing key is not a forged header. Run untreated over a mailbox,
 * this would flag a large share of ordinary old mail, and a backlog scan that
 * cries wolf across two thousand messages is worse than no backlog scan: it
 * gets switched off, and it buries the handful of real findings.
 *
 * ## 2. Everything that describes infrastructure describes it today
 *
 * Domain registration age inverts outright. A domain three days old when it
 * attacked you is two years old now, so the signal that would have caught it
 * is precisely the signal that will not fire. Indicator feeds carry what is
 * malicious now and have long delisted what was malicious then. An address may
 * have changed owner, or stopped resolving entirely.
 *
 * None of that is a reason to skip the scan. It is a reason to say so. A check
 * that ran against the wrong decade and found nothing has not found nothing;
 * it has not checked, and recording it as clean is the failure this project
 * has a standing rule against.
 *
 * ## 3. What is unaffected, which is most of it
 *
 * Bytes do not age. Attachment inspection, the detection rules, text
 * deception, the payload-channel shape, language analysis, relay-chain
 * reconstruction, display-name and lookalike checks, return-path mismatch and
 * QR decoding all read the message as delivered and are exactly as valid on a
 * message from 2023 as on one from this morning. Thread integrity gets
 * *better*, because a backlog supplies the whole conversation rather than a
 * fragment, and campaign correlation improves most of all - a campaign spread
 * across eight months is invisible one message at a time.
 *
 * SPF and DMARC also need no special handling: authAnalyzer already takes them
 * from the receiving server's Authentication-Results header rather than
 * re-deriving them, because it cannot re-derive SPF after delivery without the
 * live connecting IP. That header was written at delivery time, which makes it
 * *more* authoritative for old mail, not less.
 *
 * ## The asymmetry this produces, stated plainly
 *
 * On historical mail a HIGH_RISK verdict is as trustworthy as ever, because
 * every decisive finding is time-independent. A SAFE verdict is weaker than a
 * live SAFE, because some checks genuinely could not run. Each case says which,
 * so a two-year-old SAFE never reads as though it means the same thing.
 */

const MODE = {
    LIVE: 'LIVE',
    HISTORICAL: 'HISTORICAL'
};

/**
 * Checks whose answer describes the present rather than the moment the message
 * arrived. Each carries the reason, which is what a case displays instead of a
 * result.
 */
const TIME_DEPENDENT_CHECKS = [
    {
        id: 'DKIM_INDEPENDENT_VERIFICATION',
        reason: 'The signing key is fetched from DNS when the check runs. Domains rotate DKIM selectors routinely, so an old message often names one that no longer exists - and a key that has been retired is indistinguishable from a signature that never verified.'
    },
    {
        id: 'DOMAIN_REGISTRATION_AGE',
        reason: 'Age is measured from now. A domain registered days before it was used against you is years old today, so the newly-registered signal cannot fire on exactly the messages it exists to catch.'
    },
    {
        id: 'THREAT_INTELLIGENCE_FEEDS',
        reason: 'Open indicator feeds carry what is malicious now. A URL used in a campaign that ended long ago has almost certainly been delisted, so an absence of matches says nothing about what this message was.'
    },
    {
        id: 'IP_REPUTATION_AND_ANONYMISATION',
        reason: 'Reputation, hosting classification and VPN or Tor membership are read live. The address may have changed hands, changed role, or stopped being routed at all since this message was sent.'
    },
    {
        id: 'DNS_RESOLUTION',
        reason: 'Resolution reflects the current record. A domain that has since been taken down will not resolve, which is not evidence about the message - and one that has since been sold may resolve to somebody uninvolved.'
    }
];

class HistoricalMode {
    /** Whether a run is a backlog scan rather than live mail. */
    isHistorical(mode) {
        return mode === MODE.HISTORICAL;
    }

    /**
     * Records on the ThreatObject that the time-dependent checks were skipped,
     * and why each one was.
     *
     * Deliberately written before any of them would have run. A field that is
     * absent because a check was skipped and a field that is absent because a
     * check found nothing look identical afterwards, and the whole point is
     * that they must not.
     */
    markSkippedChecks(threatObject, messageDate) {
        const age = this.describeAge(messageDate);

        threatObject.analysis_mode = {
            mode: MODE.HISTORICAL,
            message_date: messageDate ? new Date(messageDate).toISOString() : null,
            age_days: age.days,
            age_description: age.description,
            checks_not_applicable: TIME_DEPENDENT_CHECKS.map(check => ({
                check: check.id,
                status: 'NOT_APPLICABLE_HISTORICAL',
                reason: check.reason
            })),
            verdict_caveat: 'This message was analysed after the fact. Findings that read the message itself - attachments, detection rules, concealed text, payload shape, language, relay structure, thread integrity - are as valid as on live mail. Checks that describe infrastructure could only describe it as it is now, so they were not run rather than run and recorded as finding nothing. A high-risk verdict here means what it always means; a safe verdict rests on less than a live one does.',
            remediation: 'SUPPRESSED - a backlog scan reports, it does not act on mail the recipient dealt with long ago.'
        };

        return threatObject;
    }

    /** Live analysis, recorded explicitly so a case never has to be read by the absence of a field. */
    markLive(threatObject) {
        threatObject.analysis_mode = {
            mode: MODE.LIVE,
            checks_not_applicable: [],
            verdict_caveat: null
        };
        return threatObject;
    }

    /**
     * Suppresses the DKIM disagreement finding on historical mail.
     *
     * Not by deleting the verification - what was found is still recorded and
     * still visible on the case - but by replacing the *disagreement* with the
     * honest reading of it. The header and the live check differ because the
     * key is gone, which is a fact about DNS today and not about this message.
     */
    reconcileDkim(threatObject) {
        const auth = threatObject.forensics?.authentication;
        if (!auth || !auth.dkim_header_mismatch) return threatObject;

        const independent = auth.dkim_independent_verification || {};
        const claimed = auth.dkim;

        // The specific shape caused by a rotated key: the header recorded a
        // pass at delivery, and today there is no key to verify against.
        const keyProbablyRetired = claimed === 'pass'
            && ['none', 'unknown', 'neutral', 'temperror', 'permerror'].includes(independent.overall);

        if (keyProbablyRetired) {
            auth.dkim_key_unavailable = true;
            auth.dkim_header_mismatch_suppressed = auth.dkim_header_mismatch;
            auth.dkim_header_mismatch = null;
            auth.dkim_historical_note = 'The Authentication-Results header recorded a DKIM pass at delivery, and the signing key can no longer be fetched - the selector has almost certainly been rotated out since. The header result is taken as authoritative, because it was written when the key still existed. This is not treated as a forged header: on mail this old, a missing key is the ordinary case.';
        } else if (claimed === 'pass' && independent.overall === 'fail') {
            // A signature that is present and actively fails is different, and
            // is left alone. That is not a missing key; something does not
            // verify against a key that is still published.
            auth.dkim_historical_note = 'The signature was checked against a key that is still published and did not verify. Unlike a missing selector, this is not explained by the age of the message.';
        }

        return threatObject;
    }

    describeAge(messageDate) {
        if (!messageDate) return { days: null, description: 'The message carries no usable date.' };

        const then = new Date(messageDate).getTime();
        if (!Number.isFinite(then)) return { days: null, description: 'The message date could not be read.' };

        const days = Math.max(0, Math.round((Date.now() - then) / 86400000));
        if (days < 30) return { days, description: `${days} day(s) old. Recent enough that the live checks would still have been broadly meaningful, but they were skipped for consistency across the scan.` };
        if (days < 365) return { days, description: `${Math.round(days / 30)} month(s) old.` };
        return { days, description: `${(days / 365).toFixed(1)} year(s) old. Infrastructure evidence about a message this age would describe a different internet.` };
    }
}

module.exports = new HistoricalMode();
module.exports.MODE = MODE;
module.exports.TIME_DEPENDENT_CHECKS = TIME_DEPENDENT_CHECKS;
