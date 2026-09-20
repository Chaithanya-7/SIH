/**
 * ARC chain analysis, per RFC 8617.
 *
 * ARC exists because ordinary authentication breaks on forwarding. A mailing
 * list or forwarder that rewrites a message destroys the DKIM signature and
 * sends from its own IP, so SPF and DKIM fail for mail that was perfectly
 * legitimate when it was sent. ARC records what each intermediary saw, so the
 * final receiver can look back along the chain.
 *
 * The reason this module exists as its own thing, rather than being folded into
 * the authentication result, is the warning RFC 8617 gives in §9:
 *
 *     ARC authenticates the identity of the actors that handled a message.
 *     It says nothing about whether those actors are trustworthy.
 *
 * So a valid ARC chain is not a reason to treat a message as safe, and
 * PhishLens must never let one raise confidence. What a chain is good for is
 * the opposite: explaining *why* SPF or DKIM failed on a message that was
 * genuinely forwarded, so an honest forward is not scored as a spoof. And a
 * chain that is broken, or one whose intermediaries are not recognised, is a
 * signal in its own right - forging a plausible-looking ARC chain is a way of
 * manufacturing an excuse for failed authentication.
 */

const SEALED = 'SEALED';
const BROKEN = 'BROKEN';
const ABSENT = 'ABSENT';

class ArcAnalyzer {
    /**
     * Pulls every ARC header set out of the raw message.
     *
     * Parsed from the raw text rather than a header map because ARC sets are
     * numbered by an `i=` instance tag and there is one of each header per hop,
     * so the ordering and repetition both matter and a flattened map loses them.
     */
    extractSets(rawEmailString) {
        if (!rawEmailString) return [];

        const headerBlock = rawEmailString.split(/\r?\n\r?\n/)[0] || '';
        // Unfold continuation lines (RFC 5322 §2.2.3) before matching.
        const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
        const sets = new Map();

        const patterns = [
            { field: 'seal', re: /^ARC-Seal:\s*(.+)$/gim },
            { field: 'message_signature', re: /^ARC-Message-Signature:\s*(.+)$/gim },
            { field: 'authentication_results', re: /^ARC-Authentication-Results:\s*(.+)$/gim }
        ];

        for (const { field, re } of patterns) {
            let match;
            while ((match = re.exec(unfolded)) !== null) {
                const value = match[1].trim();
                const instanceMatch = value.match(/\bi\s*=\s*(\d+)/i);
                const instance = instanceMatch ? parseInt(instanceMatch[1], 10) : null;
                if (instance === null) continue;
                if (!sets.has(instance)) sets.set(instance, { instance });
                sets.get(instance)[field] = value;
            }
        }

        return Array.from(sets.values()).sort((a, b) => a.instance - b.instance);
    }

    tag(value, name) {
        if (!value) return null;
        const match = value.match(new RegExp(`\\b${name}\\s*=\\s*([^;\\s]+)`, 'i'));
        return match ? match[1] : null;
    }

    /**
     * Structural validation only, stated plainly.
     *
     * PhishLens checks that the chain is well-formed: instances numbered from 1
     * without gaps, each set complete, and the `cv=` chain-validation tags
     * consistent with RFC 8617 §5.2 (the first is `none`, every later one is
     * `pass`, and a `fail` anywhere terminates the chain permanently).
     *
     * It does not re-verify the ARC seal signatures cryptographically. Doing so
     * needs each intermediary's public key and the exact canonicalised bytes
     * they signed, and getting that subtly wrong would produce confident
     * nonsense. An unverified chain is reported as unverified rather than
     * assumed good - which costs nothing here, because a passing chain is not
     * allowed to lower risk anyway.
     */
    analyze(threatObject, rawEmailString) {
        const sets = this.extractSets(rawEmailString);

        if (sets.length === 0) {
            threatObject.forensics = threatObject.forensics || {};
            threatObject.forensics.arc = {
                status: ABSENT,
                hops: 0,
                intermediaries: [],
                explanation: 'No ARC headers. The message was not handled by an intermediary that participates in ARC, which is the normal case for directly delivered mail.',
                affects_risk: false
            };
            return threatObject;
        }

        const problems = [];
        const intermediaries = [];

        sets.forEach((set, index) => {
            const expected = index + 1;
            if (set.instance !== expected) {
                problems.push(`Instance ${set.instance} appears where i=${expected} was expected, so the chain has a gap or is out of order.`);
            }
            if (!set.seal) problems.push(`Set i=${set.instance} has no ARC-Seal.`);
            if (!set.message_signature) problems.push(`Set i=${set.instance} has no ARC-Message-Signature.`);
            if (!set.authentication_results) problems.push(`Set i=${set.instance} has no ARC-Authentication-Results.`);

            const cv = (this.tag(set.seal, 'cv') || '').toLowerCase();
            if (index === 0 && cv && cv !== 'none') {
                problems.push(`The first set declares cv=${cv}; RFC 8617 requires cv=none on i=1.`);
            }
            if (index > 0 && cv && cv !== 'pass') {
                problems.push(`Set i=${set.instance} declares cv=${cv}, which terminates the chain - a later hop found the chain already broken.`);
            }

            intermediaries.push({
                instance: set.instance,
                signing_domain: this.tag(set.seal, 'd') || this.tag(set.message_signature, 'd') || null,
                chain_validation: cv || null,
                authentication_seen: this.summariseResults(set.authentication_results)
            });
        });

        const status = problems.length === 0 ? SEALED : BROKEN;

        threatObject.forensics = threatObject.forensics || {};
        threatObject.forensics.arc = {
            status,
            hops: sets.length,
            intermediaries,
            problems,
            verification: 'STRUCTURAL_ONLY',
            explanation: status === SEALED
                ? `A structurally valid ARC chain of ${sets.length} hop(s). Per RFC 8617 §9 this identifies who handled the message, and says nothing about whether they are trustworthy - it is recorded as context and is not treated as evidence of safety.`
                : `The ARC chain is malformed: ${problems.join(' ')} A broken or forged chain is itself worth noting, because a plausible-looking chain is a way to manufacture an excuse for failed SPF or DKIM.`,
            // Never true. Stated as a field rather than left implicit so that
            // anyone wiring ARC into scoring later has to change this line and
            // read the reason for it.
            affects_risk: false,
            risk_note: 'ARC never lowers risk in PhishLens. RFC 8617 §9: authenticated is not the same as safe.'
        };

        return threatObject;
    }

    /** What the intermediary said it saw, which is the useful part of the set. */
    summariseResults(authenticationResults) {
        if (!authenticationResults) return null;
        return {
            spf: this.tag(authenticationResults, 'spf'),
            dkim: this.tag(authenticationResults, 'dkim'),
            dmarc: this.tag(authenticationResults, 'dmarc')
        };
    }

    /**
     * Whether a failed SPF or DKIM result is explained by legitimate forwarding.
     *
     * Used to soften an authentication finding rather than to raise one: a
     * message that fails SPF at the final hop but whose ARC chain records an
     * earlier hop seeing spf=pass is the ordinary mailing-list case, and
     * scoring it as a spoof is a false positive an operator will see constantly.
     *
     * Deliberately conservative - it only applies where the chain is
     * structurally intact and an earlier hop actually recorded a pass.
     */
    explainsAuthenticationFailure(threatObject) {
        const arc = threatObject.forensics?.arc;
        if (!arc || arc.status !== SEALED) return null;

        const sawPass = (arc.intermediaries || []).find(hop =>
            hop.authentication_seen && (hop.authentication_seen.spf === 'pass' || hop.authentication_seen.dkim === 'pass'));

        if (!sawPass) return null;

        return {
            explained: true,
            by: sawPass.signing_domain,
            detail: `An intermediary (${sawPass.signing_domain || 'unnamed'}) recorded spf=${sawPass.authentication_seen.spf || 'n/a'} and dkim=${sawPass.authentication_seen.dkim || 'n/a'} before forwarding. Authentication failing at the final hop is consistent with ordinary forwarding rather than spoofing. This does not make the message safe - only the authentication failure less meaningful.`
        };
    }
}

module.exports = new ArcAnalyzer();
module.exports.STATUS = { SEALED, BROKEN, ABSENT };
