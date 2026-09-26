class ConfidenceEngine {
    evidenceFamily(evidence) {
        const type = String(evidence.evidence_type);
        if (type === 'AUTHENTICATION_ANOMALY' || type === 'MQL_AUTH') return 'AUTHENTICATION';
        if (type.startsWith('NLP_') || type === 'MQL_NLP') return 'LANGUAGE';
        if (['CAMPAIGN_ASSOCIATION', 'REPEATED_IP', 'REPEATED_DOMAIN', 'SHARED_INFRASTRUCTURE', 'EXECUTIVE_TARGETING_PATTERN'].includes(type)) return 'CAMPAIGN';
        if (type === 'IDENTITY_SPOOF' || type === 'MQL_DOM' || type === 'MQL_IMP') return 'IDENTITY';
        if (['INFRASTRUCTURE_ANOMALY', 'REPUTATION_RISK'].includes(type)) return 'INFRASTRUCTURE';
        // Authentication-flow abuse and QR links are link risks: the QR code
        // resolves to a URL, and every URL in a device-code message is to a
        // genuine provider endpoint. The AUTHFLOW rules carried a comment
        // saying they belonged to URL_RISK while nothing mapped them, so they
        // were silently forming a family of their own and counting as
        // independent of URL findings they are not independent of.
        if (type === 'MQL_URL' || type === 'MQL_AUTHFLOW' || type === 'MQL_QR') return 'URL_RISK';

        // Where the payload lives when there is nothing conventional to
        // inspect: a telephone number and no link, or a message rendered as a
        // picture. This family exists precisely for attacks that leave every
        // other family with nothing to contribute, so capping it low would
        // mean they could never reach a verdict - which is the gap they are
        // built to exploit.
        if (type === 'MQL_TOAD' || type === 'MQL_IMAGE') return 'PAYLOAD_CHANNEL';

        // Abuse of a legitimate platform. Same reasoning inverted: these
        // messages authenticate correctly and genuinely, so AUTHENTICATION -
        // the strongest family here - contributes nothing to them.
        if (type === 'MQL_LOTS') return 'TRUSTED_SERVICE';

        // Deliberate obfuscation of the text, kept apart from what the text
        // says. Hiding from the reader is a different act from the content,
        // and folding it into LANGUAGE would let one message's obfuscation
        // crowd out its own words under a shared cap.
        if (type === 'MQL_DECEPTION') return 'DECEPTION';

        // Declared rather than left to the fallthrough. These were already
        // forming families of their own at the default cap; naming them makes
        // that a decision rather than an accident of ordering.
        if (type === 'MQL_THREAD') return 'THREAD_INTEGRITY';
        if (type === 'MQL_ARC') return 'AUTHENTICATION';

        // The one family whose evidence does not come from the message. A packet
        // capture on this machine observed traffic reaching a destination the
        // message named - so unlike everything else here, it cannot have been
        // written by the sender.
        // Deliberately one member. No MQL rule was written for the same fact:
        // the observation already enters through fusion as a decisive finding,
        // and a rule asserting it again would be one event counted twice.
        if (type === 'CONNECTION_OBSERVED') return 'CONNECTION';

        // Both belong to the same family: the MQL rules judge an attachment by
        // its name and declared type, the inspector and the detection rules by
        // its contents. Kept apart they would count as two independent kinds of
        // evidence for what is one attachment being wrong.
        if (type === 'MQL_ATT' || type === 'ATTACHMENT_CONTENT') return 'ATTACHMENT_RISK';
        if (type === 'MQL_BEC') return 'BEC_COMPOSITE';
        if (type === 'MQL_INTEL') return 'THREAT_INTEL';
        if (type === 'MQL_CUSTOM') return 'CUSTOM';
        if (type.startsWith('BEHAVIOUR_')) return 'BEHAVIOURAL';
        if (type.startsWith('EXECUTIVE_') || type === 'LOOKALIKE_ORGANIZATION_DOMAIN' || type === 'PROTECTED_PERSON_TARGETED') return 'EXECUTIVE';
        if (type === 'LEARNED_PATTERN_MATCH') return 'LEARNED_PATTERN';
        return type || 'GENERAL';
    }

    severityWeight(severity) {
        return { CRITICAL: 0.35, HIGH: 0.25, MEDIUM: 0.15, LOW: 0.05 }[severity] || 0.05;
    }

    calculate(threatObject) {
        console.log('[ConfidenceEngine] Calculating explainable, correlation-aware confidence...');
        const grouped = new Map();
        (threatObject.evidence || []).forEach(evidence => {
            const family = this.evidenceFamily(evidence);
            const value = this.severityWeight(evidence.severity) * Math.max(0, Math.min(1, Number(evidence.confidence) || 0));
            if (!grouped.has(family)) grouped.set(family, []);
            grouped.get(family).push({ evidence, value });
        });

        // LEARNED_PATTERN is capped deliberately low. What the system has taught
        // itself may corroborate a case or tip a borderline one, but it must
        // never be able to drive a HIGH_RISK verdict on its own: the
        // deterministic, source-cited rules stay the primary authority.
        const caps = {
            AUTHENTICATION: 0.30, LANGUAGE: 0.25, CAMPAIGN: 0.25, IDENTITY: 0.25,
            INFRASTRUCTURE: 0.25, URL_RISK: 0.20, ATTACHMENT_RISK: 0.20,
            BEC_COMPOSITE: 0.35, BEHAVIOURAL: 0.25, LEARNED_PATTERN: 0.15,
            // A confirmed indicator-feed match is among the strongest single
            // facts available: someone has already observed this exact URL, host
            // or netblock being used maliciously.
            THREAT_INTEL: 0.35,
            // Operator-defined rules describe threats this specific deployment
            // is actually seeing, so they carry weight comparable to a built-in
            // detection family rather than being treated as a weak afterthought.
            CUSTOM: 0.30,
            // Impersonating a named executive is among the most consequential
            // things a message can do, so this weighs with the strongest families.
            EXECUTIVE: 0.35,

            // The two families that exist to cover attacks the rest of the
            // system cannot see.
            //
            // A callback message has no link, no attachment and valid
            // authentication; a platform-abuse message has genuine, correct
            // authentication by definition. In both, the families that would
            // normally carry a verdict contribute nothing - not because the
            // message is safe, but because it was built so they would have
            // nothing to say. Capping these low would preserve exactly the
            // blind spot they were added to close.
            //
            // Held at 0.30 rather than 0.35 because both reason from shape
            // rather than from a hard fact: a message can legitimately be a
            // picture, and a real brand can legitimately use a bulk sender.
            // Neither should reach a verdict entirely alone - the one case
            // that must is credentials through a form builder, and that is
            // marked decisive and reaches 0.70 through the visible floor
            // instead of through its cap.
            PAYLOAD_CHANNEL: 0.30, TRUSTED_SERVICE: 0.30,

            // Capped with the strongest families, and the only one here whose
            // evidence is an observation rather than a reading of the message.
            // A warning was issued and the machine went there anyway; nothing
            // else this system can know is more consequential than that. The
            // finding is also marked decisive, so it reaches a verdict through
            // the visible floor rather than needing the cap to carry it.
            CONNECTION: 0.35,

            // Obfuscation is a deliberate act with no accidental version, but
            // it says nothing about what the message wants - so it corroborates
            // strongly and decides nothing.
            DECEPTION: 0.25,

            // Structural conversation evidence, unaffected by how well the
            // prose reads.
            THREAD_INTEGRITY: 0.25,

            GENERAL: 0.20
        };
        const contributions = [];
        let threatScore = 0;
        grouped.forEach((items, family) => {
            // Signals within one family are correlated but not identical: the strongest
            // contributes in full and each further distinct finding contributes at half
            // the weight of the one before it. This keeps causally-linked facts (e.g. SPF
            // and DMARC failing together) from being counted as independent proof, while
            // still letting genuinely multi-indicator messages score higher than
            // single-indicator ones. The family cap bounds the total either way.
            const sorted = items.sort((a, b) => b.value - a.value);
            const raw = sorted.reduce((total, item, index) => total + item.value / Math.pow(2, index), 0);
            const contribution = Math.min(raw, caps[family] || 0.20);
            threatScore += contribution;
            contributions.push({
                family,
                contribution: Number(contribution.toFixed(2)),
                representative_finding: sorted[0].evidence.finding,
                supporting_findings: sorted.slice(1).map(item => item.evidence.finding),
                explanation: `Strongest finding in this family contributes in full; ${sorted.length - 1} further finding(s) contribute at progressively halved weight, capped at ${caps[family] || 0.20}.`
            });
        });
        let threatConfidence = Math.min(0.99, threatScore);

        // The family caps exist to stop correlated facts compounding. They must
        // not also stop a single confirmatory fact from being decisive: a link
        // currently listed on a malicious-URL feed cannot be capped down to
        // "suspicious" merely because nothing else about the message looked
        // unusual. Applied as a visible floor that appears in the contributions,
        // never as a silent override.
        const decisiveFinding = (threatObject.evidence || []).find(e => e.decisive);
        if (decisiveFinding && threatConfidence < 0.70) {
            contributions.push({
                family: 'DECISIVE_FINDING',
                contribution: Number((0.70 - threatConfidence).toFixed(2)),
                representative_finding: decisiveFinding.finding,
                explanation: 'A confirmatory finding with no benign interpretation raised this case to high risk on its own. The weighted evidence score alone was lower.'
            });
            threatConfidence = 0.70;
        }
        const originConfidence = Number(threatObject.infrastructure?.origin?.origin_confidence);
        const campaignConfidence = Number(threatObject.campaign_association?.confidence);

        threatObject.confidence = {
            threat: Number(threatConfidence.toFixed(2)),
            infrastructure_origin: Number.isFinite(originConfidence) ? Math.max(0, Math.min(1, originConfidence)) : 0,
            campaign_association: Number.isFinite(campaignConfidence) ? Math.max(0, Math.min(1, campaignConfidence)) : 0,
            actor_attribution: 'INSUFFICIENT EVIDENCE',
            scoring_version: 'PHISHLENS_EVIDENCE_FUSION_V2',
            contributions
        };

        if (threatConfidence >= 0.70) threatObject.detection.verdict = 'HIGH_RISK';
        else if (threatConfidence >= 0.35) threatObject.detection.verdict = 'SUSPICIOUS';
        else threatObject.detection.verdict = 'SAFE';
        return threatObject;
    }
}

module.exports = new ConfidenceEngine();
