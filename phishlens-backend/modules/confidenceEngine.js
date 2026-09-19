class ConfidenceEngine {
    evidenceFamily(evidence) {
        const type = String(evidence.evidence_type);
        if (type === 'AUTHENTICATION_ANOMALY' || type === 'MQL_AUTH') return 'AUTHENTICATION';
        if (type.startsWith('NLP_') || type === 'MQL_NLP') return 'LANGUAGE';
        if (['CAMPAIGN_ASSOCIATION', 'REPEATED_IP', 'REPEATED_DOMAIN', 'SHARED_INFRASTRUCTURE', 'EXECUTIVE_TARGETING_PATTERN'].includes(type)) return 'CAMPAIGN';
        if (type === 'IDENTITY_SPOOF' || type === 'MQL_DOM' || type === 'MQL_IMP') return 'IDENTITY';
        if (['INFRASTRUCTURE_ANOMALY', 'REPUTATION_RISK'].includes(type)) return 'INFRASTRUCTURE';
        if (type === 'MQL_URL') return 'URL_RISK';
        if (type === 'MQL_ATT') return 'ATTACHMENT_RISK';
        if (type === 'MQL_BEC') return 'BEC_COMPOSITE';
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

        const caps = { AUTHENTICATION: 0.30, LANGUAGE: 0.25, CAMPAIGN: 0.25, IDENTITY: 0.25, INFRASTRUCTURE: 0.25, URL_RISK: 0.20, ATTACHMENT_RISK: 0.20, BEC_COMPOSITE: 0.35, GENERAL: 0.20 };
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
        const threatConfidence = Math.min(0.99, threatScore);
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
