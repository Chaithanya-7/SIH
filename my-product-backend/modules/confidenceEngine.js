class ConfidenceEngine {
    evidenceFamily(evidence) {
        if (evidence.evidence_type === 'AUTHENTICATION_ANOMALY') return 'AUTHENTICATION';
        if (String(evidence.evidence_type).startsWith('NLP_')) return 'LANGUAGE';
        if (['CAMPAIGN_ASSOCIATION', 'REPEATED_IP', 'REPEATED_DOMAIN', 'SHARED_INFRASTRUCTURE', 'EXECUTIVE_TARGETING_PATTERN'].includes(evidence.evidence_type)) return 'CAMPAIGN';
        if (evidence.evidence_type === 'IDENTITY_SPOOF') return 'IDENTITY';
        if (['INFRASTRUCTURE_ANOMALY', 'REPUTATION_RISK'].includes(evidence.evidence_type)) return 'INFRASTRUCTURE';
        return evidence.evidence_type || 'GENERAL';
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
            const existing = grouped.get(family);
            if (!existing || value > existing.value) grouped.set(family, { evidence, value });
        });

        const caps = { AUTHENTICATION: 0.30, LANGUAGE: 0.25, CAMPAIGN: 0.25, IDENTITY: 0.25, INFRASTRUCTURE: 0.25, GENERAL: 0.20 };
        const contributions = [];
        let threatScore = 0;
        grouped.forEach(({ evidence, value }, family) => {
            const contribution = Math.min(value, caps[family] || 0.20);
            threatScore += contribution;
            contributions.push({ family, contribution: Number(contribution.toFixed(2)), representative_finding: evidence.finding, explanation: 'Only the strongest signal in this evidence family contributes, preventing correlated facts from being double-counted.' });
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
