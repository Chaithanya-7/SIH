class ConfidenceEngine {
    calculate(threatObject) {
        console.log('[ConfidenceEngine] Calculating 3-Tier Confidence Model...');

        const evidenceList = threatObject.evidence || [];
        
        // 1. Calculate Threat Confidence
        let threatScore = 0;
        evidenceList.forEach(e => {
            if (e.severity === 'CRITICAL') threatScore += 0.35;
            else if (e.severity === 'HIGH') threatScore += 0.25;
            else if (e.severity === 'MEDIUM') threatScore += 0.15;
        });
        const threatConfidence = Math.min(0.99, Math.max(0.05, threatScore));

        // 2. Calculate Infrastructure Origin Confidence
        const relays = threatObject.forensics.smtp_relay || [];
        const earliestHop = relays.find(r => r.hop_index === relays.length - 1) || relays[0];
        const infraConfidence = earliestHop ? earliestHop.trust_level : 0.70;

        // 3. Campaign Association Confidence (placeholder for Graph module)
        const campaignConfidence = threatObject.correlations.length > 0 ? 0.85 : 0.00;

        // 4. Update threatObject confidence structure
        threatObject.confidence = {
            threat: parseFloat(threatConfidence.toFixed(2)),
            infrastructure_origin: parseFloat(infraConfidence.toFixed(2)),
            campaign_association: parseFloat(campaignConfidence.toFixed(2)),
            actor_attribution: 'INSUFFICIENT EVIDENCE'
        };

        // Update overall verdict based on Threat Confidence
        if (threatConfidence >= 0.70) {
            threatObject.detection.verdict = 'HIGH_RISK';
        } else if (threatConfidence >= 0.35) {
            threatObject.detection.verdict = 'SUSPICIOUS';
        } else {
            threatObject.detection.verdict = 'SAFE';
        }

        return threatObject;
    }
}

module.exports = new ConfidenceEngine();
