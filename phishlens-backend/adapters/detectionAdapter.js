const config = require('../config');
const sublimeAdapter = require('./sublimeAdapter');

/**
 * External detection providers are optional, informational enrichment only.
 * PhishLens' own native MQL rule engine + NLP + forensics pipeline (see
 * modules/ruleEngine.js) is the primary, always-available, zero-cost
 * detection path and never depends on this adapter succeeding. A configured
 * provider that fails or times out must never abort the pipeline.
 */
class DetectionAdapter {
    async analyze(base64RawMessage) {
        const provider = (config.detection.provider || 'native').toLowerCase();

        if (provider === 'native' || provider === 'none') {
            return null;
        }

        console.log(`[DetectionAdapter] Attempting optional supplementary detection from provider: ${provider}`);

        try {
            switch (provider) {
                case 'sublime':
                    return await sublimeAdapter.analyzeMessage(base64RawMessage);
                default:
                    console.warn(`[DetectionAdapter] Unknown DETECTION_PROVIDER "${provider}"; continuing without external enrichment.`);
                    return null;
            }
        } catch (error) {
            console.warn(`[DetectionAdapter] Optional provider "${provider}" unavailable, continuing with native detection only: ${error.message}`);
            return null;
        }
    }
}

module.exports = new DetectionAdapter();
