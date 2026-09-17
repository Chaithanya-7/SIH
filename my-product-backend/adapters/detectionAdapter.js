const config = require('../config');
const sublimeAdapter = require('./sublimeAdapter');

class DetectionAdapter {
    async analyze(base64RawMessage) {
        const provider = config.detection.provider;
        console.log(`[DetectionAdapter] Routing detection request to provider: ${provider}`);

        switch (provider.toLowerCase()) {
            case 'sublime':
                return await sublimeAdapter.analyzeMessage(base64RawMessage);
            default:
                throw new Error(`Unsupported detection provider: ${provider}`);
        }
    }
}

module.exports = new DetectionAdapter();
