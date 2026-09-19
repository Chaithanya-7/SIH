const axios = require('axios');
const config = require('../config');

/**
 * Optional supplementary detection provider. Never a hard dependency: see
 * detectionAdapter.js, which catches any failure here and continues the
 * pipeline on PhishLens' own native detection alone.
 */
class SublimeAdapter {
    constructor() {
        this.endpoint = config.detection.endpoint;
        this.apiKey = config.detection.apiKey;
    }

    async analyzeMessage(base64RawMessage) {
        const response = await axios.post(
            `${this.endpoint}/v1/messages`,
            { raw_message: base64RawMessage },
            {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                timeout: 8000
            }
        );

        return {
            success: true,
            isDevFallback: false,
            verificationStatus: 'SUBLIME_MQL_VERIFIED',
            rawResponse: response.data
        };
    }
}

module.exports = new SublimeAdapter();
