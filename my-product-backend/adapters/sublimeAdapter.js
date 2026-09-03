const axios = require('axios');
const config = require('../config');

class SublimeAdapter {
    constructor() {
        this.endpoint = config.detection.endpoint;
        this.apiKey = config.detection.apiKey;
    }

    async analyzeMessage(base64RawMessage) {
        try {
            console.log(`[SublimeAdapter] Submitting message to ${this.endpoint}/v1/messages ...`);
            const response = await axios.post(
                `${this.endpoint}/v1/messages`,
                { raw_message: base64RawMessage },
                {
                    headers: {
                        'Authorization': `Bearer ${this.apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 15000
                }
            );

            return {
                success: true,
                rawResponse: response.data
            };
        } catch (error) {
            console.error('[SublimeAdapter] Full error details:', error.response?.data || error.message);
            throw new Error('Email detection service is temporarily unavailable.');
        }
    }
}

module.exports = new SublimeAdapter();
