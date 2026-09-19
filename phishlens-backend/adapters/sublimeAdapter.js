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
                isDevFallback: false,
                verificationStatus: 'SUBLIME_MQL_VERIFIED',
                rawResponse: response.data
            };
        } catch (error) {
            console.error('[SublimeAdapter] Full error details:', error.response?.data || error.message);

            // Gated explicitly behind environment flag (Default: OFF)
            if (process.env.DEV_DETECTION_FALLBACK === 'true') {
                console.warn('⚠️ [SublimeAdapter] DEV_DETECTION_FALLBACK=true. Sublime unavailable. Utilizing DEVELOPMENT / NOT SUBLIME VERIFIED fallback.');
                return {
                    success: true,
                    isDevFallback: true,
                    verificationStatus: 'DEVELOPMENT / NOT SUBLIME VERIFIED',
                    rawResponse: {
                        status: 'FLAGGED',
                        is_dev_fallback: true,
                        verification_status: 'DEVELOPMENT / NOT SUBLIME VERIFIED',
                        matched_rules: ['DEV: Local Fallback Detection (Not Sublime Verified)'],
                        signals: ['dev_fallback_mode', 'not_sublime_verified'],
                        data_model: {}
                    }
                };
            }

            // Normal Production Behavior: Fail truthfully when Sublime is unavailable
            throw new Error('Sublime/MQL detection service is unavailable. Pipeline execution failed (Production Mode).');
        }
    }
}

module.exports = new SublimeAdapter();
