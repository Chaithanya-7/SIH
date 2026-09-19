require('dotenv').config();

module.exports = {
    port: process.env.PORT || 3001,
    detection: {
        // 'native' (default): PhishLens' own zero-cost MQL rule engine + NLP + forensics
        // pipeline only. 'sublime': also attempt the optional external Sublime
        // provider as informational supplementary enrichment (never a hard
        // dependency - see adapters/detectionAdapter.js).
        provider: process.env.DETECTION_PROVIDER || 'native',
        endpoint: process.env.DETECTION_ENDPOINT || 'http://localhost:8000',
        apiKey: process.env.SUBLIME_API_KEY || ''
    }
};
