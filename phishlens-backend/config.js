require('dotenv').config();

const crypto = require('crypto');

/**
 * A short, non-reversible identifier for the API key this backend accepts.
 *
 * Returned on the public health route so a client holding the wrong key can
 * still find out that it is the wrong key, and which one would be right. Twelve
 * hex characters of a SHA-256 is plenty to compare two keys and gives away
 * nothing about either.
 *
 * `NO_KEY_SET` is a distinct answer on purpose. A backend started without
 * PHISHLENS_API_KEY rejects *every* key, including a correct one, and that is
 * indistinguishable from a stale key at the client - which is exactly the
 * confusion this is here to end.
 */
function fingerprint(key) {
    if (!key) return 'NO_KEY_SET';
    return crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 12);
}

module.exports = {
    port: process.env.PORT || 3001,
    apiKeyFingerprint: fingerprint(process.env.PHISHLENS_API_KEY),
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
