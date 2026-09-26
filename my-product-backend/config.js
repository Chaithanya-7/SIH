require('dotenv').config();

module.exports = {
    port: process.env.PORT || 3001,
    detection: {
        provider: process.env.DETECTION_PROVIDER || 'sublime',
        endpoint: process.env.DETECTION_ENDPOINT || 'http://localhost:8000',
        apiKey: process.env.SUBLIME_API_KEY || ''
    }
};
