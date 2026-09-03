const axios = require('axios');
const ipUtils = require('../utils/ipUtils');

class ReputationIntelAdapter {
    constructor() {
        this.abuseApiKey = process.env.ABUSEIPDB_API_KEY || '';
        this.ipqsApiKey = process.env.IPQS_API_KEY || '';
    }

    async lookupReputation(ip) {
        if (!ip || ipUtils.isNonPublicIP(ip)) {
            return {
                abuseipdb: { status: 'UNAVAILABLE', abuse_confidence_score: null, total_reports: null, reason: 'Non-public IP' },
                ipqs: { status: 'UNAVAILABLE', fraud_score: null, recent_abuse: null, reason: 'Non-public IP' }
            };
        }

        const result = {
            abuseipdb: { status: 'UNAVAILABLE', abuse_confidence_score: null, total_reports: null },
            ipqs: { status: 'UNAVAILABLE', fraud_score: null, recent_abuse: null }
        };

        // 1. Query AbuseIPDB if key is set
        if (this.abuseApiKey) {
            try {
                const res = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
                    params: { ipAddress: ip, maxAgeInDays: 90 },
                    headers: { 'Key': this.abuseApiKey, 'Accept': 'application/json' },
                    timeout: 3000
                });
                if (res.data && res.data.data) {
                    result.abuseipdb = {
                        status: 'AVAILABLE',
                        abuse_confidence_score: res.data.data.abuseConfidenceScore,
                        total_reports: res.data.data.totalReports,
                        last_reported_at: res.data.data.lastReportedAt || null
                    };
                }
            } catch (err) {
                console.log(`[ReputationIntelAdapter] AbuseIPDB lookup failed for ${ip}: ${err.message}`);
            }
        }

        // 2. Query IPQualityScore if key is set
        if (this.ipqsApiKey) {
            try {
                const res = await axios.get(`https://ipqualityscore.com/api/json/ip/${this.ipqsApiKey}/${ip}`, { timeout: 3000 });
                if (res.data && res.data.success) {
                    result.ipqs = {
                        status: 'AVAILABLE',
                        fraud_score: res.data.fraud_score,
                        recent_abuse: !!res.data.recent_abuse,
                        bot_status: !!res.data.bot_status
                    };
                }
            } catch (err) {
                console.log(`[ReputationIntelAdapter] IPQS lookup failed for ${ip}: ${err.message}`);
            }
        }

        return result;
    }
}

module.exports = new ReputationIntelAdapter();
