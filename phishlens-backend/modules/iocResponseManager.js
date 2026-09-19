class IOCResponseManager {
    constructor() {
        this.responseList = [];
    }

    processThreatIOCs(threatObject) {
        const iocs = threatObject.iocs || {};
        const caseId = threatObject.case_id;
        const campaignId = threatObject.campaign?.campaign_id || null;
        const confidence = threatObject.confidence?.threat || 0;

        // Process Domains
        (iocs.domains || []).forEach(dom => {
            if (!this.responseList.some(item => item.ioc === dom)) {
                this.responseList.push({
                    ioc: dom,
                    type: 'DOMAIN',
                    status: 'BLOCK_RECOMMENDED',
                    source_case: caseId,
                    campaign_id: campaignId,
                    reason: 'Associated with high-risk phishing email threat',
                    confidence,
                    added_at: new Date().toISOString()
                });
            }
        });

        // Process URLs
        (iocs.urls || []).forEach(u => {
            if (!this.responseList.some(item => item.ioc === u)) {
                this.responseList.push({
                    ioc: u,
                    type: 'URL',
                    status: 'BLOCK_RECOMMENDED',
                    source_case: caseId,
                    campaign_id: campaignId,
                    reason: 'Malicious credential harvesting link',
                    confidence,
                    added_at: new Date().toISOString()
                });
            }
        });

        // Process Hashes
        (iocs.hashes || []).forEach(h => {
            if (!this.responseList.some(item => item.ioc === h)) {
                this.responseList.push({
                    ioc: h,
                    type: 'HASH',
                    status: 'BLOCK_RECOMMENDED',
                    source_case: caseId,
                    campaign_id: campaignId,
                    reason: 'Malicious attachment SHA-256 payload signature',
                    confidence,
                    added_at: new Date().toISOString()
                });
            }
        });

        return this.responseList;
    }

    getResponseList() {
        return this.responseList;
    }
}

module.exports = new IOCResponseManager();
