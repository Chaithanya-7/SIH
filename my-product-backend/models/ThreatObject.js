const crypto = require('crypto');

class ThreatObject {
    constructor(data = {}) {
        this.case_id = data.case_id || `SM-${new Date().getFullYear()}-${Math.floor(10000 + Math.random() * 90000)}`;
        this.message = {
            sender: data.message?.sender || '',
            recipient: data.message?.recipient || '',
            subject: data.message?.subject || '',
            raw_hash: data.message?.raw_hash || '',
            delivered_at: data.message?.delivered_at || new Date().toISOString()
        };
        this.detection = {
            verdict: data.detection?.verdict || 'UNKNOWN',
            provider: data.detection?.provider || 'sublime',
            matched_rules: data.detection?.matched_rules || [],
            signals: data.detection?.signals || []
        };
        this.iocs = {
            ips: data.iocs?.ips || [],
            domains: data.iocs?.domains || [],
            urls: data.iocs?.urls || [],
            hashes: data.iocs?.hashes || []
        };
        this.evidence = data.evidence || []; // Array of EvidenceObject
        this.forensics = {
            authentication: data.forensics?.authentication || { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' },
            smtp_relay: data.forensics?.smtp_relay || []
        };
        this.infrastructure = {
            origin_ip: data.infrastructure?.origin_ip || '',
            asn: data.infrastructure?.asn || '',
            geo: data.infrastructure?.geo || {}
        };
        this.correlations = data.correlations || [];
        this.confidence = {
            threat: data.confidence?.threat || 0.0,
            infrastructure_origin: data.confidence?.infrastructure_origin || 0.0,
            campaign_association: data.confidence?.campaign_association || 0.0,
            actor_attribution: data.confidence?.actor_attribution || 'INSUFFICIENT EVIDENCE'
        };
        this.remediation = {
            status: data.remediation?.status || 'PENDING',
            policy_matched: data.remediation?.policy_matched || null,
            executed_actions: data.remediation?.executed_actions || []
        };
        this.timestamps = {
            ingested_at: data.timestamps?.ingested_at || new Date().toISOString()
        };
        this._raw_data_model = data._raw_data_model || {};
        this._raw_email_string = data._raw_email_string || '';
    }
}

module.exports = ThreatObject;
