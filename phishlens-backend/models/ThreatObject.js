const crypto = require('crypto');

class ThreatObject {
    constructor(data = {}) {
        const year = new Date().getFullYear();
        const suffix = crypto.randomBytes(3).toString('hex').toUpperCase();
        this.case_id = data.case_id || `SM-${year}-${suffix}`;
        this.org_id = data.org_id || data.mailbox_provenance?.organization_id || null;
        
        this.message = {
            sender: data.message?.sender || '',
            recipient: data.message?.recipient || '',
            subject: data.message?.subject || '',
            raw_hash: data.message?.raw_hash || '',
            delivered_at: data.message?.delivered_at || new Date().toISOString()
        };

        // 1. Detection Verdict (SAFE, SUSPICIOUS, HIGH_RISK)
        this.detection = {
            verdict: data.detection?.verdict || 'UNKNOWN',
            provider: data.detection?.provider || 'PHISHLENS_NATIVE_MQL',
            verification_status: data.detection?.verification_status || 'PENDING_NATIVE_ANALYSIS',
            is_dev_fallback: data.detection?.is_dev_fallback || false,
            matched_rules: data.detection?.matched_rules || [],
            signals: data.detection?.signals || [],
            rule_engine: data.detection?.rule_engine || null,
            external_provider_result: data.detection?.external_provider_result || { attempted: false, provider: null, status: 'NOT_CONFIGURED' }
        };

        // 2. Mailbox Status (INBOX, CONTAINMENT_REQUESTED, QUARANTINED, RELEASE_REQUESTED, RELEASED, ACTION_FAILED, UNKNOWN)
        this.mailbox = {
            status: data.mailbox?.status || 'INBOX'
        };

        // 3. Review Status (NOT_REQUIRED, PENDING_ADMIN, UNDER_REVIEW, RELEASED_BY_ADMIN, CONFIRMED_THREAT)
        this.review = {
            status: data.review?.status || (this.detection.verdict === 'HIGH_RISK' ? 'PENDING_ADMIN' : 'NOT_REQUIRED')
        };

        // 4. Provider Action Status (NOT_REQUESTED, REQUESTED, EXECUTING, PROVIDER_CONFIRMED, FAILED, REVERSED)
        this.provider_action = {
            status: data.provider_action?.status || 'NOT_REQUESTED'
        };

        // 5. Mailbox Provenance (Determines WHICH Gmail account receives provider actions)
        this.mailbox_provenance = {
            organization_id: data.mailbox_provenance?.organization_id || data.org_id || null,
            mailbox_connection_id: data.mailbox_provenance?.mailbox_connection_id || null,
            provider_account: data.mailbox_provenance?.provider_account || data.message?.recipient || '',
            provider: data.mailbox_provenance?.provider || 'GMAIL',
            provider_message_id: data.mailbox_provenance?.provider_message_id || null
        };

        // 6. Containment Context & Audit Metadata
        this.containment_context = {
            label_id: data.containment_context?.label_id || null,
            label_name: data.containment_context?.label_name || 'PhishLens/Quarantine',
            contained_at: data.containment_context?.contained_at || null,
            released_at: data.containment_context?.released_at || null,
            decision_reason: data.containment_context?.decision_reason || null,
            admin_note: data.containment_context?.admin_note || null,
            last_updated_at: data.containment_context?.last_updated_at || new Date().toISOString()
        };

        this.iocs = {
            ips: data.iocs?.ips || [],
            domains: data.iocs?.domains || [],
            urls: data.iocs?.urls || [],
            hashes: data.iocs?.hashes || []
        };
        this.evidence = data.evidence || [];
        this.nlp = data.nlp || {
            status: 'NOT_ANALYZED',
            engine: null,
            analyzed_fields: { subject: false, body: false },
            score: 0,
            signals: [],
            limitation: 'No language analysis has been performed.'
        };
        this.attachments = data.attachments || [];
        this.forensics = {
            authentication: data.forensics?.authentication || { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' },
            smtp_relay: data.forensics?.smtp_relay || []
        };
        this.infrastructure = {
            origin_ip: data.infrastructure?.origin_ip || '',
            asn: data.infrastructure?.asn || '',
            geo: data.infrastructure?.geo || {},
            origin: data.infrastructure?.origin || null,
            reputation: data.infrastructure?.reputation || {},
            anonymization: data.infrastructure?.anonymization || {}
        };
        this.correlations = data.correlations || [];
        this.campaign_association = data.campaign_association || {
            confidence: 0,
            status: 'UNASSOCIATED',
            related_cases: [],
            factors: [],
            limitation: 'No campaign association has been established.'
        };
        this.confidence = {
            threat: data.confidence?.threat || 0.0,
            infrastructure_origin: data.confidence?.infrastructure_origin || 0.0,
            campaign_association: data.confidence?.campaign_association || 0.0,
            actor_attribution: data.confidence?.actor_attribution || 'INSUFFICIENT EVIDENCE',
            scoring_version: data.confidence?.scoring_version || 'PHISHLENS_EVIDENCE_FUSION_V2',
            contributions: data.confidence?.contributions || []
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
