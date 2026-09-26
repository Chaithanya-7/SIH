const EvidenceObject = require('../models/EvidenceObject');

class EvidenceFusion {
    fuse(threatObject) {
        console.log('[EvidenceFusion] Fusing multi-vector findings into standardized EvidenceObject[]...');

        const evidenceList = [];
        const auth = threatObject.forensics?.authentication || {};
        const rawDataModel = threatObject._raw_data_model || {};
        const subject = threatObject.message?.subject || '';
        const bodyText = rawDataModel.body?.plain?.raw || '';
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip || 'N/A';

        // 1. Authentication Anomaly Evidence
        if (auth.spf === 'fail') {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'AUTHENTICATION_ANOMALY',
                source: 'HEADER_PARSER',
                finding: 'SPF Authentication Failed',
                severity: 'HIGH',
                confidence: 0.95,
                explanation: 'The sending server IP is not authorized in the sender domain SPF record.',
                provenance: { source_type: 'EMAIL_HEADER', source_reference: 'Authentication-Results' }
            }));
        }

        if (auth.dkim === 'fail') {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'AUTHENTICATION_ANOMALY',
                source: 'HEADER_PARSER',
                finding: 'DKIM Signature Verification Failed',
                severity: 'HIGH',
                confidence: 0.90,
                explanation: 'The digital signature on the email could not be verified, indicating possible message tampering or spoofing.',
                provenance: { source_type: 'EMAIL_HEADER', source_reference: 'DKIM-Signature' }
            }));
        }

        if (auth.dmarc === 'fail') {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'AUTHENTICATION_ANOMALY',
                source: 'HEADER_PARSER',
                finding: 'DMARC Policy Compliance Failed',
                severity: 'HIGH',
                confidence: 0.95,
                explanation: 'The message failed both SPF and DKIM alignment according to the domain DMARC policy.',
                provenance: { source_type: 'EMAIL_HEADER', source_reference: 'DMARC' }
            }));
        }

        // 2. Return-Path Mismatch Evidence
        if (threatObject.forensics?.return_path_mismatch) {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'IDENTITY_SPOOF',
                source: 'FORENSIC_ENGINE',
                finding: 'From Domain differs from Return-Path Domain',
                severity: 'HIGH',
                confidence: 0.88,
                explanation: 'The sender address displayed to the user does not match the actual envelope return address.',
                provenance: { source_type: 'EMAIL_HEADER', source_reference: 'Return-Path' }
            }));
        }

        // 3. BEC & Social Engineering Urgency Keywords
        const becKeywords = ['urgent', 'wire transfer', 'bank account', 'gift card', 'payroll', 'ceo', 'immediate', 'fund transfer'];
        const matchedKw = becKeywords.filter(kw => subject.toLowerCase().includes(kw) || bodyText.toLowerCase().includes(kw));
        if (matchedKw.length > 0) {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'BEC_KEYWORD',
                source: 'NLP_TEXT_ANALYZER',
                finding: `Financial Urgency Indicators Detected (${matchedKw.join(', ')})`,
                severity: 'HIGH',
                confidence: 0.85,
                explanation: 'Email contains strong social-engineering financial urgency cues common in BEC attacks.',
                provenance: { source_type: 'MESSAGE_BODY', source_reference: 'Subject/Body' }
            }));
        }

        // 4. Independent Anonymization Evidence (VPN, Proxy, Tor, Hosting)
        const anon = threatObject.infrastructure?.anonymization || {};
        if (anon.status === 'AVAILABLE') {
            if (anon.tor) {
                evidenceList.push(new EvidenceObject({
                    evidence_type: 'INFRASTRUCTURE_ANOMALY',
                    source: 'ANONYMIZATION_PROVIDER',
                    finding: 'Sending IP identified as Tor Exit Node',
                    severity: 'HIGH',
                    confidence: 0.90,
                    explanation: 'Originating infrastructure is an active Tor network anonymizing exit relay.',
                    provenance: { source_type: 'IP_INTELLIGENCE', source_reference: originIp }
                }));
            } else if (anon.vpn || anon.proxy) {
                evidenceList.push(new EvidenceObject({
                    evidence_type: 'INFRASTRUCTURE_ANOMALY',
                    source: 'ANONYMIZATION_PROVIDER',
                    finding: `Sending IP identified as ${anon.vpn ? 'VPN' : 'Proxy'} Node`,
                    severity: 'MEDIUM',
                    confidence: 0.80,
                    explanation: 'Originating infrastructure is associated with an active commercial VPN or proxy service.',
                    provenance: { source_type: 'IP_INTELLIGENCE', source_reference: originIp }
                }));
            }
        }

        // 5. Independent Reputation Evidence (AbuseIPDB / IPQS)
        const rep = threatObject.infrastructure?.reputation || {};
        if (rep.abuseipdb?.status === 'AVAILABLE' && rep.abuseipdb.abuse_confidence_score > 50) {
            evidenceList.push(new EvidenceObject({
                evidence_type: 'REPUTATION_RISK',
                source: 'ABUSEIPDB',
                finding: `High IP Abuse Confidence Score (${rep.abuseipdb.abuse_confidence_score}%)`,
                severity: rep.abuseipdb.abuse_confidence_score > 80 ? 'HIGH' : 'MEDIUM',
                confidence: parseFloat((rep.abuseipdb.abuse_confidence_score / 100).toFixed(2)),
                explanation: `Originating IP has been reported ${rep.abuseipdb.total_reports} times for malicious network activity.`,
                provenance: { source_type: 'THREAT_INTEL', source_reference: originIp }
            }));
        }

        // 6. Campaign & Cross-Case Correlation Evidence
        const campAssoc = threatObject.campaign_association || {};
        if (campAssoc.status && campAssoc.status !== 'UNASSOCIATED' && campAssoc.confidence > 0) {
            (campAssoc.factors || []).forEach(factor => {
                let evType = 'CAMPAIGN_ASSOCIATION';
                if (factor.factor === 'SHARED_IP') evType = 'REPEATED_IP';
                else if (factor.factor === 'SHARED_DOMAIN_INFRASTRUCTURE') evType = 'REPEATED_DOMAIN';
                else if (factor.factor === 'SHARED_ASN_PROVIDER') evType = 'SHARED_INFRASTRUCTURE';
                else if (factor.factor === 'SHARED_EXECUTIVE_TARGET') evType = 'EXECUTIVE_TARGETING_PATTERN';

                evidenceList.push(new EvidenceObject({
                    evidence_type: evType,
                    source: 'CAMPAIGN_GRAPH',
                    finding: factor.evidence,
                    severity: factor.weight >= 0.25 ? 'HIGH' : 'MEDIUM',
                    confidence: campAssoc.confidence,
                    explanation: `${factor.evidence}. ${campAssoc.limitation}`,
                    provenance: { case_ids: campAssoc.related_cases || [], source_type: 'PERSISTENT_GRAPH' }
                }));
            });
        }

        threatObject.evidence = evidenceList;
        return threatObject;
    }
}

module.exports = new EvidenceFusion();
