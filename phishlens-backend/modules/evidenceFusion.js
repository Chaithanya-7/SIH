const EvidenceObject = require('../models/EvidenceObject');

class EvidenceFusion {
    fuse(threatObject) {
        console.log('[EvidenceFusion] Fusing multi-vector findings into standardized EvidenceObject[]...');

        const evidenceList = [];
        const auth = threatObject.forensics?.authentication || {};
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

        // 3. Explainable NLP / social-engineering evidence
        const nlpSignals = threatObject.nlp?.signals || [];
        nlpSignals.forEach(signal => {
            evidenceList.push(new EvidenceObject({
                evidence_type: `NLP_${signal.type}`,
                source: 'NLP_TEXT_ANALYZER',
                finding: `${signal.type.replace(/_/g, ' ')} (${signal.matched_terms.join(', ')})`,
                severity: signal.severity,
                confidence: signal.confidence,
                explanation: `${signal.explanation} ${threatObject.nlp.limitation}`,
                provenance: { source_type: 'MESSAGE_BODY', source_reference: 'Subject/Body language analysis' }
            }));
        });

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

        // 7. Native MQL Rule Engine Evidence (modules/ruleEngine.js). Each rule cites
        //    its own public source; that source is carried through into the evidence
        //    explanation so an analyst can audit why a rule exists, not just that it fired.
        const matchedRules = threatObject.detection?.matched_rules || [];
        matchedRules.forEach(rule => {
            evidenceList.push(new EvidenceObject({
                evidence_type: `MQL_${rule.category}`,
                source: 'PHISHLENS_MQL_ENGINE',
                finding: rule.name,
                severity: rule.severity,
                confidence: rule.confidence,
                explanation: `${rule.matched_because} (Rule ${rule.id}; source: ${rule.source})`,
                provenance: { source_type: 'MQL_RULE', source_reference: rule.id }
            }));
        });

        // 8. Behavioural evidence: how this message compares to what this
        //    deployment has actually observed from this sender before.
        (threatObject.behavioral?.signals || []).forEach(signal => {
            evidenceList.push(new EvidenceObject({
                evidence_type: `BEHAVIOUR_${signal.type}`,
                source: 'PHISHLENS_BEHAVIOURAL_BASELINE',
                finding: signal.type.replace(/_/g, ' '),
                severity: signal.severity,
                confidence: signal.confidence,
                explanation: `${signal.explanation} ${threatObject.behavioral.limitation}`,
                provenance: { source_type: 'OBSERVED_SENDER_HISTORY', source_reference: threatObject.message?.sender || 'sender' }
            }));
        });

        // 9. Adaptive evidence: characteristics this installation has learned
        //    from mail previously confirmed malicious or legitimate. Reported as
        //    one corroborating signal with its strongest contributing
        //    characteristics named, never as a standalone verdict.
        const adaptive = threatObject.adaptive;
        if (adaptive?.status === 'SCORED' && adaptive.score >= 0.65 && adaptive.contributions.length > 0) {
            const top = adaptive.contributions.slice(0, 4).map(c => c.characteristic).join(', ');
            evidenceList.push(new EvidenceObject({
                evidence_type: 'LEARNED_PATTERN_MATCH',
                source: 'PHISHLENS_ADAPTIVE_LEARNING',
                finding: `Message shares ${adaptive.matched_characteristics} characteristic(s) with previously confirmed malicious mail`,
                severity: adaptive.score >= 0.85 ? 'HIGH' : 'MEDIUM',
                confidence: adaptive.score,
                explanation: `Strongest learned characteristics present: ${top}. Learned from ${adaptive.learned_from.malicious} confirmed malicious and ${adaptive.learned_from.legitimate} confirmed legitimate message(s) on this system. ${adaptive.limitation}`,
                provenance: { source_type: 'LOCAL_ADAPTIVE_MODEL', source_reference: adaptive.engine }
            }));
        }

        threatObject.evidence = evidenceList;
        return threatObject;
    }
}

module.exports = new EvidenceFusion();
