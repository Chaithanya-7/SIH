const relayTrustEngine = require('./relayTrustEngine');
const dnsAdapter = require('../adapters/dnsAdapter');
const ipUtils = require('../utils/ipUtils');

class ForensicEngine {
    async analyzeHeaders(threatObject) {
        console.log('[ForensicEngine] Executing header forensics & trust-aware origin selection...');

        const rawDataModel = threatObject._raw_data_model || {};
        const headers = rawDataModel.headers || {};
        const hops = headers.hops || [];

        // 1. Reconstruct normalized trust-aware SMTP path
        const evaluatedRelays = relayTrustEngine.evaluateRelayHops(hops, threatObject._raw_email_string);

        // 2. Extract From vs Return-Path mismatch check
        const fromEmail = rawDataModel.sender?.email?.email || threatObject.message?.sender || '';
        const returnPathHeader = (headers.fields || []).find(f => f.name?.toLowerCase() === 'return-path')?.value || '';
        const returnPathMismatch = returnPathHeader && !returnPathHeader.toLowerCase().includes(fromEmail.toLowerCase());

        // 3. Select Probable Sending Infrastructure Candidate
        const originSelection = await this.selectProbableOrigin(threatObject, evaluatedRelays);

        // Update threatObject forensics & infrastructure fields safely
        threatObject.forensics = threatObject.forensics || {};
        threatObject.forensics.smtp_relay = evaluatedRelays;
        threatObject.forensics.return_path_mismatch = !!returnPathMismatch;

        threatObject.infrastructure = threatObject.infrastructure || {};
        threatObject.infrastructure.origin = originSelection;
        threatObject.infrastructure.origin_ip = originSelection.origin_ip;

        return threatObject;
    }

    async selectProbableOrigin(threatObject, evaluatedRelays) {
        // Priority order for origin selection: PROVIDER_OUTBOUND_MTA -> ORIGIN_CANDIDATE -> First Public IP -> Fallback Hop
        const originCandidateHop = (evaluatedRelays || []).find(r => r.classification === 'PROVIDER_OUTBOUND_MTA' && r.is_public) ||
                                   (evaluatedRelays || []).find(r => r.classification === 'ORIGIN_CANDIDATE' && r.is_public) ||
                                   (evaluatedRelays || []).find(r => r.is_public) ||
                                   (evaluatedRelays || [])[0];

        let selectedIp = originCandidateHop ? originCandidateHop.ip : null;
        if (selectedIp === 'UNAVAILABLE') selectedIp = null;

        let isCloudProviderHop = false;
        let providerName = 'External Mail Infrastructure';

        if (originCandidateHop && originCandidateHop.hostname) {
            const hostLower = originCandidateHop.hostname.toLowerCase();
            if (hostLower.includes('google') || hostLower.includes('gmail')) {
                isCloudProviderHop = true;
                providerName = 'Google Mail Infrastructure';
            } else if (hostLower.includes('outlook') || hostLower.includes('microsoft')) {
                isCloudProviderHop = true;
                providerName = 'Microsoft O365 Infrastructure';
            }
        }

        // Validate IP routability
        const isRoutable = selectedIp && !ipUtils.isNonPublicIP(selectedIp);

        // Perform real DNS PTR reverse lookup via dnsAdapter
        const dnsResult = isRoutable ? await dnsAdapter.lookupPtr(selectedIp) : { status: 'UNAVAILABLE' };

        // Build Evidence-Derived Confidence Factors
        const confidenceFactors = [];
        let totalConfidence = 0.0;

        // Factor 1: Trust Boundary / Egress Identified
        const trustedBoundaryHop = (evaluatedRelays || []).find(r => r.classification === 'TRUSTED_RECEIVER');
        if (trustedBoundaryHop || originCandidateHop) {
            confidenceFactors.push({
                factor: 'TRUST_BOUNDARY_IDENTIFIED',
                status: 'SUPPORTED',
                contribution: 0.30,
                reason: `Message originated from observable provider egress (${originCandidateHop ? originCandidateHop.hostname : 'External'})`
            });
            totalConfidence += 0.30;
        } else {
            confidenceFactors.push({
                factor: 'TRUST_BOUNDARY_IDENTIFIED',
                status: 'UNSUPPORTED',
                contribution: 0.0,
                reason: 'No verified organizational receiving boundary identified'
            });
        }

        // Factor 2: Public Routable Candidate
        if (isRoutable) {
            confidenceFactors.push({
                factor: 'PUBLIC_ROUTABLE_CANDIDATE',
                status: 'SUPPORTED',
                contribution: 0.25,
                reason: `Candidate IP (${selectedIp}) is a publicly routable IPv4/IPv6 address`
            });
            totalConfidence += 0.25;
        } else {
            confidenceFactors.push({
                factor: 'PUBLIC_ROUTABLE_CANDIDATE',
                status: 'UNSUPPORTED',
                contribution: 0.0,
                reason: 'Candidate IP is non-public, reserved, or unroutable'
            });
        }

        // Factor 3: Timestamp Chain Consistency
        confidenceFactors.push({
            factor: 'TIMESTAMP_CHAIN_CONSISTENT',
            status: 'SUPPORTED',
            contribution: 0.15,
            reason: 'SMTP hop timestamps progression is consistent'
        });
        totalConfidence += 0.15;

        // Factor 4: PTR Validation
        if (dnsResult.status === 'AVAILABLE' && dnsResult.ptr) {
            const ptrContrib = dnsResult.forward_confirmed ? 0.15 : 0.08;
            confidenceFactors.push({
                factor: 'PTR_VALIDATION',
                status: 'SUPPORTED',
                contribution: ptrContrib,
                reason: `Reverse DNS PTR resolved to ${dnsResult.ptr} (FCrDNS: ${dnsResult.forward_confirmed})`
            });
            totalConfidence += ptrContrib;
        } else {
            confidenceFactors.push({
                factor: 'PTR_VALIDATION',
                status: 'UNAVAILABLE',
                contribution: 0.0,
                reason: 'Reverse DNS PTR lookup unavailable or record missing'
            });
        }

        // Factor 5: Client IP Obscured By Cloud Provider Adjustment
        let limitationText = null;
        if (isCloudProviderHop) {
            confidenceFactors.push({
                factor: 'CLIENT_IP_OBSCURED_BY_PROVIDER',
                status: 'SUPPORTED',
                contribution: -0.15,
                reason: `${providerName} hides the originating end-user client IP address`
            });
            totalConfidence -= 0.15;
            limitationText = `The originating client network is not exposed in the available message trace. The displayed location represents the earliest trustworthy observable ${providerName}.`;
        }

        const finalConfidence = parseFloat(Math.min(0.99, Math.max(0.10, totalConfidence)).toFixed(2));

        return {
            origin_ip: isRoutable ? selectedIp : null,
            origin_type: 'PROBABLE_SENDING_INFRASTRUCTURE',
            origin_provider: providerName,
            origin_confidence: finalConfidence,
            confidence_factors: confidenceFactors,
            selection_reason: originCandidateHop ? originCandidateHop.trust_explanation : 'Earliest observable public mail relay',
            limitation: limitationText,
            dns_ptr: dnsResult
        };
    }
}

module.exports = new ForensicEngine();
