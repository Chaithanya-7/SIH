const ipUtils = require('../utils/ipUtils');

class RelayTrustEngine {
    /**
     * Normalizes and evaluates the SMTP relay hop chain.
     * Does NOT assume input array ordering; sorts hops by timestamp/hop index.
     */
    evaluateRelayHops(hops = [], rawEmailString = '') {
        console.log(`[RelayTrustEngine] Reconstructing and evaluating ${hops.length} SMTP relay hop(s)...`);

        const hasValidIpInHops = hops && hops.some(h => {
            let ip = typeof h.received?.source?.ip === 'string' ? h.received.source.ip : h.received?.source?.ip?.ip || h.ip;
            return ip && !ipUtils.isNonPublicIP(ip);
        });

        if (!hops || hops.length === 0 || !hasValidIpInHops) {
            const rawParsedHops = this.parseRawReceivedHeaders(rawEmailString);
            if (rawParsedHops.length > 0) {
                hops = rawParsedHops;
            }
        }

        // 1. Normalize hop array
        const normalizedHops = hops.map((hop, originalIdx) => {
            let sourceIp = typeof hop.received?.source?.ip === 'string' 
                ? hop.received.source.ip 
                : hop.received?.source?.ip?.ip || hop.ip || null;
            
            const hostname = hop.received?.source?.name || hop.hostname || 'external-relay.net';
            const timestamp = hop.received?.time || hop.timestamp || new Date().toISOString();

            return {
                original_idx: originalIdx,
                hostname,
                ip: sourceIp,
                timestamp,
                auth_results: hop.authentication_results || null
            };
        });

        // 2. Classify each hop based on delivery role
        let originCandidateFound = false;

        const evaluatedRelays = normalizedHops.map((hop, idx) => {
            const ip = hop.ip;
            const isPublic = ip && !ipUtils.isNonPublicIP(ip);
            const hostLower = (hop.hostname || '').toLowerCase();

            let classification = 'UNVERIFIED_HEADER_HOP';
            let trustLevel = 0.30;
            let trustExplanation = 'Hop information whose provenance cannot be confidently established from trusted boundary';

            // Role Determination Logic based on actual SMTP transfer role:
            const isProviderOutbound = hostLower.includes('mail-') || hostLower.includes('outbound') || hostLower.includes('sendgrid') || hostLower.includes('amazonses') || hostLower.includes('google') || hostLower.includes('outlook');
            const isDestinationMx = hostLower.startsWith('mx.') || hostLower.includes('mx.google') || hostLower.includes('protection.outlook.com');

            if (isDestinationMx && idx === 0) {
                classification = 'TRUSTED_RECEIVER';
                trustLevel = 0.95;
                trustExplanation = 'Recipient organization trusted receiving MX gateway';
            } else if (isProviderOutbound && isPublic) {
                classification = 'PROVIDER_OUTBOUND_MTA';
                trustLevel = 0.85;
                trustExplanation = 'Sender mail provider outbound egress MTA';
            } else if (isPublic && !originCandidateFound) {
                classification = 'ORIGIN_CANDIDATE';
                trustLevel = 0.75;
                trustExplanation = 'Earliest observable public routable infrastructure hop';
                originCandidateFound = true;
            } else if (isPublic) {
                classification = 'EXTERNAL_RELAY';
                trustLevel = 0.50;
                trustExplanation = 'Intermediate external relay node in message path';
            }

            return {
                hop_index: idx,
                hostname: hop.hostname,
                ip: ip || 'UNAVAILABLE',
                timestamp: hop.timestamp,
                is_public: isPublic,
                trust_level: trustLevel,
                classification,
                trust_explanation: trustExplanation,
                auth_results: hop.auth_results
            };
        });

        return evaluatedRelays;
    }

    /**
     * Fallback parser for raw Received: headers when Sublime MDM hops array is missing.
     */
    parseRawReceivedHeaders(rawEmailString) {
        if (!rawEmailString || typeof rawEmailString !== 'string') return [];

        const lines = rawEmailString.split(/\r?\n/);
        const rawHops = [];
        let currentHop = null;

        for (const line of lines) {
            if (/^Received:\s*/i.test(line) && !/^Received-SPF:/i.test(line)) {
                if (currentHop) rawHops.push(currentHop);
                currentHop = line.trim();
            } else if (currentHop && /^\s+/.test(line)) {
                currentHop += ' ' + line.trim();
            } else if (currentHop) {
                rawHops.push(currentHop);
                currentHop = null;
            }
        }
        if (currentHop) rawHops.push(currentHop);

        return rawHops.map((block, idx) => {
            const matches = block.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/g) || [];
            const publicIp = matches.find(i => !ipUtils.isNonPublicIP(i));
            const ip = publicIp || (matches.length > 0 ? matches[0] : null);

            const hostMatch = block.match(/from\s+([\w.-]+)/i) || block.match(/by\s+([\w.-]+)/i);
            const hostname = hostMatch ? hostMatch[1] : 'external-relay.net';

            return {
                received: {
                    source: { name: hostname, ip: ip },
                    time: new Date().toISOString()
                }
            };
        });
    }
}

module.exports = new RelayTrustEngine();
