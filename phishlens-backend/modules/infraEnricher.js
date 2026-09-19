const geoIntelAdapter = require('../adapters/geoIntelAdapter');
const anonymizationIntelAdapter = require('../adapters/anonymizationIntelAdapter');
const reputationIntelAdapter = require('../adapters/reputationIntelAdapter');
const dnsAdapter = require('../adapters/dnsAdapter');

class InfraEnricher {
    async enrich(threatObject) {
        console.log('[InfraEnricher] Executing independent multi-provider infrastructure enrichment...');

        threatObject.infrastructure = threatObject.infrastructure || {};
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip || null;

        // Execute all provider lookups concurrently without blocking execution if one fails
        const [geoResult, repResult, dnsResult] = await Promise.all([
            geoIntelAdapter.lookupIp(originIp),
            reputationIntelAdapter.lookupReputation(originIp),
            dnsAdapter.lookupPtr(originIp)
        ]);

        // Query anonymization using geoResult data if available
        const anonResult = await anonymizationIntelAdapter.lookupAnonymization(originIp, geoResult ? geoResult.raw_response : null);

        // Assemble unified, independent provider infrastructure intelligence block
        threatObject.infrastructure.asn = geoResult ? (geoResult.asn || 'UNAVAILABLE') : 'UNAVAILABLE';
        threatObject.infrastructure.isp = geoResult ? (geoResult.isp || 'UNAVAILABLE') : 'UNAVAILABLE';
        
        threatObject.infrastructure.geolocation = geoResult;
        threatObject.infrastructure.anonymization = anonResult;
        threatObject.infrastructure.reputation = repResult;
        threatObject.infrastructure.dns = dnsResult;
        threatObject.infrastructure.enriched_at = new Date().toISOString();

        return threatObject;
    }
}

module.exports = new InfraEnricher();
