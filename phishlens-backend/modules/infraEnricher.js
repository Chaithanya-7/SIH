const geoIntelAdapter = require('../adapters/geoIntelAdapter');
const anonymizationIntelAdapter = require('../adapters/anonymizationIntelAdapter');
const reputationIntelAdapter = require('../adapters/reputationIntelAdapter');
const ipClassifier = require('./ipClassifier');
const dnsblReputation = require('./dnsblReputation');
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
        
        // Stage 1 of the IP pipeline, and the one everything else rests on.
        //
        // Stated outright rather than inferred from a provider declining to
        // answer. "There was nothing to look up" and "the lookup failed" are
        // different facts, and only this can tell them apart.
        threatObject.infrastructure.classification = ipClassifier.classify(originIp);

        threatObject.infrastructure.geolocation = geoResult;
        threatObject.infrastructure.anonymization = anonResult;
        threatObject.infrastructure.reputation = repResult;

        // Stage 4, made real. The keyed providers above answer UNAVAILABLE on
        // any install without a paid subscription, which is every install of
        // this tool; public blocklists answer over plain DNS with no account,
        // so this is the reputation evidence that actually exists.
        try {
            threatObject.infrastructure.blocklists = await dnsblReputation.check(originIp);
        } catch (e) {
            threatObject.infrastructure.blocklists = {
                ip: originIp,
                queried: false,
                reason: `Blocklist lookup failed: ${e.message}`,
                lists: []
            };
        }
        threatObject.infrastructure.dns = dnsResult;
        threatObject.infrastructure.enriched_at = new Date().toISOString();

        threatObject.infrastructure.geo_points = await this.locateAllAddresses(threatObject, originIp, geoResult);

        return threatObject;
    }

    /**
     * Locates every public address associated with the message, not only the
     * selected origin. A relay chain often crosses several networks, and an
     * analyst looking at a map needs to see the whole path rather than one
     * point chosen by a heuristic.
     *
     * Lookups run concurrently and are bounded per message, since a crafted
     * header chain could otherwise list dozens of addresses.
     */
    async locateAllAddresses(threatObject, originIp, originGeo) {
        const MAX_ADDRESSES = 12;
        const seen = new Map();

        if (originIp) seen.set(originIp, 'ORIGIN');
        (threatObject.forensics?.smtp_relay || []).forEach(hop => {
            if (hop.ip && hop.ip !== 'UNAVAILABLE' && hop.is_public && !seen.has(hop.ip)) {
                seen.set(hop.ip, hop.classification || 'RELAY');
            }
        });
        (threatObject.iocs?.ips || []).forEach(ip => { if (!seen.has(ip)) seen.set(ip, 'INDICATOR'); });

        const addresses = Array.from(seen.entries()).slice(0, MAX_ADDRESSES);

        const located = await Promise.all(addresses.map(async ([ip, role]) => {
            // The origin was already resolved above; reuse it rather than
            // querying the same address twice for one message.
            const geo = (ip === originIp && originGeo) ? originGeo : await geoIntelAdapter.lookupIp(ip);
            if (geo.status !== 'AVAILABLE' || geo.latitude === null || geo.longitude === null) return null;

            return {
                ip,
                role,
                latitude: geo.latitude,
                longitude: geo.longitude,
                city: geo.city,
                country: geo.country,
                country_code: geo.country_code,
                asn: geo.asn,
                isp: geo.isp
            };
        }));

        return located.filter(Boolean);
    }
}

module.exports = new InfraEnricher();
