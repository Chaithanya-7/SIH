const networkIntel = require('../adapters/networkIntelAdapter');
const geoIntelAdapter = require('../adapters/geoIntelAdapter');
const dnsAdapter = require('../adapters/dnsAdapter');
const ipClassifier = require('./ipClassifier');
const hostnameGeo = require('./hostnameGeo');
const { distanceKm } = require('./hostnameGeo');

/**
 * Where an address is, from several sources that do not share a lineage, with
 * an honest radius around the answer.
 *
 * ## The problem with one geolocation provider
 *
 * A single commercial database returns a city and a pair of coordinates for any
 * address you ask about, always, with no indication of how it knows. Much of
 * that is inference from registry records: the address block is registered to a
 * company with an address in Bengaluru, so every address in it is reported as
 * Bengaluru, whether the hardware is there or not. It is frequently right and
 * it is never uncertain, which is the dangerous combination - a map marker
 * drawn from it looks exactly as confident when it is a guess.
 *
 * ## What this does instead
 *
 * Five sources are asked, chosen because they fail differently:
 *
 *   1. **RIPE IPmap** - several measurement engines, and it reports which of
 *      them contributed. A location agreed by its latency and IXP engines rests
 *      on measurement; one from its reverse-DNS engine alone does not.
 *   2. **MaxMind GeoLite via RIPEstat** - a commercial database lineage.
 *   3. **ipwho.is** - a second commercial database, kept from the original
 *      implementation.
 *   4. **The router's own hostname** - operators name equipment after where it
 *      is, which describes the specific interface rather than the block.
 *   5. **PeeringDB** - where the originating network actually has equipment.
 *      Never a position; a constraint on one.
 *
 * Then the claims are clustered. Sources within a city of each other are
 * treated as agreeing, the best-supported cluster wins, and **the radius is the
 * larger of the winning sources' own precision and the spread between them** -
 * so a conclusion never looks tighter than the evidence under it.
 *
 * ## The three things it refuses to do
 *
 * **It will not average disagreement.** When sources are far apart, the mean of
 * Singapore and Virginia is the middle of the Pacific, which no source claims
 * and which would be drawn on a map as confidently as anything else. The
 * best-supported cluster is reported and the disagreement is stated.
 *
 * **It will not give an anycast address a position.** An anycast prefix is
 * announced from many places at once and is genuinely in all of them. Measured
 * while building this: 8.8.8.8 comes back Singapore from IPmap and the United
 * States from MaxMind, and both are right. A single coordinate for it is a
 * fiction.
 *
 * **It will not pretend two databases are two opinions.** Commercial
 * geolocation databases draw on overlapping registry data, so two of them
 * agreeing is close to one source speaking twice. Agreement between a
 * measurement and a database counts for far more, and the weighting says so.
 *
 * ## What it cannot do, which is the important part
 *
 * None of this locates a person. It locates infrastructure - and for a phishing
 * message that is usually a rented server or a compromised host, in a
 * datacentre, in a city the sender may never have visited. Public measurement
 * cannot turn an arbitrary address into a building, and an output shaped like a
 * street address would be a fabrication however good the pipeline behind it.
 * The answer is therefore always a coordinate, a radius, and the evidence.
 */

/**
 * How much each source's claim counts.
 *
 * Lineage matters more than count. Two commercial databases agreeing is one
 * kind of evidence; a measurement agreeing with a database is a stronger and
 * genuinely independent one.
 */
const SOURCE_WEIGHTS = {
    IPMAP_MEASURED: 1.0,   // latency, IXP or anycast engines contributed
    IPMAP_INFERRED: 0.55,  // only crowdsourced or reverse-DNS engines did
    MAXMIND: 0.6,
    IPWHOIS: 0.5,
    HOSTNAME: 0.45
};

/** Sources sharing a lineage are counted once when judging independence. */
const LINEAGE = {
    IPMAP_MEASURED: 'measurement',
    IPMAP_INFERRED: 'measurement-adjacent',
    MAXMIND: 'commercial-database',
    IPWHOIS: 'commercial-database',
    HOSTNAME: 'operator-naming'
};

/** Claims this far apart are describing the same place. */
const AGREEMENT_KM = 150;

class IpGeolocationEngine {
    /**
     * Locates one address.
     *
     * Never throws and never returns a coordinate without a radius. Returns a
     * refusal with a reason when the address cannot honestly be placed - a
     * private range, an anycast prefix, or simply no source that knows.
     */
    async locate(ip) {
        const classification = ipClassifier.classify(ip);
        if (!classification.routable) {
            return this.refusal(ip, `${ip} is not a routable public address (${classification.classification || 'reserved'}), so it has no location to find.`, { classification });
        }

        const [ipmap, ripestat, whois, ptr] = await Promise.all([
            networkIntel.ipmap(ip).catch(() => ({ status: 'UNAVAILABLE' })),
            networkIntel.ripestat(ip).catch(() => ({ status: 'UNAVAILABLE' })),
            geoIntelAdapter.lookupIp(ip).catch(() => ({ status: 'UNAVAILABLE' })),
            dnsAdapter.lookupPtr(ip).catch(() => null)
        ]);

        const claims = [];
        const notes = [];

        // 1. RIPE IPmap, weighted by which of its engines actually spoke.
        if (ipmap.status === 'AVAILABLE' && ipmap.latitude !== null) {
            const measured = (ipmap.engines_contributed || [])
                .some(e => ['latency', 'ixp', 'simple-anycast', 'single-radius'].includes(e.engine));
            claims.push({
                source: 'RIPE IPmap',
                kind: measured ? 'IPMAP_MEASURED' : 'IPMAP_INFERRED',
                lat: ipmap.latitude,
                lon: ipmap.longitude,
                city: ipmap.city,
                country_code: ipmap.country_code,
                own_radius_km: ipmap.radius_km || 40,
                detail: measured
                    ? `Measurement engines contributed (${(ipmap.engines_contributed || []).map(e => e.engine).join(', ')}).`
                    : `Only inference engines contributed (${(ipmap.engines_contributed || []).map(e => e.engine).join(', ') || 'none'}).`
            });
        } else if (ipmap.status === 'NO_LOCATION') {
            notes.push('RIPE IPmap holds no location for this address. Its engines cover infrastructure well and ordinary customer addresses poorly.');
        }

        // 2. MaxMind, through RIPEstat.
        const maxmind = ripestat.status === 'AVAILABLE' ? ripestat.maxmind : null;
        if (maxmind && maxmind.latitude !== null && maxmind.latitude !== undefined) {
            claims.push({
                source: 'MaxMind GeoLite (via RIPEstat)',
                kind: 'MAXMIND',
                lat: maxmind.latitude,
                lon: maxmind.longitude,
                city: maxmind.city || null,
                country_code: maxmind.country_code,
                // A database that reports a city is city-accurate at best, and
                // one that reports only a country is far coarser.
                own_radius_km: maxmind.city ? 50 : 600,
                detail: maxmind.city ? `Database record for ${maxmind.city}.` : 'Database record with a country but no city.'
            });
        }

        // 3. The provider already in use.
        if (whois.status === 'AVAILABLE' && whois.latitude !== null) {
            claims.push({
                source: 'ipwho.is',
                kind: 'IPWHOIS',
                lat: whois.latitude,
                lon: whois.longitude,
                city: whois.city,
                country_code: whois.country_code,
                own_radius_km: whois.city ? 50 : 600,
                detail: whois.city ? `Database record for ${whois.city}.` : 'Database record with no city.'
            });
        }

        // 4. The name the operator gave the equipment.
        // dnsAdapter reports this as `ptr`, and returns a string where there is
        // one name and an array where a address has several.
        const ptrValue = ptr?.status === 'AVAILABLE' ? ptr.ptr : null;
        const hostname = Array.isArray(ptrValue) ? ptrValue[0] : (ptrValue || null);
        const fromName = hostname ? hostnameGeo.locate(hostname) : null;
        if (fromName?.status === 'AVAILABLE') {
            claims.push({
                source: 'Router hostname',
                kind: 'HOSTNAME',
                lat: fromName.latitude,
                lon: fromName.longitude,
                city: fromName.city,
                country_code: fromName.country_code,
                own_radius_km: fromName.radius_km,
                detail: fromName.basis
            });
        } else if (hostname) {
            notes.push(`The address resolves to ${hostname}, which carries no location code this recognises.`);
        } else {
            notes.push('The address has no reverse-DNS name. Most do not, so this rules nothing out.');
        }

        // 5. PeeringDB: a constraint, never a position.
        const originAsn = (ripestat.origin_asns || [])[0] || whois.asn || null;
        const facilities = originAsn ? await networkIntel.peeringdb(originAsn).catch(() => ({ status: 'UNAVAILABLE' })) : { status: 'UNAVAILABLE' };

        return this.fuse(ip, {
            claims, notes, ipmap, ripestat, whois, facilities, originAsn, hostname, classification
        });
    }

    /**
     * Combines the claims into one answer with a radius that covers what the
     * sources actually disagree about.
     */
    fuse(ip, context) {
        const { claims, notes, ipmap, ripestat, facilities, originAsn, hostname, classification } = context;

        const evidence = claims.map(c => ({
            source: c.source,
            lineage: LINEAGE[c.kind],
            weight: SOURCE_WEIGHTS[c.kind],
            city: c.city,
            country_code: c.country_code,
            latitude: c.lat,
            longitude: c.lon,
            own_radius_km: c.own_radius_km,
            detail: c.detail
        }));

        // Anycast first. It is not a failure to locate; it is a correct answer
        // that no single coordinate can express.
        if (ipmap.anycast === true) {
            return {
                status: 'ANYCAST',
                ip,
                latitude: null,
                longitude: null,
                radius_km: null,
                confidence: 0,
                precision: 'ANYCAST',
                anycast: true,
                prefix: ripestat.prefix || null,
                origin_asn: originAsn,
                hostname,
                evidence,
                constraints: this.constraintsFrom(facilities, claims),
                notes,
                basis: 'This address is announced from many locations at once, and is genuinely in all of them. Whichever instance answers depends on where the question is asked from.',
                limitation: 'No single coordinate describes an anycast address. Sources will disagree wildly and each of them can be right; placing one dot on a map would be a fiction.'
            };
        }

        if (!claims.length) {
            return this.refusal(ip, 'No source that could be asked holds a location for this address.', {
                notes, evidence, prefix: ripestat.prefix || null, origin_asn: originAsn, hostname, classification
            });
        }

        // Cluster the claims, weight each cluster, and take the best.
        const clusters = [];
        for (const claim of claims) {
            const home = clusters.find(c => distanceKm(c.centre, { lat: claim.lat, lon: claim.lon }) <= AGREEMENT_KM);
            if (home) {
                home.members.push(claim);
                home.centre = this.centroid(home.members);
            } else {
                clusters.push({ members: [claim], centre: { lat: claim.lat, lon: claim.lon } });
            }
        }

        for (const cluster of clusters) {
            // Independent lineages, not member count. Two commercial databases
            // agreeing is close to one source speaking twice.
            const lineages = new Set(cluster.members.map(m => LINEAGE[m.kind]));
            cluster.weight = cluster.members.reduce((sum, m) => sum + SOURCE_WEIGHTS[m.kind], 0);
            cluster.lineages = [...lineages];
            cluster.independent = lineages.size;
        }

        clusters.sort((a, b) => (b.weight - a.weight) || (b.independent - a.independent));
        const best = clusters[0];
        const others = clusters.slice(1);

        // How far the rejected claims sit from the accepted answer. This is the
        // number the radius has to respect: a tight radius drawn while another
        // source says a different continent is a lie of omission.
        const disagreementKm = others.length
            ? Math.round(Math.max(...others.flatMap(c => c.members.map(m => distanceKm(best.centre, { lat: m.lat, lon: m.lon })))))
            : 0;

        // Spread inside the winning cluster.
        const spreadKm = best.members.length > 1
            ? Math.max(...best.members.map(m => distanceKm(best.centre, { lat: m.lat, lon: m.lon })))
            : 0;

        // The radius is never tighter than the coarsest source holding the
        // answer up, nor tighter than the sources disagree.
        const coarsest = Math.max(...best.members.map(m => m.own_radius_km));
        let radius = Math.round(Math.max(coarsest, spreadKm));
        if (disagreementKm > AGREEMENT_KM) {
            // Sources point at different places. The answer is the better
            // supported one, and the radius says the matter is not settled.
            radius = Math.round(Math.max(radius, Math.min(disagreementKm, 2000)));
        }

        const constraints = this.constraintsFrom(facilities, best.members);
        const contradicted = constraints.filter(c => c.contradicts);

        const confidence = this.confidenceOf(best, others, contradicted.length, radius);

        return {
            status: 'LOCATED',
            ip,
            latitude: Number(best.centre.lat.toFixed(4)),
            longitude: Number(best.centre.lon.toFixed(4)),
            radius_km: radius,
            confidence: Number(confidence.toFixed(2)),
            precision: radius <= 60 ? 'CITY' : radius <= 400 ? 'REGION' : 'COUNTRY_OR_WORSE',
            anycast: ipmap.anycast === true,
            city: best.members.map(m => m.city).find(Boolean) || null,
            country_code: best.members.map(m => m.country_code).find(Boolean) || null,
            prefix: ripestat.prefix || null,
            origin_asn: originAsn,
            hostname,
            agreeing_sources: best.members.map(m => m.source),
            independent_lineages: best.lineages,
            disagreeing_sources: others.flatMap(c => c.members.map(m => ({
                source: m.source,
                city: m.city,
                km_away: Math.round(distanceKm(best.centre, { lat: m.lat, lon: m.lon }))
            }))),
            disagreement_km: disagreementKm,
            evidence,
            constraints,
            notes,
            basis: this.describe(best, others, disagreementKm, radius, contradicted),
            limitation: 'This locates infrastructure, not a person. For a phishing message it is usually a rented or compromised server, in a datacentre, in a city the sender may never have been to. Public measurement cannot narrow an arbitrary address to a building, and the radius is the honest width of the answer rather than a rendering choice.'
        };
    }

    /** What PeeringDB says the originating network's footprint is. */
    constraintsFrom(facilities, members) {
        if (facilities.status !== 'AVAILABLE') return [];

        const claimedCountries = new Set(members.map(m => m.country_code).filter(Boolean));
        const footprint = new Set(facilities.countries || []);

        // Only a small footprint constrains anything. A carrier present in
        // forty countries excludes nothing.
        if (!facilities.constrains) {
            return [{
                source: 'PeeringDB',
                kind: 'FOOTPRINT',
                contradicts: false,
                detail: `The originating network has equipment in ${(facilities.cities || []).length} cities, which is too many to narrow anything down.`
            }];
        }

        const overlaps = [...claimedCountries].some(c => footprint.has(c));
        return [{
            source: 'PeeringDB',
            kind: 'FOOTPRINT',
            contradicts: claimedCountries.size > 0 && !overlaps,
            cities: facilities.cities,
            countries: facilities.countries,
            detail: overlaps
                ? `The originating network has equipment in ${(facilities.cities || []).join(', ')}, which includes the country this answer places it in.`
                : `The originating network has equipment only in ${(facilities.countries || []).join(', ')}, and this answer places the address elsewhere. One of the two is wrong.`
        }];
    }

    /**
     * Confidence, from independence rather than volume.
     *
     * Deliberately capped below certainty. Every input here is somebody else's
     * claim about somebody else's network, and none of it was verified from
     * this machine.
     */
    confidenceOf(best, others, contradictions, radius) {
        let score = 0.25;

        // Independent lineages agreeing is the thing that actually matters.
        score += Math.min(0.35, (best.independent - 1) * 0.2);

        // A measurement carries more than a database record.
        if (best.members.some(m => m.kind === 'IPMAP_MEASURED')) score += 0.2;

        // Unanimity, where there was anything to disagree.
        if (!others.length && best.members.length > 1) score += 0.1;

        // Disagreement and contradiction both cost.
        if (others.length) score -= Math.min(0.2, others.length * 0.1);
        score -= contradictions * 0.15;

        // A wide answer is a weak one however many sources produced it.
        if (radius > 400) score -= 0.1;
        if (radius > 1000) score -= 0.1;

        return Math.max(0.05, Math.min(0.9, score));
    }

    centroid(members) {
        const lat = members.reduce((s, m) => s + m.lat, 0) / members.length;
        const lon = members.reduce((s, m) => s + m.lon, 0) / members.length;
        return { lat, lon };
    }

    describe(best, others, disagreementKm, radius, contradicted) {
        const parts = [];
        parts.push(`${best.members.length} source(s) across ${best.independent} independent lineage(s) place this address within about ${radius} km: ${best.members.map(m => m.source).join(', ')}.`);

        if (others.length) {
            parts.push(`${others.flatMap(c => c.members).length} other source(s) disagree, by up to ${disagreementKm} km. The better-supported answer is given and the radius covers the disagreement rather than hiding it.`);
        }
        if (contradicted.length) {
            parts.push(contradicted.map(c => c.detail).join(' '));
        }
        return parts.join(' ');
    }

    refusal(ip, reason, extra = {}) {
        return {
            status: 'NOT_LOCATED',
            ip,
            latitude: null,
            longitude: null,
            radius_km: null,
            confidence: 0,
            precision: 'NONE',
            anycast: false,
            reason,
            evidence: [],
            constraints: [],
            notes: [],
            ...extra,
            limitation: 'Reported as not located rather than guessed. An address with no evidence behind it is not the same as one in the middle of a country, and a map cannot tell the difference once a coordinate is drawn.'
        };
    }

    state() {
        return {
            sources: ['RIPE IPmap', 'MaxMind GeoLite via RIPEstat', 'ipwho.is', 'Router hostname (PTR)', 'PeeringDB facilities'],
            weights: SOURCE_WEIGHTS,
            agreement_km: AGREEMENT_KM,
            network_intel: networkIntel.state(),
            not_implemented: {
                'RIPE Atlas active measurement, RTT triangulation, multilateration':
                    'Needs Atlas credits, which are earned by hosting a probe, and means commissioning measurements against somebody else\'s infrastructure.',
                'Traceroute from this machine, intermediate-hop geolocation':
                    'Sends packets to attacker-controlled infrastructure from the machine being protected, which confirms somebody is there. Also needs raw sockets and administrator rights on Windows.',
                'CAIDA ITDK, Hoiho regex corpus, alias resolution':
                    'Multi-gigabyte datasets behind registration and an acceptable-use agreement. The hostname reader here is a small dictionary in the same spirit.',
                'BGPStream':
                    'Needs a native library compiled per platform, which a desktop install cannot assume.'
            }
        };
    }
}

module.exports = new IpGeolocationEngine();
module.exports.IpGeolocationEngine = IpGeolocationEngine;
module.exports.SOURCE_WEIGHTS = SOURCE_WEIGHTS;
module.exports.AGREEMENT_KM = AGREEMENT_KM;
