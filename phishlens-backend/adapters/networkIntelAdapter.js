const https = require('https');
const fs = require('fs');
const { dataFile } = require('../modules/dataPaths');

/**
 * Network-level intelligence about an address, from sources that are free, need
 * no account, and answer without being paid.
 *
 * Three services, each answering a different question:
 *
 *   - **RIPE IPmap** - where several independent engines think this address is.
 *     It runs crowdsourced, latency, IXP, reverse-DNS and anycast engines and
 *     returns their individual contributions, not only a verdict, so the
 *     disagreement between them is visible.
 *   - **RIPEstat** - which prefix announces this address, which autonomous
 *     system originates it, and a MaxMind-derived location as a second opinion
 *     from a completely different lineage.
 *   - **PeeringDB** - where that autonomous system actually has equipment. Not
 *     a location for the address, a *constraint* on it: a network present only
 *     in Ashburn, Chicago and San Jose is unlikely to be routing from Perth.
 *
 * ## What this deliberately does not do
 *
 * No active measurement is commissioned from here. RIPE Atlas can be asked to
 * traceroute and ping a target from thousands of probes, and latency
 * multilateration from those is the most accurate public method there is - but
 * it costs credits, which are earned by hosting a probe, and it means
 * commissioning measurements against somebody else's infrastructure.
 *
 * A traceroute from *this* machine is worse still. It sends packets to
 * attacker-controlled infrastructure from the very machine being protected,
 * which confirms somebody is there and reading. The connection evidence module
 * exists to notice that happening; this one is not going to do it deliberately.
 *
 * One caveat worth stating plainly: IPmap's own `single-radius` engine schedules
 * an active measurement when it has no cached answer. That is RIPE's probes
 * touching the target, not this machine, and it reveals only that somebody
 * asked RIPE about the address - but it is an active measurement, and pretending
 * otherwise would be wrong.
 */

const TIMEOUT_MS = 6000;
const CACHE_MAX = 5000;

/** Everything here is slow and rate-limited, and an address does not move often. */
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

class NetworkIntelAdapter {
    constructor() {
        this.cacheFile = dataFile('network_intel_cache.json');
        this.cache = new Map();
        this.calls = { ipmap: 0, ripestat: 0, peeringdb: 0, cached: 0, failed: 0 };
        this.load();
    }

    load() {
        try {
            if (!fs.existsSync(this.cacheFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8') || '{}');
            Object.entries(stored.entries || {}).forEach(([key, value]) => this.cache.set(key, value));
        } catch (e) {
            console.error('[NetworkIntel] Could not read the cache:', e.message);
        }
    }

    save() {
        try {
            const entries = {};
            // Bounded, newest kept. An unbounded cache of every address ever
            // seen becomes a record of correspondence nobody asked for.
            const ordered = [...this.cache.entries()].slice(-CACHE_MAX);
            ordered.forEach(([key, value]) => { entries[key] = value; });
            this.cache = new Map(ordered);
            fs.writeFileSync(this.cacheFile, JSON.stringify({ entries, saved_at: new Date().toISOString() }, null, 2));
        } catch (e) {
            console.error('[NetworkIntel] Could not write the cache:', e.message);
        }
    }

    cached(key) {
        const hit = this.cache.get(key);
        if (!hit) return null;
        if (Date.now() - Date.parse(hit.cached_at || 0) > CACHE_TTL_MS) {
            this.cache.delete(key);
            return null;
        }
        this.calls.cached += 1;
        return hit.value;
    }

    remember(key, value) {
        this.cache.set(key, { value, cached_at: new Date().toISOString() });
        this.save();
        return value;
    }

    /** A JSON GET that follows one redirect and never throws. */
    getJson(url, redirectsLeft = 2) {
        return new Promise(resolve => {
            let settled = false;
            const done = value => { if (!settled) { settled = true; resolve(value); } };

            const request = https.get(url, {
                timeout: TIMEOUT_MS,
                headers: {
                    // Named so an operator reading their logs can tell what this
                    // is. Anonymous scraping of a free service is how free
                    // services stop being free.
                    'User-Agent': 'PhishLens/1.7 (local phishing analysis; https://github.com/mdyounus-git/PhishLens)',
                    Accept: 'application/json'
                }
            }, response => {
                // IPmap answers on a different host than it is documented under.
                if ([301, 302, 307, 308].includes(response.statusCode) && response.headers.location && redirectsLeft > 0) {
                    response.resume();
                    return done(this.getJson(response.headers.location, redirectsLeft - 1));
                }
                if (response.statusCode !== 200) { response.resume(); return done(null); }

                let body = '';
                response.setEncoding('utf8');
                response.on('data', chunk => {
                    body += chunk;
                    // A free endpoint answering with something enormous is a
                    // fault, not data.
                    if (body.length > 4 * 1024 * 1024) { request.destroy(); done(null); }
                });
                response.on('end', () => {
                    try { done(JSON.parse(body)); } catch (e) { done(null); }
                });
            });

            request.on('timeout', () => { request.destroy(); done(null); });
            request.on('error', () => done(null));
        });
    }

    /**
     * RIPE IPmap: several engines, and what each of them concluded.
     *
     * The per-engine breakdown is the valuable part. A location agreed by the
     * latency and IXP engines is a different thing from one guessed by the
     * reverse-DNS engine alone, and a single verdict hides that.
     */
    async ipmap(ip) {
        const key = `ipmap:${ip}`;
        const hit = this.cached(key);
        if (hit) return hit;

        this.calls.ipmap += 1;
        const body = await this.getJson(`https://ipmap-api.ripe.net/v1/locate/${encodeURIComponent(ip)}/best`);
        if (!body) {
            this.calls.failed += 1;
            return { status: 'UNAVAILABLE', reason: 'RIPE IPmap did not answer.' };
        }

        const engines = body?.metadata?.service?.contributions?.[ip]?.engines || [];
        const location = body.location;

        // Which engines actually contributed, rather than which exist.
        const contributed = engines.filter(e => !e.empty).map(e => ({
            engine: e.engine,
            type: e.type,
            weight: e.scoreFactor ?? null
        }));

        const anycast = engines.find(e => e.engine === 'simple-anycast');

        if (!location) {
            return this.remember(key, {
                status: 'NO_LOCATION',
                reason: 'RIPE IPmap holds no location for this address. Its engines cover infrastructure far better than they cover ordinary customer addresses.',
                engines_available: engines.map(e => e.engine),
                engines_contributed: contributed,
                anycast: anycast?.metadata?.anycast ?? null
            });
        }

        return this.remember(key, {
            status: 'AVAILABLE',
            city: location.cityName || null,
            country_code: location.countryCodeAlpha2 || null,
            iata: location.iataCode || null,
            latitude: typeof location.latitude === 'number' ? location.latitude : null,
            longitude: typeof location.longitude === 'number' ? location.longitude : null,
            engines_contributed: contributed,
            // A city-level answer. IPmap resolves to a city, never to a street.
            radius_km: 40,
            anycast: anycast?.metadata?.anycast ?? null
        });
    }

    /** RIPEstat: the prefix, the originating network, and a second geolocation lineage. */
    async ripestat(ip) {
        const key = `ripestat:${ip}`;
        const hit = this.cached(key);
        if (hit) return hit;

        this.calls.ripestat += 1;
        const [network, geo] = await Promise.all([
            this.getJson(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`),
            this.getJson(`https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}`)
        ]);

        if (!network && !geo) {
            this.calls.failed += 1;
            return { status: 'UNAVAILABLE', reason: 'RIPEstat did not answer.' };
        }

        const asns = network?.data?.asns || [];
        const located = geo?.data?.located_resources?.[0]?.locations?.[0] || null;

        return this.remember(key, {
            status: 'AVAILABLE',
            prefix: network?.data?.prefix || null,
            origin_asns: asns.map(a => `AS${a}`),
            // A different lineage from IPmap's, which is the point of having it:
            // two sources that share a database agreeing means nothing.
            maxmind: located
                ? {
                    country_code: located.country || null,
                    city: located.city || null,
                    latitude: typeof located.latitude === 'number' ? located.latitude : null,
                    longitude: typeof located.longitude === 'number' ? located.longitude : null,
                    covered_percentage: located.covered_percentage ?? null
                }
                : null
        });
    }

    /**
     * PeeringDB: where a network actually has equipment.
     *
     * This is a constraint, never a position. A network with facilities in three
     * cities tells you the address is probably in one of them - and, more
     * usefully, that a claim placing it somewhere else deserves suspicion.
     */
    async peeringdb(asn) {
        const number = String(asn || '').replace(/^AS/i, '');
        if (!/^\d+$/.test(number)) return { status: 'UNAVAILABLE', reason: 'No usable AS number.' };

        const key = `peeringdb:${number}`;
        const hit = this.cached(key);
        if (hit) return hit;

        this.calls.peeringdb += 1;
        const body = await this.getJson(`https://www.peeringdb.com/api/netfac?asn=${number}&limit=60`);
        if (!body) {
            this.calls.failed += 1;
            return { status: 'UNAVAILABLE', reason: 'PeeringDB did not answer.' };
        }

        const facilities = (body.data || []).map(f => ({
            name: f.name || null,
            city: f.city || null,
            country_code: f.country || null
        })).filter(f => f.city);

        if (!facilities.length) {
            return this.remember(key, {
                status: 'NO_FACILITIES',
                reason: 'PeeringDB lists no facilities for this network. Most networks are not in PeeringDB at all; absence says nothing.'
            });
        }

        const countries = [...new Set(facilities.map(f => f.country_code).filter(Boolean))];
        const cities = [...new Set(facilities.map(f => f.city))];

        return this.remember(key, {
            status: 'AVAILABLE',
            facilities: facilities.slice(0, 25),
            cities,
            countries,
            // One city is a real constraint; forty is a global carrier and
            // constrains nothing at all.
            constrains: cities.length <= 6
        });
    }

    state() {
        return {
            sources: ['RIPE IPmap', 'RIPEstat (network-info, MaxMind GeoLite)', 'PeeringDB'],
            calls: { ...this.calls },
            cached_entries: this.cache.size,
            cache_days: Math.round(CACHE_TTL_MS / 86400000),
            cost: 'All three are free and need no account. None is asked to perform a measurement on request.',
            caveat: "RIPE IPmap's own single-radius engine may schedule an active measurement toward the address when it has no cached answer. That is RIPE's probes, not this machine."
        };
    }
}

module.exports = new NetworkIntelAdapter();
module.exports.NetworkIntelAdapter = NetworkIntelAdapter;
