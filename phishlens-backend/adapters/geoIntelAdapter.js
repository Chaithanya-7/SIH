const https = require('https');
const fs = require('fs');
const path = require('path');
const ipUtils = require('../utils/ipUtils');

/**
 * IP geolocation.
 *
 * Two things changed here from the original implementation. It queried
 * ip-api.com over plain HTTP, which the project's own audit flagged: the
 * addresses observed in the operator's mail travelled across the network in
 * clear text, and the response steering the map could be modified in transit.
 * Requests now go over HTTPS to a free, key-less endpoint.
 *
 * Results are also cached to disk rather than only in memory. An address's
 * location rarely changes, so a restart should not mean re-querying every
 * address the deployment has ever seen - that was both slow and a needless
 * disclosure of the same data again.
 *
 * Location describes where the observed infrastructure sits. It is not the
 * location of a person, and every consumer of this data is expected to say so.
 */

const CACHE_TTL_MS = 30 * 24 * 3600 * 1000;
const MAX_CACHE_ENTRIES = 20000;

class GeoIntelAdapter {
    constructor() {
        this.cacheFile = path.join(__dirname, '../data/geo_cache.json');
        this.cache = new Map();
        this.loadCache();
    }

    loadCache() {
        try {
            const dataDir = path.dirname(this.cacheFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.cacheFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8') || '[]');
            stored.forEach(entry => { if (entry.ip) this.cache.set(entry.ip, entry); });
            console.log(`[GeoIntel] Loaded cached geolocation for ${this.cache.size} address(es).`);
        } catch (e) {
            console.error('[GeoIntel] Cache load error:', e.message);
        }
    }

    saveCache() {
        try {
            const entries = Array.from(this.cache.values()).slice(-MAX_CACHE_ENTRIES);
            fs.writeFileSync(this.cacheFile, JSON.stringify(entries));
        } catch (e) {
            console.error('[GeoIntel] Cache save error:', e.message);
        }
    }

    unavailable(ip, reason) {
        return {
            status: 'UNAVAILABLE',
            provider: 'ipwho.is',
            ip: ip || null,
            country: null, country_code: null, region: null, city: null,
            latitude: null, longitude: null, asn: null, isp: null, organization: null,
            reason
        };
    }

    fetch(ip, timeoutMs = 4000) {
        return new Promise((resolve, reject) => {
            const request = https.get(`https://ipwho.is/${encodeURIComponent(ip)}`, {
                headers: { 'User-Agent': 'PhishLens/1.0' },
                timeout: timeoutMs
            }, response => {
                if (response.statusCode !== 200) {
                    response.resume();
                    return reject(new Error(`HTTP ${response.statusCode}`));
                }
                let body = '';
                response.setEncoding('utf8');
                response.on('data', c => { body += c; });
                response.on('end', () => {
                    try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('Malformed geolocation response')); }
                });
            });
            request.on('timeout', () => request.destroy(new Error('Geolocation lookup timeout')));
            request.on('error', reject);
        });
    }

    async lookupIp(ip) {
        if (!ip || ipUtils.isNonPublicIP(ip)) {
            return this.unavailable(ip, 'Non-public or invalid IP address');
        }

        const cached = this.cache.get(ip);
        if (cached && Date.now() - new Date(cached.cached_at).getTime() < CACHE_TTL_MS) {
            return { ...cached, cached: true };
        }

        try {
            const data = await this.fetch(ip);

            // The service reports reserved and bogon ranges as unsuccessful
            // rather than guessing a location, which is the correct behaviour
            // and is passed through rather than masked.
            if (!data || data.success === false) {
                const miss = this.unavailable(ip, data?.message || 'No geolocation available for this address');
                miss.cached_at = new Date().toISOString();
                this.cache.set(ip, miss);
                this.saveCache();
                return miss;
            }

            const result = {
                status: 'AVAILABLE',
                provider: 'ipwho.is',
                ip,
                country: data.country || null,
                country_code: data.country_code || null,
                region: data.region || null,
                city: data.city || null,
                latitude: typeof data.latitude === 'number' ? data.latitude : null,
                longitude: typeof data.longitude === 'number' ? data.longitude : null,
                asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
                isp: data.connection?.isp || null,
                organization: data.connection?.org || null,
                cached_at: new Date().toISOString(),
                limitation: 'This is the location of the observed sending infrastructure, not of the person who sent the message.'
            };

            this.cache.set(ip, result);
            this.saveCache();
            return result;
        } catch (err) {
            // A failed lookup is not cached as a permanent miss: the address may
            // resolve fine once a rate limit or outage passes.
            return this.unavailable(ip, err.message);
        }
    }

    getStats() {
        const resolved = Array.from(this.cache.values()).filter(e => e.status === 'AVAILABLE').length;
        return { addresses_cached: this.cache.size, resolved, unresolved: this.cache.size - resolved };
    }
}

module.exports = new GeoIntelAdapter();
