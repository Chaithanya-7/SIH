const axios = require('axios');
const ipUtils = require('../utils/ipUtils');

class GeoIntelAdapter {
    constructor() {
        // In-memory cache for IP geolocation lookups to prevent duplicate API calls
        this.cache = new Map();
    }

    async lookupIp(ip) {
        if (!ip || ipUtils.isNonPublicIP(ip)) {
            return {
                status: 'UNAVAILABLE',
                provider: 'IP-API',
                ip: ip || null,
                country: null,
                country_code: null,
                region: null,
                city: null,
                latitude: null,
                longitude: null,
                asn: null,
                isp: null,
                organization: null,
                raw_response: null,
                reason: 'Non-public or invalid IP address'
            };
        }

        // Check in-memory cache
        if (this.cache.has(ip)) {
            console.log(`[GeoIntelAdapter] Cache hit for IP ${ip}`);
            return this.cache.get(ip);
        }

        try {
            console.log(`[GeoIntelAdapter] Querying live IP-API for IP ${ip}...`);
            const res = await axios.get(
                `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting`,
                { timeout: 3000 }
            );

            if (res.data && res.data.status === 'success') {
                const geoResult = {
                    status: 'AVAILABLE',
                    provider: 'IP-API',
                    ip,
                    country: res.data.country || null,
                    country_code: res.data.countryCode || null,
                    region: res.data.regionName || null,
                    city: res.data.city || null,
                    latitude: typeof res.data.lat === 'number' ? res.data.lat : null,
                    longitude: typeof res.data.lon === 'number' ? res.data.lon : null,
                    asn: res.data.as || null,
                    isp: res.data.isp || null,
                    organization: res.data.org || null,
                    raw_response: res.data
                };

                this.cache.set(ip, geoResult);
                return geoResult;
            } else {
                console.log(`[GeoIntelAdapter] IP-API error response for IP ${ip}: ${res.data?.message || 'Unknown'}`);
            }
        } catch (err) {
            console.log(`[GeoIntelAdapter] External Geo API call failed for IP ${ip}: ${err.message}`);
        }

        // NO FAKE FALLBACKS - Return UNAVAILABLE with nulls
        const unavailableResult = {
            status: 'UNAVAILABLE',
            provider: 'IP-API',
            ip,
            country: null,
            country_code: null,
            region: null,
            city: null,
            latitude: null,
            longitude: null,
            asn: null,
            isp: null,
            organization: null,
            raw_response: null,
            reason: 'External API call failed or rate-limited'
        };

        return unavailableResult;
    }
}

module.exports = new GeoIntelAdapter();
