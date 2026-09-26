const axios = require('axios');
const ipUtils = require('../utils/ipUtils');

class AnonymizationIntelAdapter {
    constructor() {
        this.apiKey = process.env.VPNAPI_API_KEY || '';
    }

    async lookupAnonymization(ip, rawGeoData = null) {
        if (!ip || ipUtils.isNonPublicIP(ip)) {
            return {
                status: 'UNAVAILABLE',
                provider: 'VPNAPI',
                vpn: null,
                proxy: null,
                tor: null,
                hosting: null,
                reason: 'Non-public IP address'
            };
        }

        // 1. Try dedicated VPNAPI provider if key is configured
        if (this.apiKey) {
            try {
                const res = await axios.get(`https://vpnapi.io/api/${ip}?key=${this.apiKey}`, { timeout: 3000 });
                if (res.data && res.data.security) {
                    return {
                        status: 'AVAILABLE',
                        provider: 'VPNAPI',
                        vpn: !!res.data.security.vpn,
                        proxy: !!res.data.security.proxy,
                        tor: !!res.data.security.tor,
                        hosting: !!res.data.security.hosting
                    };
                }
            } catch (err) {
                console.log(`[AnonymizationIntelAdapter] VPNAPI lookup failed for ${ip}: ${err.message}`);
            }
        }

        // 2. Fall back to IP-API proxy/hosting fields if provided by geoIntelAdapter
        if (rawGeoData && rawGeoData.status === 'success') {
            return {
                status: 'AVAILABLE',
                provider: 'IP-API_FIELDS',
                vpn: rawGeoData.proxy ? true : false,
                proxy: rawGeoData.proxy ? true : false,
                tor: false, // ip-api doesn't distinguish tor separately
                hosting: rawGeoData.hosting ? true : false
            };
        }

        // 3. Provider is unconfigured or failed - return UNAVAILABLE with nulls (not false)
        return {
            status: 'UNAVAILABLE',
            provider: 'UNCONFIGURED',
            vpn: null,
            proxy: null,
            tor: null,
            hosting: null
        };
    }
}

module.exports = new AnonymizationIntelAdapter();
