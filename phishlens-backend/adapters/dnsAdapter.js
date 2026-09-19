const dns = require('dns').promises;
const ipUtils = require('../utils/ipUtils');

class DNSAdapter {
    async lookupPtr(ip) {
        if (!ip || ipUtils.isNonPublicIP(ip)) {
            return {
                status: 'UNAVAILABLE',
                ip: ip || null,
                ptr: null,
                forward_confirmed: false,
                provider: 'SYSTEM_DNS',
                reason: 'Non-public or invalid IP address'
            };
        }

        try {
            // Perform reverse DNS lookup (PTR) with 2.5s timeout logic
            const ptrPromise = dns.reverse(ip);
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('DNS PTR lookup timeout')), 2500)
            );

            const ptrs = await Promise.race([ptrPromise, timeoutPromise]);
            const ptr = ptrs && ptrs.length > 0 ? ptrs[0] : null;

            if (!ptr) {
                return {
                    status: 'UNAVAILABLE',
                    ip,
                    ptr: null,
                    forward_confirmed: false,
                    provider: 'SYSTEM_DNS',
                    reason: 'No PTR record found'
                };
            }

            // Perform forward confirmation lookup (FCrDNS)
            let forwardConfirmed = false;
            try {
                const forwardIpsPromise = dns.resolve4(ptr);
                const forwardIps = await Promise.race([forwardIpsPromise, timeoutPromise]);
                forwardConfirmed = forwardIps && forwardIps.includes(ip);
            } catch (fcErr) {
                forwardConfirmed = false;
            }

            return {
                status: 'AVAILABLE',
                ip,
                ptr,
                forward_confirmed: forwardConfirmed,
                provider: 'SYSTEM_DNS'
            };
        } catch (err) {
            return {
                status: 'UNAVAILABLE',
                ip,
                ptr: null,
                forward_confirmed: false,
                provider: 'SYSTEM_DNS',
                reason: err.message
            };
        }
    }
}

module.exports = new DNSAdapter();
