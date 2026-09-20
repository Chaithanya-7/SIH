const dns = require('dns').promises;
const withDeadline = require('../modules/withDeadline');
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
            // Each lookup gets its own deadline.
            //
            // One timeout promise was created here and raced against both this
            // lookup and the forward confirmation below. The clock starts when
            // the promise is made, not when a race begins, so the second lookup
            // inherited whatever time the first left over - and after a slow
            // PTR it failed at once, having been given no chance at all.
            const ptrs = await withDeadline(dns.reverse(ip), 2500, `PTR lookup for ${ip}`);
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
                const forwardIps = await withDeadline(dns.resolve4(ptr), 2500, `forward lookup for ${ptr}`);
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
