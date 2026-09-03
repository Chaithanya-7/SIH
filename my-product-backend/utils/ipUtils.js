/**
 * Comprehensive IP Utility module for IPv4 and IPv6 validation and range classification.
 */

class IPUtils {
    /**
     * Checks if a string is a valid IPv4 address.
     */
    isIPv4(ip) {
        if (typeof ip !== 'string') return false;
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every(part => {
            if (!/^\d+$/.test(part)) return false;
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && (part === '0' || !part.startsWith('0'));
        });
    }

    /**
     * Checks if a string is a valid IPv6 address.
     */
    isIPv6(ip) {
        if (typeof ip !== 'string') return false;
        // Basic IPv6 regex pattern
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
        return ipv6Regex.test(ip);
    }

    /**
     * Checks if an IP address is valid (IPv4 or IPv6).
     */
    isValidIP(ip) {
        return this.isIPv4(ip) || this.isIPv6(ip);
    }

    /**
     * Checks if an IP is non-public or non-origin (loopback, private RFC1918, CGNAT, link-local, test ranges, multicast, unspecified).
     */
    isNonPublicIP(ip) {
        if (!this.isValidIP(ip)) return true;

        if (this.isIPv4(ip)) {
            const parts = ip.split('.').map(Number);
            const [b1, b2, b3, b4] = parts;

            // Loopback: 127.0.0.0/8
            if (b1 === 127) return true;

            // Unspecified: 0.0.0.0/8
            if (b1 === 0) return true;

            // Private RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (b1 === 10) return true;
            if (b1 === 172 && b2 >= 16 && b2 <= 31) return true;
            if (b1 === 192 && b2 === 168) return true;

            // Shared CGNAT: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
            if (b1 === 100 && b2 >= 64 && b2 <= 127) return true;

            // Link-Local: 169.254.0.0/16
            if (b1 === 169 && b2 === 254) return true;

            // Documentation / Test Ranges:
            // TEST-NET-1: 192.0.2.0/24
            // TEST-NET-2: 198.51.100.0/24
            // TEST-NET-3: 203.0.113.0/24
            if (b1 === 192 && b2 === 0 && b3 === 2) return true;
            if (b1 === 198 && b2 === 51 && b3 === 100) return true;
            if (b1 === 203 && b2 === 0 && b3 === 113) return true;

            // Multicast: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
            if (b1 >= 224 && b1 <= 239) return true;

            // Reserved / Broadcast: 240.0.0.0/4
            if (b1 >= 240) return true;

            return false;
        }

        if (this.isIPv6(ip)) {
            const normalized = ip.toLowerCase();
            // Loopback & Unspecified
            if (normalized === '::1' || normalized === '::') return true;
            // Link-local fe80::/10
            if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
            // Unique local fc00::/7
            if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
            // Multicast ff00::/8
            if (normalized.startsWith('ff')) return true;
            // Documentation 2001:db8::/32
            if (normalized.startsWith('2001:db8:')) return true;

            return false;
        }

        return true;
    }
}

module.exports = new IPUtils();
