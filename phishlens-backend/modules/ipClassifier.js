/**
 * What kind of address is this, before anything is asked about it.
 *
 * This is the first stage of the IP pipeline and it was the missing one. Every
 * later stage depends on the answer: a geolocation lookup for 192.168.1.10
 * returns nothing useful, a reputation lookup for 127.0.0.1 is meaningless, and
 * treating either as "unknown" quietly loses the difference between "we could
 * not find out" and "there was nothing to find out". The adapters were
 * inferring this from a provider's failure to answer, which is a guess dressed
 * as a fact.
 *
 * Entirely local: no network, no service, no key. It is arithmetic over the
 * address itself, so it works offline and cannot be rate-limited.
 *
 * Ranges are cited to the RFC that reserves them, because "special" is not a
 * property of an address, it is a decision somebody wrote down.
 */

const IPV4_SPECIAL = [
    { cidr: '0.0.0.0/8', scope: 'RESERVED', label: 'This network', rfc: 'RFC 1122 §3.2.1.3' },
    { cidr: '10.0.0.0/8', scope: 'PRIVATE', label: 'Private use', rfc: 'RFC 1918' },
    { cidr: '100.64.0.0/10', scope: 'CARRIER_GRADE_NAT', label: 'Shared address space', rfc: 'RFC 6598' },
    { cidr: '127.0.0.0/8', scope: 'LOOPBACK', label: 'Loopback', rfc: 'RFC 1122 §3.2.1.3' },
    { cidr: '169.254.0.0/16', scope: 'LINK_LOCAL', label: 'Link local', rfc: 'RFC 3927' },
    { cidr: '172.16.0.0/12', scope: 'PRIVATE', label: 'Private use', rfc: 'RFC 1918' },
    { cidr: '192.0.0.0/24', scope: 'RESERVED', label: 'IETF protocol assignments', rfc: 'RFC 6890' },
    { cidr: '192.0.2.0/24', scope: 'DOCUMENTATION', label: 'TEST-NET-1', rfc: 'RFC 5737' },
    { cidr: '192.88.99.0/24', scope: 'RESERVED', label: '6to4 relay anycast (deprecated)', rfc: 'RFC 7526' },
    { cidr: '192.168.0.0/16', scope: 'PRIVATE', label: 'Private use', rfc: 'RFC 1918' },
    { cidr: '198.18.0.0/15', scope: 'BENCHMARKING', label: 'Network benchmark testing', rfc: 'RFC 2544' },
    { cidr: '198.51.100.0/24', scope: 'DOCUMENTATION', label: 'TEST-NET-2', rfc: 'RFC 5737' },
    { cidr: '203.0.113.0/24', scope: 'DOCUMENTATION', label: 'TEST-NET-3', rfc: 'RFC 5737' },
    { cidr: '224.0.0.0/4', scope: 'MULTICAST', label: 'Multicast', rfc: 'RFC 5771' },
    { cidr: '240.0.0.0/4', scope: 'RESERVED', label: 'Reserved for future use', rfc: 'RFC 1112 §4' },
    { cidr: '255.255.255.255/32', scope: 'BROADCAST', label: 'Limited broadcast', rfc: 'RFC 8190' }
];

const IPV6_SPECIAL = [
    { cidr: '::/128', scope: 'RESERVED', label: 'Unspecified address', rfc: 'RFC 4291 §2.5.2' },
    { cidr: '::1/128', scope: 'LOOPBACK', label: 'Loopback', rfc: 'RFC 4291 §2.5.3' },
    { cidr: '64:ff9b::/96', scope: 'RESERVED', label: 'IPv4/IPv6 translation', rfc: 'RFC 6052' },
    { cidr: '100::/64', scope: 'RESERVED', label: 'Discard-only address block', rfc: 'RFC 6666' },
    { cidr: '2001::/32', scope: 'RESERVED', label: 'Teredo tunnelling', rfc: 'RFC 4380' },
    { cidr: '2001:20::/28', scope: 'RESERVED', label: 'ORCHIDv2', rfc: 'RFC 7343' },
    { cidr: '2001:db8::/32', scope: 'DOCUMENTATION', label: 'Documentation', rfc: 'RFC 3849' },
    { cidr: '2002::/16', scope: 'RESERVED', label: '6to4', rfc: 'RFC 3056' },
    { cidr: 'fc00::/7', scope: 'PRIVATE', label: 'Unique local address', rfc: 'RFC 4193' },
    { cidr: 'fe80::/10', scope: 'LINK_LOCAL', label: 'Link local unicast', rfc: 'RFC 4291 §2.5.6' },
    { cidr: 'ff00::/8', scope: 'MULTICAST', label: 'Multicast', rfc: 'RFC 4291 §2.7' }
];

// Only a globally routable unicast address is worth asking the world about.
const ROUTABLE = 'PUBLIC';

/**
 * Most specific range first, the way a routing table resolves an address.
 *
 * Order in the list above is written for a reader, and a reader groups by
 * subject. A lookup that takes the first match then answers from whichever
 * range happened to be written first: 255.255.255.255 came back RESERVED,
 * because 240.0.0.0/4 contains it and was listed earlier, and the broadcast
 * address stopped being distinguishable from reserved space.
 */
const byPrefixLength = ranges =>
    ranges.slice().sort((a, b) => Number(b.cidr.split('/')[1]) - Number(a.cidr.split('/')[1]));

const IPV4_ORDERED = byPrefixLength(IPV4_SPECIAL);
const IPV6_ORDERED = byPrefixLength(IPV6_SPECIAL);

class IpClassifier {
    // ---------------------------------------------------------------- IPv4

    parseIpv4(value) {
        const parts = String(value).trim().split('.');
        if (parts.length !== 4) return null;

        let result = 0;
        for (const part of parts) {
            // Rejects '01', '1e2', '+1', ' 1' and anything else that a lenient
            // parser would accept and a router would not.
            if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
            const octet = Number(part);
            if (octet > 255) return null;
            result = (result * 256) + octet;
        }
        return result;
    }

    ipv4InCidr(address, cidr) {
        const [network, bits] = cidr.split('/');
        const base = this.parseIpv4(network);
        const prefix = Number(bits);
        if (base === null) return false;
        if (prefix === 0) return true;
        const mask = prefix === 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
        return ((address & mask) >>> 0) === ((base & mask) >>> 0);
    }

    // ---------------------------------------------------------------- IPv6

    /** Expands to eight 16-bit groups, resolving `::` and any IPv4 tail. */
    parseIpv6(value) {
        let text = String(value).trim().toLowerCase();
        if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
        // A zone index identifies an interface, not a different address.
        text = text.split('%')[0];
        if (!text.includes(':')) return null;
        // `:::` is not a valid elision, and a count of `::` does not catch it:
        // in ':::' the pattern matches once and the leftover single colon is
        // then absorbed by the empty-group filter below, so '2001:db8:::1'
        // would quietly parse as '2001:db8::1'.
        if (text.includes(':::')) return null;
        if ((text.match(/::/g) || []).length > 1) return null;

        // A trailing dotted quad, as in ::ffff:192.0.2.1
        const dotted = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
        if (dotted) {
            const v4 = this.parseIpv4(dotted[1]);
            if (v4 === null) return null;
            const high = ((v4 >>> 16) & 0xFFFF).toString(16);
            const low = (v4 & 0xFFFF).toString(16);
            text = text.slice(0, dotted.index) + high + ':' + low;
        }

        const [head, tail] = text.split('::');
        const headGroups = head ? head.split(':').filter(g => g !== '') : [];
        const tailGroups = tail !== undefined && tail ? tail.split(':').filter(g => g !== '') : [];

        let groups;
        if (text.includes('::')) {
            const missing = 8 - headGroups.length - tailGroups.length;
            if (missing < 0) return null;
            groups = [...headGroups, ...Array(missing).fill('0'), ...tailGroups];
        } else {
            groups = headGroups;
        }

        if (groups.length !== 8) return null;
        const numeric = [];
        for (const group of groups) {
            if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
            numeric.push(parseInt(group, 16));
        }
        return numeric;
    }

    ipv6InCidr(groups, cidr) {
        const [network, bits] = cidr.split('/');
        const base = this.parseIpv6(network);
        const prefix = Number(bits);
        if (!base) return false;

        let remaining = prefix;
        for (let i = 0; i < 8 && remaining > 0; i++) {
            const take = Math.min(16, remaining);
            const mask = take === 16 ? 0xFFFF : ((0xFFFF << (16 - take)) & 0xFFFF);
            if ((groups[i] & mask) !== (base[i] & mask)) return false;
            remaining -= take;
        }
        return true;
    }

    // ------------------------------------------------------------- classify

    /**
     * What this address is, and whether it is worth looking up.
     *
     * `routable` is the field the rest of the pipeline should read. It is the
     * difference between "ask the world about this" and "there is nothing to
     * ask", and stating it here means no adapter has to infer it from a failed
     * request.
     */
    classify(value) {
        if (value === null || value === undefined || String(value).trim() === '') {
            return {
                ip: null,
                version: null,
                scope: 'INVALID',
                label: 'No address supplied',
                rfc: null,
                routable: false,
                reason: 'No address was supplied.'
            };
        }

        const ip = String(value).trim();

        const v4 = this.parseIpv4(ip);
        if (v4 !== null) {
            const special = IPV4_ORDERED.find(range => this.ipv4InCidr(v4, range.cidr));
            if (special) {
                return {
                    ip,
                    version: 4,
                    scope: special.scope,
                    label: special.label,
                    rfc: special.rfc,
                    cidr: special.cidr,
                    routable: false,
                    reason: `${ip} is in ${special.cidr} (${special.label}, ${special.rfc}), which is not reachable across the public internet.`
                };
            }
            return {
                ip,
                version: 4,
                scope: ROUTABLE,
                label: 'Globally routable unicast',
                rfc: null,
                routable: true,
                reason: `${ip} is a public IPv4 address.`
            };
        }

        const v6 = this.parseIpv6(ip);
        if (v6) {
            // An IPv4-mapped address carries an IPv4 address inside it, and
            // what matters is what that inner address is - reporting the
            // wrapper would hide a private address behind an IPv6 shape.
            if (this.ipv6InCidr(v6, '::ffff:0:0/96')) {
                const embedded = `${(v6[6] >> 8) & 0xFF}.${v6[6] & 0xFF}.${(v6[7] >> 8) & 0xFF}.${v6[7] & 0xFF}`;
                const inner = this.classify(embedded);
                return {
                    ...inner,
                    ip,
                    version: 6,
                    mapped_ipv4: embedded,
                    reason: `${ip} is an IPv4-mapped address (RFC 4291 §2.5.5.2) carrying ${embedded}. ${inner.reason}`
                };
            }

            const special = IPV6_ORDERED.find(range => this.ipv6InCidr(v6, range.cidr));
            if (special) {
                return {
                    ip,
                    version: 6,
                    scope: special.scope,
                    label: special.label,
                    rfc: special.rfc,
                    cidr: special.cidr,
                    routable: false,
                    reason: `${ip} is in ${special.cidr} (${special.label}, ${special.rfc}), which is not reachable across the public internet.`
                };
            }
            return {
                ip,
                version: 6,
                scope: ROUTABLE,
                label: 'Globally routable unicast',
                rfc: null,
                routable: true,
                reason: `${ip} is a public IPv6 address.`
            };
        }

        return {
            ip,
            version: null,
            scope: 'INVALID',
            label: 'Not an IP address',
            rfc: null,
            routable: false,
            reason: `"${ip.slice(0, 60)}" is not a valid IPv4 or IPv6 address.`
        };
    }

    /** Convenience for the common question. */
    isRoutable(value) {
        return this.classify(value).routable;
    }
}

module.exports = new IpClassifier();
module.exports.IpClassifier = IpClassifier;
