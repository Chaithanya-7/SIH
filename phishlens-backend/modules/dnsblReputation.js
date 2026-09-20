const dns = require('dns').promises;
const ipClassifier = require('./ipClassifier');

/**
 * IP reputation from public blocklists, over plain DNS, with no key and no account.
 *
 * The reputation stage was wired to AbuseIPDB, IPQS and VPNAPI, all of which
 * need an API key. On an install that has none - which is every install of a
 * tool that promises to cost nothing - all three answered UNAVAILABLE, so the
 * whole stage reported nothing on every message while looking like it was
 * working.
 *
 * DNSBLs need no key because the query *is* a DNS lookup: the address is
 * reversed, the zone appended, and a returned A record means listed. That makes
 * them the honest choice here.
 *
 * ## What a listing means, and what it does not
 *
 * These lists do not agree with each other and do not mean the same thing. A
 * Spamhaus PBL listing says an address is end-user space that should not be
 * delivering mail directly - which is meaningful for a sending relay and says
 * nothing about malice. An XBL listing says the host appears compromised. A
 * SpamCop listing reflects recent reports and expires by itself.
 *
 * So this records what each list said and when, and leaves the weighing to the
 * engine that can see the rest of the message. It never collapses the answer to
 * "this IP is malicious".
 *
 * ## The failure that matters
 *
 * Spamhaus refuses queries arriving from large public resolvers. A refusal is
 * returned as an answer in 127.255.255.0/24, which a naive client reads as a
 * listing, and an absent answer reads as "not listed". Both are wrong: the
 * truthful answer is that nothing was learned. Reporting a refused query as a
 * clean result is the exact failure this codebase keeps finding, so refusals
 * are surfaced as their own state.
 */

const LISTS = [
    {
        id: 'spamhaus_zen',
        name: 'Spamhaus ZEN',
        zone: 'zen.spamhaus.org',
        // https://www.spamhaus.org/faq/section/DNSBL%20Usage
        codes: {
            '127.0.0.2': { list: 'SBL', meaning: 'On the Spamhaus Block List: the address is a known spam source.', weight: 'HIGH' },
            '127.0.0.3': { list: 'SBL CSS', meaning: 'Detected by the Spamhaus snowshoe-spam detection system.', weight: 'HIGH' },
            '127.0.0.4': { list: 'XBL', meaning: 'The host appears compromised - an exploited machine or a proxy.', weight: 'HIGH' },
            '127.0.0.5': { list: 'XBL', meaning: 'The host appears compromised - an exploited machine or a proxy.', weight: 'HIGH' },
            '127.0.0.6': { list: 'XBL', meaning: 'The host appears compromised - an exploited machine or a proxy.', weight: 'HIGH' },
            '127.0.0.7': { list: 'XBL', meaning: 'The host appears compromised - an exploited machine or a proxy.', weight: 'HIGH' },
            '127.0.0.9': { list: 'SBL DROP', meaning: 'In a range Spamhaus advises dropping outright.', weight: 'HIGH' },
            '127.0.0.10': { list: 'PBL', meaning: 'End-user address space that should not deliver mail directly. Not evidence of malice, but unusual for a sending relay.', weight: 'MEDIUM' },
            '127.0.0.11': { list: 'PBL', meaning: 'End-user address space that should not deliver mail directly. Not evidence of malice, but unusual for a sending relay.', weight: 'MEDIUM' }
        }
    },
    {
        id: 'spamcop',
        name: 'SpamCop',
        zone: 'bl.spamcop.net',
        codes: {
            '127.0.0.2': { list: 'SCBL', meaning: 'Reported to SpamCop as a source of unsolicited mail recently.', weight: 'MEDIUM' }
        }
    },
    {
        id: 'uceprotect',
        name: 'UCEPROTECT level 1',
        zone: 'dnsbl-1.uceprotect.net',
        codes: {
            '127.0.0.2': { list: 'UCEPROTECT-1', meaning: 'The individual address was seen sending to spam traps.', weight: 'LOW' }
        }
    }
];

// A refusal arrives as a normal answer inside this range rather than as an
// error, which is what makes it dangerous to read carelessly.
const REFUSAL_PREFIX = '127.255.255.';

const REFUSAL_REASONS = {
    '127.255.255.252': 'The query was malformed.',
    '127.255.255.254': 'The query came from a public DNS resolver, which this list refuses. Point the system at a local or ISP resolver to get an answer.',
    '127.255.255.255': 'The query was refused for exceeding this list\'s free-use volume.'
};

class DnsblReputation {
    constructor() {
        // Measured rather than guessed: on a cold resolver an ordinary A record
        // took over three seconds here, so a 2.5s limit timed out every list
        // and reported three inconclusive lookups for an address that would
        // have answered. Slow is not the same as unreachable.
        this.timeoutMs = Number(process.env.DNSBL_TIMEOUT_MS || 6000);
        this.enabled = process.env.DNSBL_ENABLED !== 'false';
    }

    /** `1.2.3.4` becomes `4.3.2.1`, which is how a DNSBL is asked about it. */
    reverseIpv4(ip) {
        return ip.split('.').reverse().join('.');
    }

    async queryOne(list, ip) {
        const query = `${this.reverseIpv4(ip)}.${list.zone}`;
        const started = Date.now();

        try {
            const answers = await Promise.race([
                dns.resolve4(query),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timed out')), this.timeoutMs))
            ]);

            const refusal = answers.find(a => a.startsWith(REFUSAL_PREFIX));
            if (refusal) {
                return {
                    list: list.id,
                    name: list.name,
                    status: 'QUERY_REFUSED',
                    reason: REFUSAL_REASONS[refusal] || `The list refused the query (${refusal}).`,
                    // Said explicitly, because a refusal is not a clean result
                    // and must never be counted as one.
                    means_clean: false,
                    checked_at: new Date().toISOString(),
                    took_ms: Date.now() - started
                };
            }

            const findings = answers
                .map(answer => ({ answer, decoded: list.codes[answer] }))
                .filter(entry => entry.decoded)
                .map(entry => ({
                    code: entry.answer,
                    list: entry.decoded.list,
                    meaning: entry.decoded.meaning,
                    weight: entry.decoded.weight
                }));

            if (findings.length === 0) {
                // Listed, but under a code this list has not documented here.
                return {
                    list: list.id,
                    name: list.name,
                    status: 'LISTED_UNKNOWN_CODE',
                    codes: answers,
                    reason: `${list.name} returned ${answers.join(', ')}, which is not a response code PhishLens recognises.`,
                    checked_at: new Date().toISOString(),
                    took_ms: Date.now() - started
                };
            }

            return {
                list: list.id,
                name: list.name,
                status: 'LISTED',
                findings,
                checked_at: new Date().toISOString(),
                took_ms: Date.now() - started
            };
        } catch (error) {
            // NXDOMAIN is the ordinary "not on this list" answer, and the only
            // failure here that is genuinely good news.
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
                return {
                    list: list.id,
                    name: list.name,
                    status: 'NOT_LISTED',
                    checked_at: new Date().toISOString(),
                    took_ms: Date.now() - started
                };
            }
            return {
                list: list.id,
                name: list.name,
                status: 'UNAVAILABLE',
                reason: `${list.name} could not be reached (${error.code || error.message}).`,
                means_clean: false,
                checked_at: new Date().toISOString(),
                took_ms: Date.now() - started
            };
        }
    }

    /**
     * Asks every list about one address.
     *
     * Returns what each said rather than a verdict. The caller decides what a
     * PBL listing is worth next to an XBL one, because only the caller can see
     * whether this address was the sending relay or a hop along the way.
     */
    async check(ip) {
        const classification = ipClassifier.classify(ip);

        if (!classification.routable) {
            return {
                ip,
                queried: false,
                classification,
                // The distinction the classifier exists to preserve: there was
                // nothing to ask, which is not the same as having asked and
                // found nothing.
                reason: `No blocklist was queried. ${classification.reason}`,
                lists: []
            };
        }

        if (classification.version === 6) {
            return {
                ip,
                queried: false,
                classification,
                reason: 'These blocklists publish IPv4 zones only, so an IPv6 sender cannot be checked against them.',
                lists: []
            };
        }

        if (!this.enabled) {
            return { ip, queried: false, classification, reason: 'Blocklist checks are switched off.', lists: [] };
        }

        const lists = await Promise.all(LISTS.map(list => this.queryOne(list, classification.ip)));

        const listed = lists.filter(r => r.status === 'LISTED');
        const refused = lists.filter(r => r.status === 'QUERY_REFUSED' || r.status === 'UNAVAILABLE');

        return {
            ip: classification.ip,
            queried: true,
            classification,
            lists,
            summary: {
                listed_on: listed.map(r => r.name),
                strongest: listed
                    .flatMap(r => r.findings || [])
                    .sort((a, b) => ({ HIGH: 3, MEDIUM: 2, LOW: 1 }[b.weight] || 0) - ({ HIGH: 3, MEDIUM: 2, LOW: 1 }[a.weight] || 0))[0] || null,
                // Surfaced so a result assembled from half-working lookups is
                // never mistaken for a clean sweep.
                inconclusive: refused.map(r => ({ name: r.name, reason: r.reason })),
                complete: refused.length === 0
            }
        };
    }
}

module.exports = new DnsblReputation();
module.exports.DnsblReputation = DnsblReputation;
module.exports.LISTS = LISTS;
