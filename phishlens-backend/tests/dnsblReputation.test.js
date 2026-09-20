const test = require('node:test');
const assert = require('node:assert');

/**
 * Blocklist reputation, and the difference between "clean" and "not asked".
 *
 * The failure this guards against is the one the reputation stage already had:
 * a lookup that cannot succeed reporting as though it had, so a message from an
 * address nobody checked looks exactly like a message from an address everybody
 * cleared.
 */

function fresh() {
    ['../modules/dnsblReputation', '../modules/ipClassifier'].forEach(m => delete require.cache[require.resolve(m)]);
    return require('../modules/dnsblReputation');
}

test('a private address is not sent to a blocklist at all', async () => {
    const dnsbl = fresh();
    // Made to fail loudly: nothing should reach DNS for an address that cannot
    // be on a public blocklist.
    dnsbl.queryOne = async () => { throw new Error('a private address must never be queried'); };

    const result = await dnsbl.check('192.168.1.10');
    assert.strictEqual(result.queried, false);
    assert.deepStrictEqual(result.lists, []);
    assert.strictEqual(result.classification.scope, 'PRIVATE');
    assert.match(result.reason, /RFC 1918/);
});

test('loopback and documentation addresses are likewise skipped', async () => {
    const dnsbl = fresh();
    dnsbl.queryOne = async () => { throw new Error('should not be queried'); };

    for (const ip of ['127.0.0.1', '192.0.2.1', '169.254.5.5']) {
        const result = await dnsbl.check(ip);
        assert.strictEqual(result.queried, false, `${ip} must not be queried`);
        assert.ok(result.reason.length > 20, `${ip} must explain why not`);
    }
});

test('IPv6 is reported as uncheckable rather than as clean', async () => {
    const dnsbl = fresh();
    const result = await dnsbl.check('2606:4700:4700::1111');

    assert.strictEqual(result.queried, false);
    assert.match(result.reason, /IPv4 zones only/);
    // The distinction that matters: this is an absence of evidence, and must
    // not read as evidence of absence.
    assert.deepStrictEqual(result.lists, []);
});

test('the address is reversed the way a blocklist expects', () => {
    const dnsbl = fresh();
    assert.strictEqual(dnsbl.reverseIpv4('1.2.3.4'), '4.3.2.1');
    assert.strictEqual(dnsbl.reverseIpv4('185.220.101.44'), '44.101.220.185');
});

test('a listing reports which list said what, not a verdict', async () => {
    const dnsbl = fresh();
    dnsbl.queryOne = async (list, ip) => {
        if (list.id !== 'spamhaus_zen') return { list: list.id, name: list.name, status: 'NOT_LISTED' };
        return {
            list: list.id,
            name: list.name,
            status: 'LISTED',
            findings: [{ code: '127.0.0.4', list: 'XBL', meaning: 'The host appears compromised.', weight: 'HIGH' }]
        };
    };

    const result = await dnsbl.check('185.220.101.44');
    assert.strictEqual(result.queried, true);
    assert.deepStrictEqual(result.summary.listed_on, ['Spamhaus ZEN']);
    assert.strictEqual(result.summary.strongest.list, 'XBL');
    assert.strictEqual(result.summary.strongest.weight, 'HIGH');
    assert.strictEqual(result.summary.complete, true);

    // No field anywhere says "malicious". The weighing belongs to the engine
    // that can see the rest of the message.
    assert.ok(!JSON.stringify(result).toLowerCase().includes('"malicious"'));
});

test('a refused query is not a clean result', async () => {
    const dnsbl = fresh();
    dnsbl.queryOne = async (list) => {
        if (list.id === 'spamhaus_zen') {
            return {
                list: list.id,
                name: list.name,
                status: 'QUERY_REFUSED',
                reason: 'The query came from a public DNS resolver, which this list refuses.',
                means_clean: false
            };
        }
        return { list: list.id, name: list.name, status: 'NOT_LISTED' };
    };

    const result = await dnsbl.check('8.8.8.8');

    // Spamhaus answers a refusal in 127.255.255.0/24 - a normal A record that a
    // careless client reads as a listing, and whose absence reads as clean.
    // Neither is true, and the summary has to say so.
    assert.strictEqual(result.summary.complete, false,
        'a sweep containing a refused lookup is not complete');
    assert.strictEqual(result.summary.inconclusive.length, 1);
    assert.match(result.summary.inconclusive[0].reason, /public DNS resolver/);
    assert.deepStrictEqual(result.summary.listed_on, [], 'a refusal is not a listing either');
});

test('an unreachable list is inconclusive, not absolution', async () => {
    const dnsbl = fresh();
    dnsbl.queryOne = async (list) => ({
        list: list.id, name: list.name, status: 'UNAVAILABLE',
        reason: `${list.name} could not be reached (ETIMEOUT).`, means_clean: false
    });

    const result = await dnsbl.check('45.33.32.156');
    assert.strictEqual(result.summary.complete, false);
    assert.strictEqual(result.summary.inconclusive.length, 3, 'every failed list is named');
    assert.deepStrictEqual(result.summary.listed_on, []);
});

test('the strongest finding across lists is the one surfaced', async () => {
    const dnsbl = fresh();
    dnsbl.queryOne = async (list) => {
        if (list.id === 'spamhaus_zen') {
            return {
                list: list.id, name: list.name, status: 'LISTED',
                findings: [{ code: '127.0.0.10', list: 'PBL', meaning: 'End-user space.', weight: 'MEDIUM' }]
            };
        }
        if (list.id === 'spamcop') {
            return {
                list: list.id, name: list.name, status: 'LISTED',
                findings: [{ code: '127.0.0.2', list: 'SCBL', meaning: 'Reported recently.', weight: 'MEDIUM' }]
            };
        }
        return {
            list: list.id, name: list.name, status: 'LISTED',
            findings: [{ code: '127.0.0.2', list: 'UCEPROTECT-1', meaning: 'Spam trap.', weight: 'LOW' }]
        };
    };

    const result = await dnsbl.check('45.33.32.156');
    assert.strictEqual(result.summary.listed_on.length, 3);
    // Ranked, so a weak listing never outranks a strong one just by ordering.
    assert.strictEqual(result.summary.strongest.weight, 'MEDIUM');
});

test('every configured list is a real zone with decodable response codes', () => {
    const { LISTS } = fresh();
    assert.ok(LISTS.length >= 3, 'more than one opinion is the point of using blocklists');

    LISTS.forEach(list => {
        assert.match(list.zone, /^[a-z0-9.-]+$/, `${list.id} needs a DNS zone`);
        assert.ok(Object.keys(list.codes).length > 0, `${list.id} must decode its own answers`);
        Object.entries(list.codes).forEach(([code, decoded]) => {
            assert.match(code, /^127\.0\.0\.\d+$/, `${list.id} code ${code} is not a loopback answer`);
            assert.ok(decoded.meaning.length > 20, `${list.id} ${code} must say what it means in words`);
            assert.ok(['HIGH', 'MEDIUM', 'LOW'].includes(decoded.weight), `${list.id} ${code} needs a weight`);
        });
    });

    // A PBL listing means the address is end-user space, not that it is
    // malicious, and must not be weighted as though it were.
    const zen = LISTS.find(l => l.id === 'spamhaus_zen');
    assert.strictEqual(zen.codes['127.0.0.10'].weight, 'MEDIUM');
    assert.strictEqual(zen.codes['127.0.0.4'].weight, 'HIGH');
});
