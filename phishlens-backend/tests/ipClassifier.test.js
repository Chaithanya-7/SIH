const test = require('node:test');
const assert = require('node:assert');

const classifier = require('../modules/ipClassifier');

/**
 * Stage one of the IP pipeline: what kind of address is this.
 *
 * Every later stage reads `routable` to decide whether asking the world about
 * an address is meaningful. Getting this wrong is quiet and costly in both
 * directions: calling a public address private loses the whole investigation,
 * and calling a private one public produces a geolocation for somebody's
 * living-room router.
 */

const scopeOf = value => classifier.classify(value).scope;

test('public IPv4 addresses are routable', () => {
    ['8.8.8.8', '1.1.1.1', '45.33.32.156', '185.220.101.44', '203.0.114.1'].forEach(ip => {
        const result = classifier.classify(ip);
        assert.strictEqual(result.scope, 'PUBLIC', `${ip} should be public`);
        assert.strictEqual(result.routable, true);
        assert.strictEqual(result.version, 4);
    });
});

test('RFC 1918 private ranges are recognised at their real boundaries', () => {
    // Inside
    ['10.0.0.0', '10.255.255.255', '172.16.0.0', '172.31.255.255', '192.168.0.0', '192.168.255.255']
        .forEach(ip => assert.strictEqual(scopeOf(ip), 'PRIVATE', `${ip} should be private`));

    // Just outside. 172.15 and 172.32 are public, which a naive "172.16-172.31"
    // string check gets wrong, and a /12 mask gets right.
    ['9.255.255.255', '11.0.0.0', '172.15.255.255', '172.32.0.0', '192.167.255.255', '192.169.0.0']
        .forEach(ip => assert.strictEqual(scopeOf(ip), 'PUBLIC', `${ip} should be public`));
});

test('loopback, link-local and carrier-grade NAT are distinguished from each other', () => {
    assert.strictEqual(scopeOf('127.0.0.1'), 'LOOPBACK');
    assert.strictEqual(scopeOf('127.255.255.254'), 'LOOPBACK');
    assert.strictEqual(scopeOf('169.254.1.1'), 'LINK_LOCAL');
    // Shared address space: not private, not public. A message apparently from
    // here came through a carrier's NAT, which is worth saying plainly.
    assert.strictEqual(scopeOf('100.64.0.1'), 'CARRIER_GRADE_NAT');
    assert.strictEqual(scopeOf('100.127.255.255'), 'CARRIER_GRADE_NAT');
    assert.strictEqual(scopeOf('100.63.255.255'), 'PUBLIC');
    assert.strictEqual(scopeOf('100.128.0.0'), 'PUBLIC');
});

test('documentation ranges are not treated as real infrastructure', () => {
    // These appear constantly in examples and copied configuration. Geolocating
    // them produces a confident answer about an address that describes nothing.
    ['192.0.2.1', '198.51.100.7', '203.0.113.9'].forEach(ip => {
        assert.strictEqual(scopeOf(ip), 'DOCUMENTATION', `${ip} is a documentation address`);
        assert.strictEqual(classifier.isRoutable(ip), false);
    });
});

test('multicast, broadcast, benchmarking and reserved space are all refused', () => {
    assert.strictEqual(scopeOf('224.0.0.1'), 'MULTICAST');
    assert.strictEqual(scopeOf('239.255.255.255'), 'MULTICAST');
    assert.strictEqual(scopeOf('255.255.255.255'), 'BROADCAST');
    assert.strictEqual(scopeOf('198.18.0.1'), 'BENCHMARKING');
    assert.strictEqual(scopeOf('240.0.0.1'), 'RESERVED');
    assert.strictEqual(scopeOf('0.0.0.0'), 'RESERVED');
});

test('malformed addresses are refused rather than half-parsed', () => {
    [
        '256.1.1.1',        // octet out of range
        '1.2.3',            // too few
        '1.2.3.4.5',        // too many
        '01.2.3.4',         // leading zero: octal in some parsers, decimal in others
        '1.2.3.-4',
        '1.2.3.4a',
        ' ',
        'not-an-ip',
        '192.168.1.1/24'    // a network, not a host
    ].forEach(value => {
        assert.strictEqual(scopeOf(value), 'INVALID', `"${value}" must not parse as an address`);
    });

    assert.strictEqual(classifier.classify(null).scope, 'INVALID');
    assert.strictEqual(classifier.classify(undefined).scope, 'INVALID');
    assert.strictEqual(classifier.classify('').scope, 'INVALID');
});

test('IPv6 public addresses are routable', () => {
    ['2606:4700:4700::1111', '2a00:1450:4001:80e::200e'].forEach(ip => {
        const result = classifier.classify(ip);
        assert.strictEqual(result.scope, 'PUBLIC', `${ip} should be public`);
        assert.strictEqual(result.version, 6);
        assert.strictEqual(result.routable, true);
    });
});

test('IPv6 special ranges are recognised', () => {
    assert.strictEqual(scopeOf('::1'), 'LOOPBACK');
    assert.strictEqual(scopeOf('::'), 'RESERVED');
    assert.strictEqual(scopeOf('fe80::1'), 'LINK_LOCAL');
    assert.strictEqual(scopeOf('fc00::1'), 'PRIVATE');
    assert.strictEqual(scopeOf('fd12:3456::1'), 'PRIVATE');
    assert.strictEqual(scopeOf('2001:db8::1'), 'DOCUMENTATION');
    assert.strictEqual(scopeOf('ff02::1'), 'MULTICAST');
});

test('an IPv4-mapped IPv6 address is judged by the address inside it', () => {
    // ::ffff:192.168.1.1 is a private address wearing an IPv6 shape. Reporting
    // the wrapper as public would send a private address off for geolocation.
    const mapped = classifier.classify('::ffff:192.168.1.1');
    assert.strictEqual(mapped.scope, 'PRIVATE');
    assert.strictEqual(mapped.routable, false);
    assert.strictEqual(mapped.mapped_ipv4, '192.168.1.1');
    assert.match(mapped.reason, /IPv4-mapped/);

    const mappedPublic = classifier.classify('::ffff:8.8.8.8');
    assert.strictEqual(mappedPublic.scope, 'PUBLIC');
    assert.strictEqual(mappedPublic.routable, true);
    assert.strictEqual(mappedPublic.mapped_ipv4, '8.8.8.8');
});

test('IPv6 forms that mean the same address are read the same way', () => {
    ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1', '2001:DB8::1']
        .forEach(form => assert.strictEqual(scopeOf(form), 'DOCUMENTATION', `${form} is documentation space`));

    // A zone index names a local interface; it does not change the address.
    assert.strictEqual(scopeOf('fe80::1%eth0'), 'LINK_LOCAL');
    // A bracketed address, as it appears in a Received header.
    assert.strictEqual(scopeOf('[::1]'), 'LOOPBACK');
});

test('malformed IPv6 is refused', () => {
    ['2001::db8::1', 'gggg::1', '2001:db8:::1', '12345::1'].forEach(value => {
        assert.strictEqual(scopeOf(value), 'INVALID', `"${value}" must not parse`);
    });
});

test('every non-routable answer explains itself, with the RFC that reserves it', () => {
    ['10.0.0.1', '127.0.0.1', '169.254.1.1', '192.0.2.1', '100.64.0.1', 'fe80::1'].forEach(ip => {
        const result = classifier.classify(ip);
        assert.strictEqual(result.routable, false);
        assert.ok(result.reason && result.reason.length > 20, `${ip} must say why it is not routable`);
        assert.ok(result.rfc, `${ip} must cite the RFC that reserves it`);
        assert.ok(result.cidr, `${ip} must name the range it falls in`);
    });
});
