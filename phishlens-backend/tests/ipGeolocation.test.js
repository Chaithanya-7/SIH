const test = require('node:test');
const assert = require('node:assert');

const hostnameGeo = require('../modules/hostnameGeo');
const { distanceKm } = require('../modules/hostnameGeo');
const { IpGeolocationEngine, SOURCE_WEIGHTS } = require('../modules/ipGeolocationEngine');

/**
 * Locating an address from several sources, with an honest radius.
 *
 * ## What is actually being guarded
 *
 * A single geolocation provider answers every question with a city and a pair
 * of coordinates, always, with no indication of how it knows. Much of that is
 * inference from registry records - the block is registered to a company in
 * Bengaluru, so every address in it is reported as Bengaluru. It is often right
 * and it is never uncertain, and a map marker drawn from it looks exactly as
 * confident when it is a guess.
 *
 * So most of these tests are about refusing to overstate: not averaging
 * disagreement into a place nobody claimed, not giving an anycast address a
 * coordinate, not treating two databases as two opinions, and never drawing a
 * radius tighter than the evidence holding it up.
 */

// The engine is exercised through a fake network layer. The live sources were
// checked by hand while building it; what needs testing repeatedly is the
// reasoning, and that must not depend on a third party being reachable.
function engineWith({ ipmap = { status: 'UNAVAILABLE' }, ripestat = { status: 'UNAVAILABLE' }, whois = { status: 'UNAVAILABLE' }, ptr = null, facilities = { status: 'UNAVAILABLE' } } = {}) {
    const engine = new IpGeolocationEngine();
    return {
        engine,
        context: { ipmap, ripestat, whois, facilities, originAsn: 'AS64500', hostname: ptr, classification: { routable: true }, claims: [], notes: [] }
    };
}

/** Builds the claim list the way locate() does, so fuse() can be tested directly. */
function claimsFrom(list) {
    return list.map(c => ({
        source: c.source,
        kind: c.kind,
        lat: c.lat,
        lon: c.lon,
        city: c.city || null,
        country_code: c.country || null,
        own_radius_km: c.radius || 50,
        detail: c.detail || ''
    }));
}

// ---------------------------------------------------------------------------
// The hostname reader
// ---------------------------------------------------------------------------

test('a location code in a router name is read, in either spelling', () => {
    assert.strictEqual(hostnameGeo.locate('ae-1.r00.londen12.uk.bb.gin.ntt.net').city, 'London');
    assert.strictEqual(hostnameGeo.locate('xe-0-0-0.sin-b1.example.net').city, 'Singapore');
    // Several large operators spell the city out, and the three-letter table
    // misses those entirely: stripping the site number leaves "frankfurt".
    assert.strictEqual(hostnameGeo.locate('ae7.edge4.Frankfurt1.Level3.net').city, 'Frankfurt');
    assert.strictEqual(hostnameGeo.locate('po1.ashburn-dc2.example.net').city, 'Ashburn');
});

test('a code that is also an ordinary word does not place anything', () => {
    // `sin` is Singapore and sits inside "using"; `ord` is Chicago and sits
    // inside "order". Matching bare substrings would put a great deal of the
    // internet in Illinois.
    for (const name of ['single-user-machine.using.example.com', 'order-processing.internal.example.com', 'dns.google', 'b.resolvers.level3.net']) {
        assert.strictEqual(hostnameGeo.locate(name).status, 'UNAVAILABLE', `${name} must not be located`);
    }
});

test('a name with two places is marked ambiguous and widened', () => {
    // `lon-fra` is a trunk between two sites. Which end this interface is on
    // cannot be told from the name.
    const found = hostnameGeo.locate('be-3.lon-fra.trunk.example.net');
    assert.strictEqual(found.ambiguous, true);
    assert.ok(found.radius_km > 200, 'the radius must cover both ends, not just the first');
});

test('a hostname never claims better than city accuracy', () => {
    const found = hostnameGeo.locate('xe-0-0-0.sin-b1.example.net');
    assert.ok(found.radius_km >= 50, 'a city code means the site, not a street');
    assert.match(found.limitation, /stale|wrong/i, 'and it must say a name can be out of date');
});

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

test('an anycast address is not given a coordinate', async () => {
    // Measured while building this: 8.8.8.8 comes back Singapore from IPmap and
    // the United States from MaxMind, and both are correct. A prefix announced
    // from many places is genuinely in all of them, and one dot is a fiction.
    const { engine, context } = engineWith({
        ipmap: { status: 'AVAILABLE', anycast: true, latitude: 1.29, longitude: 103.85, city: 'Singapore', country_code: 'SG', engines_contributed: [{ engine: 'latency' }] }
    });
    context.claims = claimsFrom([{ source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 1.29, lon: 103.85, city: 'Singapore' }]);

    const result = engine.fuse('8.8.8.8', context);

    assert.strictEqual(result.status, 'ANYCAST');
    assert.strictEqual(result.latitude, null);
    assert.strictEqual(result.radius_km, null);
    assert.strictEqual(result.confidence, 0);
    assert.match(result.limitation, /fiction|no single coordinate/i);
});

test('an address no source knows is reported as not located, never centred on a country', () => {
    const { engine, context } = engineWith();
    const result = engine.fuse('203.0.113.7', context);

    assert.strictEqual(result.status, 'NOT_LOCATED');
    assert.strictEqual(result.latitude, null);
    // The failure this prevents: a coordinate with nothing behind it renders
    // identically to one with five agreeing sources.
    assert.match(result.limitation, /not the same as one in the middle of a country/i);
});

test('a reserved address is refused before anything is asked about it', async () => {
    const engine = new IpGeolocationEngine();
    const result = await engine.locate('192.168.1.1');
    assert.strictEqual(result.status, 'NOT_LOCATED');
    assert.match(result.reason, /not a routable public address/i);
});

// ---------------------------------------------------------------------------
// Fusion: the rules that keep the answer honest
// ---------------------------------------------------------------------------

test('two commercial databases agreeing count as one lineage, not two opinions', () => {
    // Geolocation databases draw on overlapping registry data, so two of them
    // agreeing is close to one source speaking twice. Counting them as two
    // independent confirmations is how a guess becomes a confident answer.
    const { engine, context } = engineWith();
    context.claims = claimsFrom([
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 12.97, lon: 77.59, city: 'Bengaluru', country: 'IN' },
        { source: 'ipwho.is', kind: 'IPWHOIS', lat: 12.98, lon: 77.60, city: 'Bengaluru', country: 'IN' }
    ]);

    const result = engine.fuse('139.59.1.1', context);

    assert.strictEqual(result.status, 'LOCATED');
    assert.deepStrictEqual([...result.independent_lineages], ['commercial-database']);
    assert.ok(result.confidence <= 0.5,
        `two same-lineage sources must not produce high confidence, got ${result.confidence}`);
});

test('a measurement agreeing with a database outweighs two databases', () => {
    const { engine, context } = engineWith();

    context.claims = claimsFrom([
        { source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 51.51, lon: -0.13, city: 'London', country: 'GB' },
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 51.50, lon: -0.12, city: 'London', country: 'GB' }
    ]);
    const measured = engine.fuse('1.1.1.1', context);

    const { engine: e2, context: c2 } = engineWith();
    c2.claims = claimsFrom([
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 51.51, lon: -0.13, city: 'London', country: 'GB' },
        { source: 'ipwho.is', kind: 'IPWHOIS', lat: 51.50, lon: -0.12, city: 'London', country: 'GB' }
    ]);
    const databases = e2.fuse('1.1.1.1', c2);

    assert.ok(measured.confidence > databases.confidence,
        'a measurement plus a database must beat two databases sharing a lineage');
    assert.strictEqual(measured.independent_lineages.length, 2);
});

test('disagreement is not averaged into a place nobody claimed', () => {
    // The mean of Singapore and Virginia is the middle of the Pacific, which no
    // source claims and which a map would draw as confidently as anything else.
    const { engine, context } = engineWith();
    context.claims = claimsFrom([
        { source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 1.29, lon: 103.85, city: 'Singapore', country: 'SG' },
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 39.04, lon: -77.49, city: 'Ashburn', country: 'US' }
    ]);

    const result = engine.fuse('203.0.113.9', context);

    // The answer is one of the claims, not a midpoint between them.
    assert.ok(
        Math.abs(result.latitude - 1.29) < 0.5 || Math.abs(result.latitude - 39.04) < 0.5,
        `the answer must be a claimed place, got ${result.latitude},${result.longitude}`
    );
    assert.ok(result.disagreement_km > 10000, 'the distance between them must be reported');
    assert.ok(result.disagreeing_sources.length >= 1, 'and the rejected source named');
    assert.ok(result.radius_km > 1000, 'with a radius wide enough to admit the disagreement');
});

test('the radius is never tighter than the coarsest source holding the answer up', () => {
    const { engine, context } = engineWith();
    context.claims = claimsFrom([
        // A country-level record, which cannot support a city-sized radius
        // however precise the coordinate looks.
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 20.59, lon: 78.96, country: 'IN', radius: 600 },
        { source: 'ipwho.is', kind: 'IPWHOIS', lat: 20.60, lon: 78.97, country: 'IN', radius: 600 }
    ]);

    const result = engine.fuse('203.0.113.11', context);
    assert.ok(result.radius_km >= 600, `got ${result.radius_km} km from two 600 km sources`);
    assert.notStrictEqual(result.precision, 'CITY', 'a 600 km answer is not city precision');
});

test('a network footprint that contradicts the answer lowers confidence', () => {
    // PeeringDB says where the originating network actually has equipment. A
    // network present only in Germany, with an answer placing it in India,
    // means one of the two is wrong - and the confidence should say so.
    const agreeing = engineWith({
        facilities: { status: 'AVAILABLE', constrains: true, cities: ['Frankfurt'], countries: ['DE'] }
    });
    agreeing.context.claims = claimsFrom([
        { source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 50.11, lon: 8.68, city: 'Frankfurt', country: 'DE' },
        { source: 'ipwho.is', kind: 'IPWHOIS', lat: 50.12, lon: 8.69, city: 'Frankfurt', country: 'DE' }
    ]);
    const consistent = agreeing.engine.fuse('203.0.113.12', agreeing.context);

    const clashing = engineWith({
        facilities: { status: 'AVAILABLE', constrains: true, cities: ['Frankfurt'], countries: ['DE'] }
    });
    clashing.context.claims = claimsFrom([
        { source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 12.97, lon: 77.59, city: 'Bengaluru', country: 'IN' },
        { source: 'ipwho.is', kind: 'IPWHOIS', lat: 12.98, lon: 77.60, city: 'Bengaluru', country: 'IN' }
    ]);
    const contradicted = clashing.engine.fuse('203.0.113.12', clashing.context);

    assert.strictEqual(consistent.constraints[0].contradicts, false);
    assert.strictEqual(contradicted.constraints[0].contradicts, true);
    assert.ok(contradicted.confidence < consistent.confidence,
        'a contradicted answer must be less confident than a corroborated one');
    assert.match(contradicted.constraints[0].detail, /One of the two is wrong/i);
});

test('a global carrier constrains nothing, and says so', () => {
    const { engine, context } = engineWith({
        facilities: { status: 'AVAILABLE', constrains: false, cities: new Array(15).fill('x'), countries: ['US', 'DE', 'SG'] }
    });
    context.claims = claimsFrom([{ source: 'ipwho.is', kind: 'IPWHOIS', lat: 12.97, lon: 77.59, city: 'Bengaluru', country: 'IN' }]);

    const result = engine.fuse('139.59.1.1', context);
    assert.strictEqual(result.constraints[0].contradicts, false,
        'a network present in fifteen cities excludes nothing, so it must not contradict');
    assert.match(result.constraints[0].detail, /too many to narrow/i);
});

test('confidence never reaches certainty', () => {
    // Every input is somebody else's claim about somebody else's network, and
    // none of it was verified from this machine.
    const { engine, context } = engineWith();
    context.claims = claimsFrom([
        { source: 'RIPE IPmap', kind: 'IPMAP_MEASURED', lat: 51.51, lon: -0.13, city: 'London', country: 'GB', radius: 40 },
        { source: 'MaxMind GeoLite (via RIPEstat)', kind: 'MAXMIND', lat: 51.50, lon: -0.12, city: 'London', country: 'GB' },
        { source: 'Router hostname', kind: 'HOSTNAME', lat: 51.51, lon: -0.13, city: 'London', country: 'GB' }
    ]);

    const result = engine.fuse('203.0.113.13', context);
    assert.ok(result.confidence <= 0.9, `confidence must stay below certainty, got ${result.confidence}`);
    assert.ok(result.confidence > 0.5, 'but three lineages agreeing should still be reasonably strong');
    assert.match(result.limitation, /locates infrastructure, not a person/i);
});

// ---------------------------------------------------------------------------
// What was deliberately left out
// ---------------------------------------------------------------------------

test('the techniques not implemented are named, with the reason', () => {
    const engine = new IpGeolocationEngine();
    const omitted = engine.state().not_implemented;

    // Each of these is a real technique that would improve accuracy, and each
    // was declined for a reason worth being able to point at later.
    const reasons = Object.values(omitted).join(' ');
    assert.match(reasons, /Atlas credits/i, 'active measurement costs credits earned by hosting a probe');
    assert.match(reasons, /machine being protected/i, 'a traceroute from here would announce the victim');
    assert.match(reasons, /registration/i, 'CAIDA datasets need an acceptable-use agreement');
    assert.match(reasons, /native library/i, 'BGPStream needs compiling per platform');

    assert.ok(Object.keys(omitted).length >= 4);
});

test('the weighting puts measurement above inference', () => {
    assert.ok(SOURCE_WEIGHTS.IPMAP_MEASURED > SOURCE_WEIGHTS.MAXMIND);
    assert.ok(SOURCE_WEIGHTS.IPMAP_MEASURED > SOURCE_WEIGHTS.IPMAP_INFERRED,
        'the same service inferring rather than measuring must count for less');
    assert.ok(SOURCE_WEIGHTS.HOSTNAME < SOURCE_WEIGHTS.MAXMIND,
        'a name an operator chose is weaker than a database record');
});

test('distances are computed, not guessed', () => {
    // London to Frankfurt is about 640 km; Singapore to Ashburn about 15,500.
    const londonFrankfurt = distanceKm({ lat: 51.5074, lon: -0.1278 }, { lat: 50.1109, lon: 8.6821 });
    assert.ok(londonFrankfurt > 590 && londonFrankfurt < 690, `got ${Math.round(londonFrankfurt)} km`);

    const far = distanceKm({ lat: 1.29, lon: 103.85 }, { lat: 39.04, lon: -77.49 });
    assert.ok(far > 15000 && far < 16500, `got ${Math.round(far)} km`);
});
