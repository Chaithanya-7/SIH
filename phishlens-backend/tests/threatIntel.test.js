const test = require('node:test');
const assert = require('node:assert');

const threatIntelStore = require('../modules/threatIntelStore');
const rdapAdapter = require('../adapters/rdapAdapter');
const ruleEngine = require('../modules/ruleEngine');
const emailParser = require('../modules/emailParser');
const mqlBridge = require('../modules/mqlBridge');
const nlpAnalyzer = require('../modules/nlpAnalyzer');

/**
 * These tests drive the store through its public lookup surface with a
 * controlled in-memory indicator set. They never download feeds, so they run
 * offline and deterministically.
 */
function seedStore() {
    threatIntelStore.urls = new Set(['http://bad.example/login.php']);
    threatIntelStore.urlHosts = new Map([['bad.example', 'urlhaus'], ['phish.example', 'openphish']]);
    threatIntelStore.domains = new Map([['evil.example', 'threatfox']]);
    threatIntelStore.ips = new Map([['203.0.113.10', 'feodo']]);
    threatIntelStore.cidrs = [{ cidr: '198.51.100.0/24', feed: 'spamhaus_drop' }];
    threatIntelStore.lastSync = new Date().toISOString();
}

function clearStore() {
    threatIntelStore.urls = new Set();
    threatIntelStore.urlHosts = new Map();
    threatIntelStore.domains = new Map();
    threatIntelStore.ips = new Map();
    threatIntelStore.cidrs = [];
    threatIntelStore.lastSync = null;
}

test('an unsynced store contributes nothing rather than guessing', () => {
    clearStore();
    assert.strictEqual(threatIntelStore.isSynced(), false);
    assert.strictEqual(threatIntelStore.lookupUrl('http://bad.example/login.php'), null);
    assert.strictEqual(threatIntelStore.lookupIp('203.0.113.10'), null);
    assert.match(threatIntelStore.getStatus().limitation, /No indicator feed has been synchronised/);
});

test('exact URL, host, domain, IP and netblock indicators all match', () => {
    seedStore();

    assert.strictEqual(threatIntelStore.lookupUrl('http://bad.example/login.php').matched, 'EXACT_URL');
    assert.strictEqual(threatIntelStore.lookupUrl('http://bad.example/a/different/path').matched, 'URL_HOST');
    assert.strictEqual(threatIntelStore.lookupDomain('evil.example').matched, 'DOMAIN');
    assert.strictEqual(threatIntelStore.lookupIp('203.0.113.10').matched, 'IP');

    const netblockHit = threatIntelStore.lookupIp('198.51.100.77');
    assert.strictEqual(netblockHit.matched, 'NETBLOCK');
    assert.strictEqual(netblockHit.indicator, '198.51.100.0/24');
});

test('addresses outside a listed netblock do not match it', () => {
    seedStore();
    assert.strictEqual(threatIntelStore.lookupIp('198.51.101.77'), null);
    assert.strictEqual(threatIntelStore.lookupIp('8.8.8.8'), null);
});

/**
 * Open URL feeds legitimately list malicious content hosted on multi-tenant
 * platforms. Treating the platform host as malicious would flag every message
 * linking to Google Drive or GitHub, which would make the signal unusable.
 */
test('multi-tenant platforms are never condemned by a host-level match', () => {
    seedStore();
    threatIntelStore.urlHosts.set('github.com', 'urlhaus');
    threatIntelStore.urlHosts.set('drive.google.com', 'urlhaus');
    threatIntelStore.domains.set('cdn.discordapp.com', 'threatfox');

    assert.strictEqual(threatIntelStore.lookupUrl('https://github.com/someone/repo'), null);
    assert.strictEqual(threatIntelStore.lookupUrl('https://drive.google.com/file/d/abc/view'), null);
    assert.strictEqual(threatIntelStore.lookupDomain('github.com'), null);
    assert.strictEqual(threatIntelStore.lookupDomain('cdn.discordapp.com'), null);

    // An attacker-controlled subdomain of a site builder is a distinct host and must still match.
    threatIntelStore.urlHosts.set('secure-login.webflow.io', 'openphish');
    assert.strictEqual(threatIntelStore.lookupUrl('https://secure-login.webflow.io/').matched, 'URL_HOST');
});

test('an exact malicious URL on a multi-tenant platform still matches', () => {
    seedStore();
    const hostedUrl = 'https://drive.google.com/file/d/malicious-payload/view';
    threatIntelStore.urls.add(hostedUrl);
    assert.strictEqual(threatIntelStore.lookupUrl(hostedUrl).matched, 'EXACT_URL');
});

test('RDAP reduces hostnames to the registrable domain', () => {
    assert.strictEqual(rdapAdapter.registrableDomain('mail.example.com'), 'example.com');
    assert.strictEqual(rdapAdapter.registrableDomain('a.b.c.example.co.uk'), 'example.co.uk');
    assert.strictEqual(rdapAdapter.registrableDomain('example.com'), 'example.com');
    assert.strictEqual(rdapAdapter.registrableDomain('203.0.113.10'), null);
});

async function buildCase(raw) {
    const parsedEmail = await emailParser.parse(raw);
    let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
    threatObject.forensics.authentication = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } };
    threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'message');
    return { threatObject, parsedEmail };
}

const SAMPLE = [
    'From: "Billing" <billing@supplier.example>',
    'To: employee@company.example',
    'Subject: Invoice',
    'Message-ID: <ti1@supplier.example>',
    'Content-Type: text/plain',
    '',
    'Invoice details are available online.'
].join('\r\n');

test('enrichment-stage rules fire on indicator matches and add to earlier findings', async () => {
    const { threatObject, parsedEmail } = await buildCase(SAMPLE);
    const messageStageCount = threatObject.detection.matched_rules.length;

    threatObject.threat_intelligence = {
        matches: [
            { indicator_type: 'URL', indicator: 'http://bad.example/login.php', matched: 'EXACT_URL', feed: 'urlhaus' },
            { indicator_type: 'IP', indicator: '203.0.113.10', matched: 'IP', feed: 'feodo' }
        ],
        domain_ages: [{ domain: 'supplier.example', is_sender_domain: true, status: 'AVAILABLE', age_days: 3, registered_at: '2026-09-16T00:00:00Z' }]
    };

    const enriched = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
    const ids = enriched.detection.matched_rules.map(r => r.id);

    assert.ok(ids.includes('MQL-INTEL-101'), 'exact malicious URL should match');
    assert.ok(ids.includes('MQL-INTEL-103'), 'known malicious IP should match');
    assert.ok(ids.includes('MQL-INTEL-104'), 'newly registered sender domain should match');
    assert.ok(enriched.detection.matched_rules.length >= messageStageCount,
        'enrichment findings must add to the message-stage findings, not replace them');

    for (const rule of enriched.detection.matched_rules.filter(r => r.category === 'INTEL')) {
        assert.ok(rule.source && rule.source.length > 5, `${rule.id} must cite its source`);
        assert.ok(rule.matched_because && rule.matched_because.length > 5, `${rule.id} must say why it fired`);
    }
});

test('an established sender domain does not trigger the newly-registered rule', async () => {
    const { threatObject, parsedEmail } = await buildCase(SAMPLE);
    threatObject.threat_intelligence = {
        matches: [],
        domain_ages: [{ domain: 'supplier.example', is_sender_domain: true, status: 'AVAILABLE', age_days: 4200, registered_at: '2015-01-01T00:00:00Z' }]
    };

    const enriched = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
    const ids = enriched.detection.matched_rules.map(r => r.id);

    assert.ok(!ids.includes('MQL-INTEL-104'));
    assert.ok(!ids.includes('MQL-INTEL-101'));
});

test('a link on a live malicious-URL feed reaches HIGH_RISK on its own', async () => {
    const evidenceFusion = require('../modules/evidenceFusion');
    const confidenceEngine = require('../modules/confidenceEngine');

    const { threatObject, parsedEmail } = await buildCase(SAMPLE);
    threatObject.threat_intelligence = {
        matches: [{ indicator_type: 'URL', indicator: 'http://bad.example/login.php', matched: 'EXACT_URL', feed: 'urlhaus' }],
        domain_ages: []
    };

    let result = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
    result = evidenceFusion.fuse(result);
    result = confidenceEngine.calculate(result);

    assert.strictEqual(result.detection.verdict, 'HIGH_RISK',
        'a message linking to a currently-listed malicious URL must not be downgraded to merely suspicious');

    const floor = result.confidence.contributions.find(c => c.family === 'DECISIVE_FINDING');
    assert.ok(floor, 'the decisive finding must be visible in the contributions, not applied silently');
    assert.ok(floor.representative_finding.length > 0);
});

test('a weaker host-level intel match alone does not reach HIGH_RISK', async () => {
    const evidenceFusion = require('../modules/evidenceFusion');
    const confidenceEngine = require('../modules/confidenceEngine');

    const { threatObject, parsedEmail } = await buildCase(SAMPLE);
    threatObject.threat_intelligence = {
        matches: [{ indicator_type: 'URL', indicator: 'bad.example', matched: 'URL_HOST', feed: 'urlhaus' }],
        domain_ages: []
    };

    let result = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
    result = evidenceFusion.fuse(result);
    result = confidenceEngine.calculate(result);

    assert.notStrictEqual(result.detection.verdict, 'HIGH_RISK',
        'only a confirmatory exact match is decisive; a host-level match is corroborating');
    assert.ok(!result.confidence.contributions.some(c => c.family === 'DECISIVE_FINDING'));
});

test('no feed data means no intel findings rather than fabricated ones', async () => {
    const { threatObject, parsedEmail } = await buildCase(SAMPLE);
    threatObject.threat_intelligence = { matches: [], domain_ages: [] };

    const enriched = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
    assert.strictEqual(enriched.detection.matched_rules.filter(r => r.category === 'INTEL').length, 0);
});

test.after(() => clearStore());
