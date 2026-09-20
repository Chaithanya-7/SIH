const test = require('node:test');
const assert = require('node:assert');
const QRCode = require('qrcode');
const { PNG } = require('pngjs');

const qrAnalyzer = require('../modules/qrAnalyzer');
const arcAnalyzer = require('../modules/arcAnalyzer');
const ruleEngine = require('../modules/ruleEngine');

/**
 * Covers the three things added for attack shapes the pipeline previously could
 * not see at all: a link that exists only as pixels, a forwarding chain that
 * explains away failed authentication, and an authentication flow the victim
 * completes themselves on a genuine provider page.
 */

async function qrPng(text, { invert = false } = {}) {
    const png = await QRCode.toBuffer(text, { type: 'png', width: 300, margin: 2 });
    if (!invert) return png;
    const image = PNG.sync.read(png);
    for (let i = 0; i < image.data.length; i += 4) {
        image.data[i] = 255 - image.data[i];
        image.data[i + 1] = 255 - image.data[i + 1];
        image.data[i + 2] = 255 - image.data[i + 2];
    }
    return PNG.sync.write(image);
}

// ---------------------------------------------------------------------------
// QR codes
// ---------------------------------------------------------------------------

test('a link that exists only inside an attached image is recovered', async () => {
    const png = await qrPng('https://secure-login-verify.example/ms/auth');
    const result = qrAnalyzer.analyze({}, { attachments: [{ filename: 'invoice.png', contentType: 'image/png', content: png }] });

    assert.strictEqual(result.qr.codes_found, 1);
    assert.strictEqual(result.qr.codes[0].payload, 'https://secure-login-verify.example/ms/auth');
    assert.deepStrictEqual(result.qr.extracted_urls, ['https://secure-login-verify.example/ms/auth']);
});

/**
 * The regression that matters most here. jsQR carries state between calls: a
 * failed `dontInvert` attempt makes the *next* call return null for an image it
 * decodes perfectly on its own, even with a brand-new pixel buffer. Two earlier
 * versions of the decoder made two calls and silently could not read inverted
 * codes - exactly the case the second call had been added for.
 */
test('an inverted QR code is still read', async () => {
    const png = await qrPng('https://inverted-lure.example/login', { invert: true });
    const result = qrAnalyzer.analyze({}, { attachments: [{ filename: 'scan.png', contentType: 'image/png', content: png }] });

    assert.strictEqual(result.qr.codes_found, 1, 'a light-on-dark code must not be missed');
    assert.strictEqual(result.qr.codes[0].payload, 'https://inverted-lure.example/login');
    assert.strictEqual(result.qr.codes[0].polarity, 'inverted', 'and the unusual polarity should be recorded');
});

test('JPEG attachments are scanned, not only PNG', async () => {
    const jpeg = require('jpeg-js');
    const png = PNG.sync.read(await qrPng('https://jpeg-lure.example/x'));
    const encoded = jpeg.encode({ data: png.data, width: png.width, height: png.height }, 92).data;

    const result = qrAnalyzer.analyze({}, { attachments: [{ filename: 'photo.jpg', contentType: 'image/jpeg', content: encoded }] });
    assert.strictEqual(result.qr.codes_found, 1);
});

/** Saying what was not looked at is the difference between a gap and a blind spot. */
test('a PDF is reported as unscanned rather than silently skipped', () => {
    const result = qrAnalyzer.analyze({}, {
        attachments: [{ filename: 'statement.pdf', contentType: 'application/pdf', content: Buffer.from('%PDF-1.7') }]
    });

    assert.strictEqual(result.qr.codes_found, 0);
    assert.strictEqual(result.qr.not_scanned.length, 1);
    assert.match(result.qr.not_scanned[0].reason, /not rendered/);
});

test('a code carrying credentials rather than a link is classified as such', async () => {
    const png = await qrPng('WIFI:T:WPA;S:GuestNetwork;P:letmein123;;');
    const result = qrAnalyzer.analyze({}, { attachments: [{ filename: 'wifi.png', contentType: 'image/png', content: png }] });

    assert.strictEqual(result.qr.codes[0].payload_kind, 'wifi_credentials');
    assert.deepStrictEqual(result.qr.extracted_urls, [], 'it is not a URL, so it must not enter the URL set');
});

test('an image with no code in it produces nothing rather than a guess', () => {
    const blank = PNG.sync.write(new PNG({ width: 64, height: 64 }));
    const result = qrAnalyzer.analyze({}, { attachments: [{ filename: 'logo.png', contentType: 'image/png', content: blank }] });

    assert.strictEqual(result.qr.codes_found, 0);
    assert.strictEqual(result.qr.not_scanned.length, 0);
});

test('a QR link raises a rule that cites the technique', async () => {
    const png = await qrPng('https://qr-lure.example/office365');
    const threatObject = qrAnalyzer.analyze({ detection: {} }, { attachments: [{ filename: 'doc.png', contentType: 'image/png', content: png }] });
    threatObject.iocs = { urls: threatObject.qr.extracted_urls };

    const evaluated = ruleEngine.evaluate(threatObject, { textBody: '', attachments: [{ filename: 'doc.png' }], from: { address: 'a@b.test' } });
    const qrRule = evaluated.detection.matched_rules.find(r => r.id === 'MQL-QR-101');

    assert.ok(qrRule, 'a decoded QR link should be a finding in its own right');
    assert.ok(qrRule.mitre.includes('T1566.001'));
});

test('a message with no text but an attachment is flagged on that shape alone', () => {
    const threatObject = { detection: {}, iocs: { urls: [] }, qr: { codes: [], not_scanned: [] } };
    const evaluated = ruleEngine.evaluate(threatObject, {
        textBody: '   \n  ',
        attachments: [{ filename: 'invoice.pdf' }],
        from: { address: 'sender@example.test' }
    });

    assert.ok(evaluated.detection.matched_rules.some(r => r.id === 'MQL-QR-104'),
        'an empty body with an attachment is the shape where a content classifier has nothing to read');
});

// ---------------------------------------------------------------------------
// ARC
// ---------------------------------------------------------------------------

const ARC_VALID = [
    'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=lists.example; s=arc; b=abc',
    'ARC-Message-Signature: i=1; a=rsa-sha256; d=lists.example; s=arc; h=from:to; b=def',
    'ARC-Authentication-Results: i=1; lists.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass',
    'From: Sender <someone@sender.example>',
    'To: victim@corp.example',
    'Subject: Forwarded',
    '',
    'body'
].join('\r\n');

test('no ARC headers is reported as the ordinary case, not as a problem', () => {
    const result = arcAnalyzer.analyze({}, 'From: a@b.test\r\nSubject: x\r\n\r\nbody');
    assert.strictEqual(result.forensics.arc.status, 'ABSENT');
    assert.strictEqual(result.forensics.arc.affects_risk, false);
});

test('a well-formed chain is recorded as context and never as reassurance', () => {
    const result = arcAnalyzer.analyze({}, ARC_VALID);
    const arc = result.forensics.arc;

    assert.strictEqual(arc.status, 'SEALED');
    assert.strictEqual(arc.hops, 1);
    assert.strictEqual(arc.intermediaries[0].signing_domain, 'lists.example');
    assert.strictEqual(arc.affects_risk, false, 'RFC 8617 §9: authenticated is not the same as safe');
    assert.match(arc.risk_note, /never lowers risk/);
});

test('a chain that skips an instance is reported as broken', () => {
    const broken = ARC_VALID.replace(/i=1/g, 'i=2');
    const result = arcAnalyzer.analyze({}, broken);

    assert.strictEqual(result.forensics.arc.status, 'BROKEN');
    assert.ok(result.forensics.arc.problems.some(p => /gap or is out of order/.test(p)));
});

test('a later hop declaring cv=fail terminates the chain', () => {
    const raw = [
        'ARC-Seal: i=1; cv=none; d=first.example; b=a',
        'ARC-Message-Signature: i=1; d=first.example; b=b',
        'ARC-Authentication-Results: i=1; first.example; spf=pass',
        'ARC-Seal: i=2; cv=fail; d=second.example; b=c',
        'ARC-Message-Signature: i=2; d=second.example; b=d',
        'ARC-Authentication-Results: i=2; second.example; spf=fail',
        'From: a@b.test', '', 'body'
    ].join('\r\n');

    const result = arcAnalyzer.analyze({}, raw);
    assert.strictEqual(result.forensics.arc.status, 'BROKEN');
    assert.ok(result.forensics.arc.problems.some(p => /terminates the chain/.test(p)));
});

test('a broken chain raises a finding, because forging one manufactures an excuse', () => {
    const threatObject = arcAnalyzer.analyze({ detection: {}, iocs: { urls: [] } }, ARC_VALID.replace(/i=1/g, 'i=3'));
    const evaluated = ruleEngine.evaluate(threatObject, { textBody: 'hello', attachments: [], from: { address: 'a@b.test' } });

    assert.ok(evaluated.detection.matched_rules.some(r => r.id === 'MQL-ARC-101'));
});

/** The useful direction: softening a failure that forwarding explains. */
test('a sealed chain can explain an authentication failure without excusing the message', () => {
    const threatObject = arcAnalyzer.analyze({}, ARC_VALID);
    const explanation = arcAnalyzer.explainsAuthenticationFailure(threatObject);

    assert.ok(explanation);
    assert.strictEqual(explanation.by, 'lists.example');
    assert.match(explanation.detail, /does not make the message safe/);
});

test('a broken chain explains nothing', () => {
    const threatObject = arcAnalyzer.analyze({}, ARC_VALID.replace(/i=1/g, 'i=4'));
    assert.strictEqual(arcAnalyzer.explainsAuthenticationFailure(threatObject), null);
});

// ---------------------------------------------------------------------------
// Authentication-flow abuse
// ---------------------------------------------------------------------------

/**
 * The case where every URL check comes back clean because the link genuinely
 * is Microsoft's. What is abused is the person, not the domain.
 */
test('a device-code flow is caught even though the link is a genuine provider page', () => {
    const threatObject = { detection: {}, iocs: { urls: ['https://microsoft.com/devicelogin'] }, qr: { codes: [], not_scanned: [] } };
    const evaluated = ruleEngine.evaluate(threatObject, {
        textBody: 'To finish setting up your access, open the link and enter code A7BQ-3KDP.',
        attachments: [],
        from: { address: 'it-support@corp-helpdesk.test' }
    });

    const rule = evaluated.detection.matched_rules.find(r => r.id === 'MQL-AUTHFLOW-101');
    assert.ok(rule, 'a genuine provider link is exactly why this needs its own rule');
    assert.match(rule.matched_because, /supplies a code to enter/);
});

test('an ordinary Microsoft link is not mistaken for a device-code flow', () => {
    const threatObject = { detection: {}, iocs: { urls: ['https://www.microsoft.com/en-gb/microsoft-365'] }, qr: { codes: [], not_scanned: [] } };
    const evaluated = ruleEngine.evaluate(threatObject, { textBody: 'Here is the product page.', attachments: [], from: { address: 'a@b.test' } });

    assert.ok(!evaluated.detection.matched_rules.some(r => r.id === 'MQL-AUTHFLOW-101'));
});

test('a generic tunnelling host is noted but only weakly', () => {
    const threatObject = { detection: {}, iocs: { urls: ['https://login-portal.workers.dev/auth'] }, qr: { codes: [], not_scanned: [] } };
    const evaluated = ruleEngine.evaluate(threatObject, { textBody: 'Sign in here.', attachments: [], from: { address: 'a@b.test' } });

    const rule = evaluated.detection.matched_rules.find(r => r.id === 'MQL-AUTHFLOW-102');
    assert.ok(rule);
    assert.ok(rule.confidence <= 0.5, 'developer infrastructure is common, so this must stay weak on its own');
});

// ---------------------------------------------------------------------------
// MITRE techniques as data
// ---------------------------------------------------------------------------

/**
 * Every rule already cited MITRE in prose, which reads well and is useless to a
 * SIEM. The same citations are now emitted as identifiers.
 */
test('matched rules produce technique identifiers, not just prose', () => {
    const threatObject = { detection: {}, iocs: { urls: ['http://203.0.113.9/login'] }, qr: { codes: [], not_scanned: [] } };
    const evaluated = ruleEngine.evaluate(threatObject, { textBody: 'Sign in.', attachments: [], from: { address: 'a@b.test' } });

    const patterns = evaluated.detection.attack_patterns;
    assert.ok(Array.isArray(patterns) && patterns.length > 0);

    const link = patterns.find(p => p.technique === 'T1566.002');
    assert.ok(link, 'a malicious-link rule should attribute T1566.002');
    assert.strictEqual(link.name, 'Phishing: Spearphishing Link');
    assert.ok(link.attributed_by.length > 0, 'and name which rules attributed it, so it can be checked');
});

test('a technique with no name is reported with its id rather than invented', () => {
    const summarised = ruleEngine.evaluate(
        { detection: {}, iocs: { urls: [] }, qr: { codes: [], not_scanned: [] } },
        { textBody: 'nothing here', attachments: [], from: { address: 'a@b.test' } }
    );
    assert.ok(Array.isArray(summarised.detection.attack_patterns));
});

test('a clean message attributes no techniques at all', () => {
    const evaluated = ruleEngine.evaluate(
        { detection: {}, iocs: { urls: ['https://www.bbc.co.uk/news'] }, qr: { codes: [], not_scanned: [] } },
        { textBody: 'Here is the article we discussed this morning.', attachments: [], from: { address: 'colleague@corp.example' } }
    );
    assert.deepStrictEqual(evaluated.detection.attack_patterns, []);
});

// ---------------------------------------------------------------------------
// Key-gated feeds
// ---------------------------------------------------------------------------

/**
 * PhishTank is reachable without a key.
 *
 * This test previously asserted the opposite, because a 429 seen during three
 * rapid requests was read as an authentication requirement. Checked properly,
 * the keyless URL redirects to a signed CDN link and returns the full verified
 * set - roughly 76,000 URLs - and spaced requests succeed consistently. A key
 * raises the rate limit rather than unlocking the data.
 */
test('PhishTank is on by default and a key is optional, not required', () => {
    delete require.cache[require.resolve('../modules/threatIntelStore')];
    const saved = process.env.PHISHTANK_API_KEY;
    delete process.env.PHISHTANK_API_KEY;

    try {
        const store = require('../modules/threatIntelStore');
        const feed = store.enabledFeeds().find(f => f.id === 'phishtank');
        assert.ok(feed, 'the feed works without a key, so it must be enabled without one');
        assert.strictEqual(store.feedUrl(feed), 'https://data.phishtank.com/data/online-valid.csv');

        process.env.PHISHTANK_API_KEY = 'test-key';
        assert.strictEqual(store.feedUrl(feed), 'https://data.phishtank.com/data/test-key/online-valid.csv',
            'a key switches to the keyed URL, which carries a higher rate limit');
    } finally {
        if (saved === undefined) delete process.env.PHISHTANK_API_KEY;
        else process.env.PHISHTANK_API_KEY = saved;
        delete require.cache[require.resolve('../modules/threatIntelStore')];
    }
});

/**
 * A 14 MB feed fetched on every sync earns a 429 and gains nothing - the
 * verified set does not turn over minute to minute.
 */
test('a large rate-limited feed is not refetched on every sync', () => {
    delete require.cache[require.resolve('../modules/threatIntelStore')];
    const store = require('../modules/threatIntelStore');
    const feed = store.enabledFeeds().find(f => f.id === 'phishtank');

    assert.ok(feed.minimumIntervalMinutes >= 60, 'it should declare a sync interval');
    store.lastFeedSync = { phishtank: new Date().toISOString() };
    assert.strictEqual(store.dueForSync(feed), false, 'just fetched, so not due');

    store.lastFeedSync = { phishtank: new Date(Date.now() - (feed.minimumIntervalMinutes + 5) * 60000).toISOString() };
    assert.strictEqual(store.dueForSync(feed), true, 'past the interval, so due again');

    const always = store.enabledFeeds().find(f => f.id === 'openphish');
    assert.strictEqual(store.dueForSync(always), true, 'small feeds with no interval always sync');
    delete require.cache[require.resolve('../modules/threatIntelStore')];
});

/** A phishing URL routinely contains a comma, and splitting on commas truncates it. */
test('the CSV parser keeps a URL containing a comma intact', () => {
    delete require.cache[require.resolve('../modules/threatIntelStore')];
    const store = require('../modules/threatIntelStore');
    const feed = store.availableFeeds().find(f => f.id === 'phishtank');
    assert.ok(feed);

    const raw = [
        'phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target',
        '1,"https://evil.test/a,b/login",http://x,2026-01-01,yes,2026-01-01,yes,Microsoft',
        '2,"https://gone.test/old",http://x,2026-01-01,yes,2026-01-01,no,Other'
    ].join('\n');

    const urls = storeParsePhishtank(store, raw);

    assert.deepStrictEqual(urls, ['https://evil.test/a,b/login'],
        'the comma inside the quoted field must not split the URL, and an offline entry is not a current indicator');
    delete require.cache[require.resolve('../modules/threatIntelStore')];
});

/** Reaches the feed's own parser without exporting internals just for a test. */
function storeParsePhishtank(store, raw) {
    const saved = process.env.PHISHTANK_API_KEY;
    process.env.PHISHTANK_API_KEY = 'x';
    try {
        const feed = store.enabledFeeds().find(f => f.id === 'phishtank');
        return feed.parse(raw);
    } finally {
        if (saved === undefined) delete process.env.PHISHTANK_API_KEY;
        else process.env.PHISHTANK_API_KEY = saved;
    }
}
