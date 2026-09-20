const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const publicSuffix = require('../modules/publicSuffix');

/**
 * Verified against the Public Suffix List's own conformance suite rather than
 * against cases chosen by whoever wrote the implementation - which is the
 * failure mode of the heuristic this replaces. That one passed every example
 * its author thought of, and got 7 of 10 realistic hosts wrong.
 */

const TEST_FILE = path.join(__dirname, '..', 'reference', 'test_psl.txt');

/** Parses the official `checkPublicSuffix('host', 'expected');` cases. */
function officialCases() {
    if (!fs.existsSync(TEST_FILE)) return [];
    const cases = [];
    for (const line of fs.readFileSync(TEST_FILE, 'utf8').split(/\r?\n/)) {
        const match = line.match(/^checkPublicSuffix\((.+?),\s*(.+?)\);/);
        if (!match) continue;
        const parse = v => {
            const trimmed = v.trim();
            if (trimmed === 'null') return null;
            return trimmed.replace(/^['"]|['"]$/g, '');
        };
        cases.push({ host: parse(match[1]), expected: parse(match[2]) });
    }
    return cases;
}

test('the list actually loaded', () => {
    const state = publicSuffix.state();
    assert.strictEqual(state.loaded, true, 'without the list every answer is a guess');
    assert.ok(state.rules > 5000, `expected thousands of rules, got ${state.rules}`);
    assert.ok(state.wildcard_rules > 0 && state.exception_rules > 0,
        'wildcard and exception rules are what make the algorithm non-trivial');
});

test('it passes the Public Suffix List conformance suite', () => {
    const cases = officialCases();
    assert.ok(cases.length > 50, `expected the official suite, found ${cases.length} cases`);

    const failures = [];
    for (const { host, expected } of cases) {
        // The suite includes mixed-case and unicode hosts; unicode is out of
        // scope here because the list is consumed in its ASCII form, so those
        // are skipped rather than silently counted as passes.
        if (host && /[^\x00-\x7F]/.test(host)) continue;

        const actual = publicSuffix.registrableDomain(host);
        if (actual !== (expected === null ? null : expected.toLowerCase())) {
            failures.push(`${host}: got ${actual}, expected ${expected}`);
        }
    }

    assert.deepStrictEqual(failures, [], `${failures.length} conformance case(s) failed`);
});

/**
 * The reason this module exists. Each of these reduced to the platform's own
 * domain under the old heuristic, so a domain-age lookup returned the
 * platform's registration date and a page created that morning looked like a
 * sixteen-year-old established domain.
 */
test('a subdomain on a free hosting platform is its own registrable domain', () => {
    const platforms = [
        ['evil-bank-login.github.io', 'evil-bank-login.github.io'],
        ['secure-login.pages.dev', 'secure-login.pages.dev'],
        ['phish.workers.dev', 'phish.workers.dev'],
        ['fake.web.app', 'fake.web.app'],
        ['lure.blogspot.com', 'lure.blogspot.com'],
        ['x.netlify.app', 'x.netlify.app']
    ];

    platforms.forEach(([host, expected]) => {
        assert.strictEqual(publicSuffix.registrableDomain(host), expected,
            `${host} must not reduce to the platform's own domain`);
    });
});

test('multi-label public suffixes resolve to the right registrable domain', () => {
    assert.strictEqual(publicSuffix.registrableDomain('mail.corp.co.uk'), 'corp.co.uk');
    assert.strictEqual(publicSuffix.registrableDomain('trust.nhs.uk'), 'trust.nhs.uk');
    assert.strictEqual(publicSuffix.registrableDomain('a.b.example.com'), 'example.com');
    assert.strictEqual(publicSuffix.registrableDomain('shop.example.com.au'), 'example.com.au');
});

test('a bare public suffix has no registrable domain', () => {
    ['co.uk', 'com', 'github.io', 'pages.dev'].forEach(suffix =>
        assert.strictEqual(publicSuffix.registrableDomain(suffix), null,
            `${suffix} is a registry boundary, not something somebody registered`));
});

test('addresses and malformed hosts are rejected rather than guessed at', () => {
    ['203.0.113.9', '2001:db8::1', '', 'localhost', 'not a host'].forEach(host =>
        assert.strictEqual(publicSuffix.registrableDomain(host), null));
});

test('a trailing dot and mixed case are handled', () => {
    assert.strictEqual(publicSuffix.registrableDomain('WWW.Example.COM.'), 'example.com');
});

/** Used to tell a platform apart from a domain somebody owns outright. */
test('it can say whether a host is itself a public suffix', () => {
    assert.strictEqual(publicSuffix.isPublicSuffix('github.io'), true);
    assert.strictEqual(publicSuffix.isPublicSuffix('co.uk'), true);
    assert.strictEqual(publicSuffix.isPublicSuffix('example.com'), false);
});

/**
 * A stale list is far better than none, so a failed refresh must never clear a
 * working one. The realistic failure is a captive portal or an error page
 * returning 200 with HTML - if that replaced the list, registrable-domain
 * extraction would silently degrade for every host.
 */
test('a refresh that returns the wrong content is rejected and the list kept', async () => {
    const before = publicSuffix.state().rules;
    assert.ok(before > 5000);

    const result = await publicSuffix.refresh('https://example.com/');

    assert.strictEqual(result.ok, false);
    assert.strictEqual(publicSuffix.state().rules, before, 'the working list must survive a bad refresh');
    assert.strictEqual(publicSuffix.registrableDomain('evil.github.io'), 'evil.github.io',
        'and extraction must still be correct afterwards');
});

test('a refresh from an unreachable host fails without damage', async () => {
    const before = publicSuffix.state().rules;
    const result = await publicSuffix.refresh('https://this-host-does-not-exist.invalid/list.dat');

    assert.strictEqual(result.ok, false);
    assert.ok(result.error);
    assert.strictEqual(publicSuffix.state().rules, before);
});

/**
 * What the list is actually for in detection terms.
 *
 * Correct registrable-domain extraction on its own only turns a wrong answer
 * into "unknown": an RDAP lookup for evil.github.io returns 404, because
 * nobody registered it. The useful fact is the one the list supplies - the
 * parent is a suffix anyone can obtain a subdomain of, so the attacker
 * inherits a sixteen-year-old reputable domain and valid TLS for the price of
 * signing up.
 */
test('a link on a platform subdomain is flagged, a real company subdomain is not', () => {
    const ruleEngine = require('../modules/ruleEngine');

    const check = (url) => {
        const threatObject = { detection: {}, iocs: { urls: [url] }, qr: { codes: [], not_scanned: [] } };
        const evaluated = ruleEngine.evaluate(threatObject, {
            textBody: 'Please sign in to continue.', attachments: [], from: { address: 'a@b.test' }
        });
        return evaluated.detection.matched_rules.some(r => r.id === 'MQL-URL-110');
    };

    ['https://evil-bank-login.github.io/signin', 'https://secure-login.pages.dev/auth',
     'https://x.workers.dev/', 'https://lure.blogspot.com/post']
        .forEach(url => assert.strictEqual(check(url), true, `${url} should be flagged`));

    ['https://login.paypal.com/signin', 'https://www.bbc.co.uk/news',
     'https://example.com/page', 'https://github.io/']
        .forEach(url => assert.strictEqual(check(url), false, `${url} must not be flagged`));
});
