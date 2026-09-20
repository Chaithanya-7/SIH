const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * The advisor is tested against synthetic records rather than live DNS: what
 * matters is that a given published posture produces the right conclusion, and
 * a test that depends on somebody else's DNS fails for reasons that have
 * nothing to do with this code.
 */

/**
 * The advisor reads the operator's configured organisation domains through
 * executiveGuard, which loads them from the data directory. Pointing at a
 * private directory keeps that empty regardless of what any other test file is
 * doing concurrently - without it, this suite failed intermittently whenever
 * the executive-guard tests happened to be writing domains at the same moment.
 */
function advisorWith(records) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-posture-'));
    process.env.PHISHLENS_DATA_DIR = dir;
    isolatedDirs.push(dir);

    ['../modules/dmarcAdvisor', '../modules/executiveGuard'].forEach(m => delete require.cache[require.resolve(m)]);
    const advisor = require('../modules/dmarcAdvisor');
    advisor.cache.clear();
    advisor.resolveTxt = async (name) => records[name] || null;
    return advisor;
}

const isolatedDirs = [];
const previousDataDir = process.env.PHISHLENS_DATA_DIR;

test.after(() => {
    if (previousDataDir === undefined) delete process.env.PHISHLENS_DATA_DIR;
    else process.env.PHISHLENS_DATA_DIR = previousDataDir;
    isolatedDirs.forEach(d => { try { fs.rmSync(d, { recursive: true, force: true }); } catch (e) { /* best effort */ } });
});

test('a domain with no DMARC record is called out as spoofable, with the record to publish', async () => {
    const advisor = advisorWith({ 'example.test': ['v=spf1 include:_spf.example.test -all'] });
    const result = await advisor.assess('example.test');

    assert.strictEqual(result.spoofable, true);
    assert.strictEqual(result.severity, 'CRITICAL');
    const dmarc = result.findings.find(f => f.control === 'DMARC');
    assert.match(dmarc.dns_record.value, /^v=DMARC1; p=none/,
        'the first step is monitoring, because jumping to reject breaks legitimate senders');
    assert.strictEqual(dmarc.dns_record.name, '_dmarc.example.test');
});

/** p=none reports abuse without stopping it, which is the distinction that matters. */
test('p=none is treated as reporting, not protection', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=none; rua=mailto:r@example.test'],
        'example.test': ['v=spf1 -all']
    });
    const result = await advisor.assess('example.test');

    assert.strictEqual(result.spoofable, true);
    const dmarc = result.findings.find(f => f.control === 'DMARC');
    assert.match(dmarc.consequence, /still lands in the inbox/);
    assert.match(dmarc.dns_record.value, /p=quarantine; pct=25/, 'the next step is staged, not a jump to reject');
});

test('a partial rollout is reported with the gap it leaves', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=quarantine; pct=25; rua=mailto:r@example.test'],
        'example.test': ['v=spf1 -all']
    });
    const result = await advisor.assess('example.test');
    const dmarc = result.findings.find(f => f.control === 'DMARC');

    assert.match(dmarc.consequence, /remaining 75%/,
        'an operator should see what fraction of forged mail still gets through');
});

test('p=reject is reported as correct rather than nagged at', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=reject; rua=mailto:r@example.test'],
        'example.test': ['v=spf1 include:_spf.example.test -all']
    });
    const result = await advisor.assess('example.test');

    assert.strictEqual(result.spoofable, false);
    assert.strictEqual(result.severity, 'OK');
});

/** Enforcing the parent while leaving subdomains open is a common and exploitable gap. */
test('sp=none under an enforcing policy is flagged', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=reject; sp=none; rua=mailto:r@example.test'],
        'example.test': ['v=spf1 -all']
    });
    const result = await advisor.assess('example.test');

    const sub = result.findings.find(f => f.control === 'DMARC_SUBDOMAIN');
    assert.ok(sub, 'a subdomain exemption under an enforcing parent must be reported');
    assert.strictEqual(sub.severity, 'HIGH');
});

/** +all makes forged mail pass SPF, so it is worse than publishing nothing. */
test('SPF +all is treated as critical', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=reject; rua=mailto:r@example.test'],
        'example.test': ['v=spf1 +all']
    });
    const result = await advisor.assess('example.test');

    const spf = result.findings.find(f => f.control === 'SPF');
    assert.strictEqual(spf.severity, 'CRITICAL');
    assert.match(spf.consequence, /worse than publishing nothing/);
});

test('a policy with no reporting address is flagged, because tightening it blind breaks mail', async () => {
    const advisor = advisorWith({
        '_dmarc.example.test': ['v=DMARC1; p=quarantine'],
        'example.test': ['v=spf1 -all']
    });
    const result = await advisor.assess('example.test');

    const reporting = result.findings.find(f => f.control === 'DMARC_REPORTING');
    assert.ok(reporting);
    assert.match(reporting.consequence, /blocking your own mail/);
});

test('with no organisation domains configured it says so rather than inventing a result', async () => {
    const advisor = advisorWith({});
    const result = await advisor.assessOwnDomains();

    assert.deepStrictEqual(result.domains, []);
    assert.match(result.note, /No organisation domains are configured/);
});
