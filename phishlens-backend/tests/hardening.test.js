const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

/**
 * Regressions for defects found by auditing the existing code rather than by
 * building anything new. Each one was silent: nothing crashed, nothing was
 * logged, and the system reported success.
 */

/** Comments carry apostrophes and deliberate mentions of what is NOT there. */
function stripComments(text) {
    return text.replace(/\/\/[^\n]*/g, '');
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/**
 * Cases are held in a Map keyed by case_id. Three random bytes gives roughly a
 * 95% chance of a collision by the ten-thousandth case - a few weeks of one
 * corporate mailbox - and a collision silently replaced an existing
 * investigation with a new one.
 */
test('case identifiers do not collide at realistic volumes', () => {
    const ThreatObject = require('../models/ThreatObject');
    const ids = new Set();
    for (let i = 0; i < 100000; i++) ids.add(new ThreatObject({}).case_id);
    assert.strictEqual(ids.size, 100000, 'a collision here overwrites somebody\'s case');
});

/**
 * Actions are held in a Map keyed by action_id. Drawing from 90,000 values
 * collides with near-certainty by the thousandth action, which would overwrite
 * the record of something that had been done to somebody's mail.
 */
test('remediation action identifiers do not collide at realistic volumes', () => {
    const RemediationAction = require('../models/RemediationAction');
    const ids = new Set();
    for (let i = 0; i < 100000; i++) ids.add(new RemediationAction({}).action_id);
    assert.strictEqual(ids.size, 100000);
});

/**
 * campaign_id is the table's PRIMARY KEY. The previous form drew from 900
 * values - an even chance of collision by the thirty-fifth campaign - and the
 * insert callback discarded its error, so a collided campaign resolved as
 * though stored and the case was filed under somebody else's attack.
 */
test('campaign identifiers are drawn from a space large enough to be unique', () => {
    const src = fs.readFileSync(path.join(__dirname, '../modules/campaignGraph.js'), 'utf8');
    assert.doesNotMatch(src, /CMP-\d+-\$\{Math\.floor/, 'campaign ids must not come from Math.random over a small range');
    assert.match(src, /crypto\.randomBytes\(\d+\)\.toString\('hex'\)/, 'they should come from a cryptographic source');

    const insert = src.slice(src.indexOf('INSERT INTO campaigns'));
    assert.doesNotMatch(insert.slice(0, 900), /\(\)\s*=>\s*resolve\(campaign\)/,
        'the insert callback must not discard its error');
});

// ---------------------------------------------------------------------------
// A guard that hid a missing method
// ---------------------------------------------------------------------------

/**
 * The Gmail readiness check called mailboxConnectionManager.getAllConnections,
 * which did not exist, behind a `typeof === 'function'` guard that substituted
 * an empty list. Readiness therefore reported "no mailbox connected" for ever,
 * and the Mail Coverage view - whose whole job is answering whether mail could
 * arrive unexamined - said Gmail was not being watched while it was.
 */
test('the mailbox manager exposes the method the readiness check calls', () => {
    const manager = require('../modules/mailboxConnectionManager');
    assert.strictEqual(typeof manager.getAllConnections, 'function');
});

test('Gmail readiness can actually see a connected mailbox', () => {
    const manager = require('../modules/mailboxConnectionManager');
    const gmail = require('../adapters/gmailIngestionAdapter');
    const savedId = gmail.clientId;
    const savedSecret = gmail.clientSecret;
    gmail.clientId = 'test-id';
    gmail.clientSecret = 'test-secret';

    try {
        assert.strictEqual(gmail.preflight().connected_mailboxes, 0);

        manager.connections.set('test-conn', { id: 'test-conn', status: 'CONNECTED', organization_id: 'org1' });
        const ready = gmail.preflight();

        assert.strictEqual(ready.connected_mailboxes, 1, 'a connected mailbox must be visible to the readiness check');
        assert.strictEqual(ready.ready, true);
    } finally {
        manager.connections.delete('test-conn');
        gmail.clientId = savedId;
        gmail.clientSecret = savedSecret;
    }
});

test('no module hides a missing method behind a typeof guard', () => {
    const root = path.join(__dirname, '..');
    const offenders = [];
    ['modules', 'adapters'].forEach(dir => {
        fs.readdirSync(path.join(root, dir)).filter(f => f.endsWith('.js')).forEach(f => {
            const content = fs.readFileSync(path.join(root, dir, f), 'utf8');
            content.split('\n').forEach((line, i) => {
                const code = line.trim();
                if (code.startsWith('*') || code.startsWith('//')) return;
                if (/typeof\s+\w+\.\w+\s*===\s*'function'/.test(line)) {
                    offenders.push(`${dir}/${f}:${i + 1}`);
                }
            });
        });
    });
    assert.deepStrictEqual(offenders, [],
        'a typeof guard on another module\'s method turns a missing method into silently wrong behaviour');
});

// ---------------------------------------------------------------------------
// Nothing may report an action it did not take
// ---------------------------------------------------------------------------

/**
 * notificationAdapter carried a dispatchRecipientWarning that wrote an audit
 * entry reading "Recipient <address> notified" and returned success, without
 * sending anything to anyone. Nothing called it, which is the only reason the
 * ledger was not already carrying false records of people being warned.
 */
test('nothing claims to have notified a recipient without sending anything', () => {
    const notificationAdapter = require('../adapters/notificationAdapter');
    assert.strictEqual(notificationAdapter.dispatchRecipientWarning, undefined,
        'warning a recipient is done by marking the message, and reported only on provider confirmation');
});

test('a SOC alert with nowhere to go is reported as skipped, not as sent', async () => {
    const notificationAdapter = require('../adapters/notificationAdapter');
    const saved = process.env.SOC_WEBHOOK_URL;
    delete process.env.SOC_WEBHOOK_URL;
    try {
        const result = await notificationAdapter.dispatchSocAlert(
            { case_id: 'T1', message: {}, detection: {}, confidence: {} }, 'TEST_POLICY');

        assert.strictEqual(result.success, false);
        assert.strictEqual(result.skipped, true);
        assert.match(result.reason, /nowhere to send/);
    } finally {
        if (saved !== undefined) process.env.SOC_WEBHOOK_URL = saved;
    }
});

// ---------------------------------------------------------------------------
// API authentication fails closed
// ---------------------------------------------------------------------------

/**
 * Authentication was an allowlist of protected prefixes, with anything unlisted
 * open. That shape failed three times: '/api/ingest' did not cover
 * '/api/ingestion' and '/api/remediate' did not cover '/api/remediation'
 * because Express matches on segment boundaries, and '/api/overview' was never
 * added at all - so it returned every case in every organisation to anyone who
 * asked, its own isolation logic keying off a req.user nothing had populated.
 */
test('every /api route is authenticated unless deliberately exempted', () => {
    const src = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');

    assert.match(src, /app\.use\('\/api',\s*\(req, res, next\)/,
        'authentication must be mounted across /api rather than on a list of prefixes');
    assert.doesNotMatch(src, /app\.use\(\[[\s\S]{0,2000}\],\s*requireAuth\)/,
        'the prefix allowlist must not come back - forgetting a line on it silently opens a route');

    const block = src.match(/const PUBLIC_API_ROUTES = new Set\(\[([\s\S]*?)\]\)/);
    assert.ok(block, 'the exemptions must be an explicit, readable list');
    const exemptions = [...stripComments(block[1]).matchAll(/'([^']+)'/g)].map(m => m[1]).sort();

    assert.deepStrictEqual(exemptions, [
        '/api/auth/google/verify',
        '/api/health',
        '/api/webhooks/gmail'
    ], 'anything added here is readable without a credential and needs its own justification');
});

/**
 * These connect a mailbox to an account that is already signed in and read
 * req.user.id, so exempting them would turn an authorization check into a
 * TypeError on undefined.
 */
test('the Gmail connect endpoints are not among the public exemptions', () => {
    const src = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf8');
    const block = src.match(/const PUBLIC_API_ROUTES = new Set\(\[([\s\S]*?)\]\)/)[1];
    assert.doesNotMatch(stripComments(block), /auth\/gmail/);
});

// ---------------------------------------------------------------------------
// Enrichment failures must not destroy a detection
// ---------------------------------------------------------------------------

/**
 * updateCampaign resolves null when its row has gone or the query errored, and
 * the line after it dereferenced the result. A storage problem in an enrichment
 * step took the whole detection down with it.
 */
test('a campaign that cannot be stored does not take the detection with it', () => {
    const src = fs.readFileSync(path.join(__dirname, '../modules/campaignGraph.js'), 'utf8');
    const callSite = src.slice(src.indexOf('campaignRecord = await this.createCampaign'));

    assert.match(callSite.slice(0, 1400), /if \(!campaignRecord\)/,
        'a null or failed campaign record must be handled before it is dereferenced');
    assert.match(callSite.slice(0, 2000), /UNAVAILABLE/,
        'and the absence recorded on the case rather than thrown away');
});

/**
 * The defect that prompted this audit: totalWeight was incremented in four
 * places and declared nowhere, and a class method is strict mode, so the
 * pipeline crashed the moment two messages shared a sender.
 */
test('no module assigns to an identifier it never declares', () => {
    const root = path.join(__dirname, '..');
    const known = new Set(['module', 'exports', 'process', 'console', 'global']);
    const offenders = [];

    ['modules', 'adapters', 'models', 'middleware'].forEach(dir => {
        const full = path.join(root, dir);
        if (!fs.existsSync(full)) return;
        fs.readdirSync(full).filter(f => f.endsWith('.js')).forEach(f => {
            const src = fs.readFileSync(path.join(full, f), 'utf8');
            src.split('\n').forEach((line, i) => {
                const m = line.match(/^\s{4,}([A-Za-z_$][\w$]*)\s*(?:\+|-|\*|\/)?=(?!=)/);
                if (!m) return;
                const name = m[1];
                if (known.has(name)) return;

                // A parameter counts as declared, including one carrying a
                // default value: `evaluateRelayHops(hops = [], raw = '')`
                // declares hops. Missing that produced a false positive the
                // first time this check was written.
                const param = String.raw`\s*(?:=[^,)]*)?\s*[,)]`;
                const declared = new RegExp(
                    String.raw`\b(?:const|let|var|function|class)\s+` + name + String.raw`\b`
                    + String.raw`|\(\s*` + name + param
                    + String.raw`|,\s*` + name + param
                    + String.raw`|catch\s*\(\s*` + name + String.raw`\s*\)`
                );
                if (!declared.test(src)) offenders.push(`${dir}/${f}:${i + 1}  ${name}`);
            });
        });
    });

    assert.deepStrictEqual(offenders, [],
        'in strict mode this throws ReferenceError at runtime, not at load');
});
