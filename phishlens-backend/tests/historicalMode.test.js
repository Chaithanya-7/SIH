const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const historicalMode = require('../modules/historicalMode');
const ruleEngine = require('../modules/ruleEngine');

/**
 * Analysing mail that arrived long ago.
 *
 * The backlog scan runs the same pipeline as live mail deliberately. What
 * these cover is the small number of places where that would be wrong, and
 * one place where it would be actively harmful.
 */

test('a retired DKIM selector is not reported as a forged header', () => {
    // The trap this module exists for.
    //
    // PhishLens re-verifies DKIM itself, and the signing key comes from DNS at
    // the moment of checking. Domains rotate selectors as routine maintenance,
    // so an old message often names one that is simply gone. The header says
    // dkim=pass, live verification finds nothing, the two disagree - and that
    // disagreement fires MQL-AUTH-102 at CRITICAL, 0.85, a rule written for
    // headers forged to mislead filters.
    //
    // Untreated, this would flag a large share of ordinary old mail. A backlog
    // scan that cries wolf across two thousand messages is worse than none: it
    // gets switched off, and it buries the few real findings with it.
    const threatObject = {
        forensics: {
            authentication: {
                dkim: 'pass',
                dkim_header_mismatch: 'Authentication-Results header claims dkim=pass, but independent verification found: none',
                dkim_independent_verification: { status: 'AVAILABLE', overall: 'none', results: [] }
            }
        }
    };

    historicalMode.reconcileDkim(threatObject);
    const auth = threatObject.forensics.authentication;

    assert.strictEqual(auth.dkim_header_mismatch, null, 'the accusation must be withdrawn');
    assert.strictEqual(auth.dkim_key_unavailable, true);
    assert.ok(auth.dkim_historical_note, 'and the reason must be recorded rather than the finding vanishing');

    // Withdrawn, not erased. What was actually observed stays on the case.
    assert.ok(auth.dkim_header_mismatch_suppressed, 'the original observation must remain visible');

    // And with the mismatch gone, the rule that fires on it does not.
    const matched = ruleEngine.evaluate(
        { forensics: threatObject.forensics, iocs: {}, attachments: [], detection: {} },
        { from: { address: 'someone@supplier.example' }, textBody: 'Invoice attached.', messageId: '<x@supplier.example>' }
    );
    const ids = (matched.detection?.matched_rules || []).map(r => r.id);
    assert.ok(!ids.includes('MQL-AUTH-102'), 'a rotated key must not read as a forged header');
});

test('a signature that fails against a key still published is left alone', () => {
    // The distinction that makes the suppression above safe. A missing key is
    // explained by the age of the message; a signature that actively fails
    // against a key that is still there is not, and must survive.
    const threatObject = {
        forensics: {
            authentication: {
                dkim: 'pass',
                dkim_header_mismatch: 'Authentication-Results header claims dkim=pass, but independent verification found: fail',
                dkim_independent_verification: { status: 'AVAILABLE', overall: 'fail', results: [] }
            }
        }
    };

    historicalMode.reconcileDkim(threatObject);
    const auth = threatObject.forensics.authentication;

    assert.ok(auth.dkim_header_mismatch, 'an active verification failure is not explained by age');
    assert.notStrictEqual(auth.dkim_key_unavailable, true);
});

test('checks that could only describe today are marked, not run and scored as clean', () => {
    const threatObject = {};
    const twoYearsAgo = new Date(Date.now() - 730 * 86400000).toISOString();

    historicalMode.markSkippedChecks(threatObject, twoYearsAgo);
    const mode = threatObject.analysis_mode;

    assert.strictEqual(mode.mode, 'HISTORICAL');
    assert.ok(mode.age_days >= 700, 'the age must be computed, since it is what the caveat rests on');

    const skipped = mode.checks_not_applicable.map(c => c.check);
    for (const expected of [
        'DKIM_INDEPENDENT_VERIFICATION',
        'DOMAIN_REGISTRATION_AGE',
        'THREAT_INTELLIGENCE_FEEDS',
        'IP_REPUTATION_AND_ANONYMISATION',
        'DNS_RESOLUTION'
    ]) {
        assert.ok(skipped.includes(expected), `${expected} describes the present and must be declared skipped`);
    }

    // Every one carries its reason. "Not applicable" with no explanation is
    // the same dead end as a silent skip.
    for (const entry of mode.checks_not_applicable) {
        assert.strictEqual(entry.status, 'NOT_APPLICABLE_HISTORICAL');
        assert.ok(entry.reason && entry.reason.length > 40, `${entry.check} must say why`);
    }

    assert.ok(mode.verdict_caveat, 'a historical SAFE must not read like a live one');
});

test('live analysis is recorded as live rather than left blank', () => {
    // So a case is never read by the absence of a field: "no analysis_mode"
    // and "analysed live" would otherwise be the same thing on the wire.
    const threatObject = {};
    historicalMode.markLive(threatObject);

    assert.strictEqual(threatObject.analysis_mode.mode, 'LIVE');
    assert.deepStrictEqual(threatObject.analysis_mode.checks_not_applicable, []);
    assert.strictEqual(threatObject.analysis_mode.verdict_caveat, null);
});

test('the pipeline suppresses remediation and learning on a backlog scan', () => {
    // Read from the source rather than executed, because reaching these lines
    // means running the whole pipeline with live DNS. What matters is that the
    // guards exist and are attached to the historical flag.
    const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    assert.match(source, /if \(historical\) \{[\s\S]{0,400}SUPPRESSED_HISTORICAL/,
        'a scan must not quarantine mail the recipient dealt with years ago');
    assert.match(source, /if \(!historical\) \{[\s\S]{0,200}adaptiveLearning\.learnFromDetection/,
        'the model must not learn from a mailbox-sized batch of reduced-evidence verdicts');
    assert.match(source, /historical \? Promise\.resolve\(null\) : infraEnricher\.enrich/,
        'live infrastructure enrichment describes today, not when the message arrived');
    assert.match(source, /historical \? Promise\.resolve\(null\) : threatIntelEnricher\.enrich/,
        'feeds carry what is malicious now, not what was malicious then');

    // The behavioural baseline is deliberately NOT suppressed: recording what a
    // sender's mail normally looks like is exactly what history is good for,
    // and it is why a backlog is processed oldest first.
    assert.match(source, /behavioralAnalyzer\.recordObservation\(threatObject, parsedEmail\);/);
});

// ---------------------------------------------------------------------------
// The extension side
// ---------------------------------------------------------------------------

const EXTENSION = path.join(__dirname, '..', '..', 'phishlens-extension');

function loadProviders() {
    const source = fs.readFileSync(path.join(EXTENSION, 'mail-providers.js'), 'utf8');
    const sandbox = { window: {}, globalThis: {}, module: { exports: {} } };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);
    return sandbox.module.exports?.forHostname ? sandbox.module.exports : (sandbox.PhishLensMailProviders || sandbox.window.PhishLensMailProviders);
}

test('the scanner can page through Gmail, and says so honestly for Outlook', () => {
    const providers = loadProviders();

    assert.strictEqual(providers.gmail.pageHash(1), '#inbox', 'the first page is the inbox itself');
    assert.strictEqual(providers.gmail.pageHash(2), '#inbox/p2');
    assert.strictEqual(providers.gmail.pageHash(17), '#inbox/p17');
    assert.strictEqual(providers.gmail.pageHash(0), null, 'a nonsense page number must not produce an address');

    // Outlook pages differently, and guessing would be the worst outcome: the
    // scan would read the first page repeatedly and report a whole mailbox
    // examined. Absence here is what makes the scanner refuse out loud.
    assert.strictEqual(typeof providers.outlook.pageHash, 'undefined',
        'an unimplemented pager must be absent, not a guess');
});

test('the backlog scanner refuses a provider it cannot page, rather than looping', () => {
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    assert.match(content, /typeof provider\.pageHash !== 'function'/,
        'it must check before it starts');
    assert.match(content, /Backlog scanning is not implemented for/,
        'and say so, rather than silently examining nothing');
});

test('backlog submissions are labelled historical, and live ones are not', () => {
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    // The label is the entire mechanism. Without it the backend runs live
    // enrichment over old mail and acts on the result.
    const historicalFn = content.slice(content.indexOf('async function examineHistorical'));
    assert.match(historicalFn.slice(0, 900), /analysis_mode: 'HISTORICAL'/,
        'a backlog submission must declare itself');

    const liveFn = content.slice(content.indexOf('async function examine(entry)'), content.indexOf('function noteFailure'));
    assert.ok(!liveFn.includes('HISTORICAL'), 'live mail must never be labelled historical');
});

test('the scan is paced, and the pacing is not decorative', () => {
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    const pace = content.match(/BACKLOG_PACE_MS\s*=\s*(\d+)/);
    assert.ok(pace, 'there must be a pace');
    assert.ok(Number(pace[1]) >= 1000,
        'thousands of rapid requests from a signed-in session is indistinguishable from scraping, '
        + "and the realistic cost is a security challenge on the person's own mailbox");

    // It has to actually wait between messages, not merely define a constant.
    assert.match(content, /await pause\(BACKLOG_PACE_MS\)/);

    // And it must give up on a backend that has gone away rather than working
    // through an entire mailbox failing.
    assert.match(content, /consecutiveFailures >= 5/);
});
