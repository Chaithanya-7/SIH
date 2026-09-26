const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const assuranceEvidence = require('../modules/assuranceEvidence');
const confidenceEngine = require('../modules/confidenceEngine');
const evidenceFusion = require('../modules/evidenceFusion');

/**
 * Showing the working behind a clean verdict.
 *
 * Before this existed, a message with nothing wrong with it produced an empty
 * evidence list - measured: verdict SAFE, evidence items 0, contributions 0. A
 * green label with nothing at all behind it, which is indistinguishable from an
 * analysis that fell over and produced nothing. The reassuring reading is also
 * the more common one, so the habit somebody forms is to trust a label that has
 * never shown its working.
 *
 * ## The property that matters most here
 *
 * **Assurance must never reduce a threat score.** Detection was added to this
 * system for phishing sent through legitimate platforms and compromised
 * accounts, all of which passes SPF, DKIM and DMARC because none of it is
 * forged. Every one of those messages collects a full set of passed
 * authentication checks. Netting those off against suspicion would mean the
 * better an attacker's infrastructure, the safer their mail looked - so several
 * of these tests exist purely to hold that line.
 */

const cleanCase = () => ({
    detection: { verdict: 'SAFE', matched_rules: [] },
    forensics: { authentication: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { policy: 'reject' } } },
    iocs: { urls: [] },
    attachments: [],
    behavioral: { status: 'ANALYZED', messages_seen_from_sender: 14 },
    text_deception: { hidden_characters: [], mixed_script_words: [], concealed_markup: { substantial: false } },
    payload_channel: { channels: ['LINK'] },
    thread: { claims_to_be_reply: false, has_thread_headers: false, findings: [] },
    threat_intelligence: {
        status: 'MATCHED_AGAINST_LOCAL_FEEDS',
        matches: [],
        domain_ages: [{ is_sender_domain: true, status: 'AVAILABLE', age_days: 4200 }]
    }
});

const parsed = { from: { address: 'priya@supplier.example' } };
const find = (t, name) => t.assurance.checks.find(c => c.check === name);

test('a clean message now shows what was checked instead of nothing', () => {
    const before = cleanCase();

    // The state this replaces: fusion over a clean message produces no evidence
    // at all, so there is nothing for a person to read.
    const fused = evidenceFusion.fuse({ ...before });
    assert.strictEqual(fused.evidence.length, 0, 'this test is only meaningful while that is true');

    const result = assuranceEvidence.assess(before, parsed);

    assert.strictEqual(result.assurance.status, 'ASSESSED');
    assert.ok(result.assurance.passed >= 8, 'a clean message should have substantially more than nothing behind it');
    assert.strictEqual(result.assurance.not_run, 0, 'nothing in this fixture prevents a check from running');
});

test('assurance does not touch the verdict or the score', () => {
    // The line this whole module has to hold.
    let threatObject = cleanCase();
    threatObject.confidence = { threat: 0.42, contributions: [{ family: 'LANGUAGE', contribution: 0.42 }] };
    threatObject.detection.verdict = 'SUSPICIOUS';

    const before = JSON.stringify({ c: threatObject.confidence, d: threatObject.detection });
    threatObject = assuranceEvidence.assess(threatObject, parsed);
    const after = JSON.stringify({ c: threatObject.confidence, d: threatObject.detection });

    assert.strictEqual(after, before, 'assess() must not alter confidence or detection in any way');
});

test('a suspicious message keeps its verdict however many checks passed', () => {
    // Nine clean checks and one finding is still a finding. Anything else would
    // let a well-resourced attacker collect enough passes to bury it.
    let threatObject = cleanCase();
    threatObject.detection.verdict = 'HIGH_RISK';
    threatObject = assuranceEvidence.assess(threatObject, parsed);

    assert.strictEqual(threatObject.detection.verdict, 'HIGH_RISK');
    assert.match(threatObject.assurance.summary, /do not offset/i,
        'the summary must say plainly that clean checks do not cancel a finding');
});

test('passing authentication is never presented as proof of honesty', () => {
    const threatObject = assuranceEvidence.assess(cleanCase(), parsed);
    const auth = find(threatObject, 'Sender authentication');

    assert.strictEqual(auth.result, 'PASSED');

    // The sentence that stops this whole feature from being dangerous. A real
    // Dropbox share, a real DocuSign envelope and mail from a compromised
    // account all pass every one of these checks.
    assert.ok(auth.does_not_rule_out, 'a passed check must say what it does not rule out');
    assert.match(auth.does_not_rule_out, /compromised account|platform/i);
});

test('every passed check says what it does not rule out', () => {
    const threatObject = assuranceEvidence.assess(cleanCase(), parsed);

    const silent = threatObject.assurance.checks
        .filter(c => c.result === 'PASSED')
        .filter(c => !c.does_not_rule_out || c.does_not_rule_out.length < 40)
        .map(c => c.check);

    // A bare "passed" invites the reader to conclude more than the check
    // supports, and the checks here differ enormously in what they establish.
    assert.deepStrictEqual(silent, [], 'a passed check with no stated limit is an invitation to over-read it');
});

test('a check that could not run is never reported as one that passed', () => {
    // The project's central rule, applied in the direction that is easiest to
    // get wrong. "No malicious attachment was found" is assurance only if the
    // attachments were actually read.
    const threatObject = assuranceEvidence.assess({
        detection: { verdict: 'SAFE', matched_rules: [] },
        forensics: {},
        iocs: {},
        attachments: [{ file_name: 'invoice.pdf' }],
        threat_intelligence: { status: 'NO_FEED_DATA', matches: [] }
    }, { from: { address: 'someone@unknown.example' } });

    assert.strictEqual(find(threatObject, 'Sender authentication').result, 'NOT_RUN');
    assert.strictEqual(find(threatObject, 'Attachments').result, 'NOT_RUN');
    assert.match(find(threatObject, 'Attachments').detail, /not a clean one/i);

    // The feed check in particular: an empty match list from feeds that were
    // never loaded looks exactly like an empty match list from feeds that were.
    const feeds = find(threatObject, 'Known-malicious indicator feeds');
    assert.strictEqual(feeds.result, 'NOT_RUN');
    assert.match(feeds.detail, /easiest to mistake for a pass/i);

    assert.match(threatObject.assurance.summary, /could not run/i);
});

test('a failed check is not dressed up as assurance', () => {
    const threatObject = assuranceEvidence.assess({
        detection: { verdict: 'HIGH_RISK', matched_rules: [{ id: 'MQL-AUTH-104' }] },
        forensics: { authentication: { spf: 'fail', dkim: 'fail', dmarc: 'fail' } },
        iocs: {},
        attachments: []
    }, { from: { address: 'spoofed@bank.example' } });

    const auth = find(threatObject, 'Sender authentication');
    assert.strictEqual(auth.result, 'NOT_APPLICABLE');
    assert.match(auth.detail, /finding, not assurance/i);

    // And it must point at the evidence rather than restating the finding here,
    // so one fact is not presented twice in two different places.
    assert.strictEqual(find(threatObject, 'Detection rules').result, 'NOT_APPLICABLE');
});

test('a first message from a sender is not treated as a problem or as a pass', () => {
    const threatObject = assuranceEvidence.assess({
        ...cleanCase(),
        behavioral: { status: 'ANALYZED', messages_seen_from_sender: 0 }
    }, parsed);

    const history = find(threatObject, 'Sender history');
    assert.strictEqual(history.result, 'NOT_APPLICABLE');
    // Every genuine correspondent starts here.
    assert.match(history.detail, /Not suspicious in itself/i);
});

test('the record states its own limit', () => {
    const threatObject = assuranceEvidence.assess(cleanCase(), parsed);
    assert.match(threatObject.assurance.limitation, /not a finding of innocence/i);
    assert.match(threatObject.assurance.limitation, /does not lower the threat score/i);
});

test('the pipeline runs it after the verdict, where it cannot influence one', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    const scoreAt = source.indexOf('confidenceEngine.calculate(threatObject)');
    const assureAt = source.indexOf('assuranceEvidence.assess(threatObject, parsedEmail)');

    assert.ok(scoreAt > -1 && assureAt > -1, 'both steps must be present');
    assert.ok(assureAt > scoreAt,
        'assurance runs after scoring, so it cannot participate in the score even by accident');
});

test('a clean message still scores SAFE with assurance present', () => {
    // Belt and braces: the whole pipeline order, end to end, asserting the
    // record changed nothing.
    let threatObject = cleanCase();
    threatObject = evidenceFusion.fuse(threatObject);
    threatObject = confidenceEngine.calculate(threatObject);
    const scored = threatObject.confidence.threat;

    threatObject = assuranceEvidence.assess(threatObject, parsed);
    assert.strictEqual(threatObject.confidence.threat, scored);
    assert.strictEqual(threatObject.detection.verdict, 'SAFE');
    assert.ok(threatObject.assurance.checks.length >= 10);
});
