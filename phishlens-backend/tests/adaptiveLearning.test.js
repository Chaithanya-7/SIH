const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const emailParser = require('../modules/emailParser');
const mqlBridge = require('../modules/mqlBridge');
const nlpAnalyzer = require('../modules/nlpAnalyzer');
const ruleEngine = require('../modules/ruleEngine');

const MODEL_FILE = path.join(__dirname, '../data/learned_model.json');
const BASELINE_FILE = path.join(__dirname, '../data/sender_baselines.json');

/**
 * These tests exercise the learning engines against isolated model files so a
 * test run never reads or writes the operator's real learned model.
 */
async function withIsolatedStores(run) {
    const saved = {};
    [MODEL_FILE, BASELINE_FILE].forEach(file => {
        // Checked and removed in one attempt rather than two.
        //
        // existsSync followed by unlinkSync is a race, and the test runner runs
        // files in parallel: another suite clearing the same store between the
        // two calls made this throw ENOENT in a full run while passing in
        // isolation. The file being gone is the outcome this wants anyway.
        try {
            saved[file] = fs.readFileSync(file, 'utf8');
        } catch (e) {
            saved[file] = null;
        }
        try {
            fs.unlinkSync(file);
        } catch (e) {
            if (e.code !== 'ENOENT') throw e;
        }
    });

    // Required after clearing the files so the singletons start from empty state.
    delete require.cache[require.resolve('../modules/adaptiveLearning')];
    delete require.cache[require.resolve('../modules/behavioralAnalyzer')];
    const adaptiveLearning = require('../modules/adaptiveLearning');
    const behavioralAnalyzer = require('../modules/behavioralAnalyzer');

    try {
        // Must be awaited: without it the restore below would run before the
        // async test body finishes, leaving the operator's real model files
        // exposed to test writes.
        return await run(adaptiveLearning, behavioralAnalyzer);
    } finally {
        Object.entries(saved).forEach(([file, content]) => {
            if (content === null) { if (fs.existsSync(file)) fs.unlinkSync(file); }
            else fs.writeFileSync(file, content);
        });
        delete require.cache[require.resolve('../modules/adaptiveLearning')];
        delete require.cache[require.resolve('../modules/behavioralAnalyzer')];
    }
}

async function analyze(raw, auth = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } }) {
    const parsedEmail = await emailParser.parse(raw);
    let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
    threatObject.forensics.authentication = auth;
    threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = ruleEngine.evaluate(threatObject, parsedEmail);
    return { threatObject, parsedEmail };
}

function phishingSample(n) {
    return [
        `From: "Account Team" <alerts${n}@suspicious-domain.example>`,
        'To: employee@company.example',
        `Subject: Invoice settlement notice ${n}`,
        `Message-ID: <mal${n}@suspicious-domain.example>`,
        'Content-Type: text/plain',
        '',
        'Settlement of the outstanding remittance requires immediate wire transfer authorisation to the updated beneficiary account.'
    ].join('\r\n');
}

function legitimateSample(n) {
    return [
        `From: "Priya Raman" <priya${n}@partner.example>`,
        'To: employee@company.example',
        `Subject: Planning notes ${n}`,
        `Message-ID: <ok${n}@partner.example>`,
        'Content-Type: text/plain',
        '',
        'Sharing the meeting summary and the delivery schedule we discussed during the review session.'
    ].join('\r\n');
}

test('engine refuses to score until it has enough labelled examples of both classes', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        const { threatObject, parsedEmail } = await analyze(phishingSample(1));
        const scored = adaptiveLearning.score(threatObject, parsedEmail);

        assert.strictEqual(scored.adaptive.status, 'INSUFFICIENT_TRAINING_DATA');
        assert.strictEqual(scored.adaptive.score, 0);
        assert.ok(scored.learning_features.length > 0, 'characteristics are still captured for later learning');
    });
});

test('characteristics of confirmed malicious mail are learned and recognised in a new message', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        for (let i = 0; i < 6; i++) {
            const { threatObject, parsedEmail } = await analyze(phishingSample(i));
            adaptiveLearning.learn(threatObject, parsedEmail, 'malicious', 'ANALYST_CONFIRMED');
        }
        for (let i = 0; i < 6; i++) {
            const { threatObject, parsedEmail } = await analyze(legitimateSample(i));
            adaptiveLearning.learn(threatObject, parsedEmail, 'benign', 'ANALYST_RELEASED');
        }

        assert.ok(adaptiveLearning.isReady(), 'engine should be ready after balanced labelled data');

        // A previously unseen message reusing the learned wording and sender domain.
        const { threatObject, parsedEmail } = await analyze(phishingSample(99));
        const scored = adaptiveLearning.score(threatObject, parsedEmail);

        assert.strictEqual(scored.adaptive.status, 'SCORED');
        assert.ok(scored.adaptive.score > 0.5, `expected a raised score, got ${scored.adaptive.score}`);
        assert.ok(scored.adaptive.contributions.length > 0, 'score must name the characteristics behind it');

        const named = scored.adaptive.contributions.map(c => c.characteristic);
        assert.ok(named.some(c => c.startsWith('token:') || c.startsWith('sender_domain:')),
            'learned characteristics should include wording or sender domain');
    });
});

test('a legitimate message is not raised by the learned model', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        for (let i = 0; i < 6; i++) {
            const mal = await analyze(phishingSample(i));
            adaptiveLearning.learn(mal.threatObject, mal.parsedEmail, 'malicious', 'ANALYST_CONFIRMED');
            const ben = await analyze(legitimateSample(i));
            adaptiveLearning.learn(ben.threatObject, ben.parsedEmail, 'benign', 'ANALYST_RELEASED');
        }

        const { threatObject, parsedEmail } = await analyze(legitimateSample(99));
        const scored = adaptiveLearning.score(threatObject, parsedEmail);

        assert.ok(scored.adaptive.score < 0.5, `legitimate mail should not be raised, got ${scored.adaptive.score}`);
    });
});

test('every learned contribution is explainable with its own evidence counts', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        for (let i = 0; i < 6; i++) {
            const mal = await analyze(phishingSample(i));
            adaptiveLearning.learn(mal.threatObject, mal.parsedEmail, 'malicious', 'ANALYST_CONFIRMED');
            const ben = await analyze(legitimateSample(i));
            adaptiveLearning.learn(ben.threatObject, ben.parsedEmail, 'benign', 'ANALYST_RELEASED');
        }

        const { threatObject, parsedEmail } = await analyze(phishingSample(50));
        const scored = adaptiveLearning.score(threatObject, parsedEmail);

        for (const contribution of scored.adaptive.contributions) {
            assert.ok(typeof contribution.characteristic === 'string');
            assert.ok(Number.isFinite(contribution.weight));
            assert.ok(Number.isInteger(contribution.seen_in_malicious));
            assert.ok(Number.isInteger(contribution.seen_in_legitimate));
        }

        const indicators = adaptiveLearning.getTopIndicators(10);
        assert.ok(indicators.length > 0, 'operator must be able to review what was learned');
        assert.ok(indicators.every(i => i.weight > 0));
    });
});

test('learning works from a stored case alone, without retaining message bodies', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        const { threatObject, parsedEmail } = await analyze(phishingSample(7));
        adaptiveLearning.score(threatObject, parsedEmail);

        // Simulate the stored case: raw message intentionally absent.
        const storedCase = { ...threatObject };
        delete storedCase._raw_email_string;
        delete storedCase._raw_data_model;

        const learned = adaptiveLearning.learn(storedCase, null, 'malicious', 'ANALYST_CONFIRMED');
        assert.ok(learned, 'an analyst decision made later must still be learnable');
        assert.ok(learned.characteristics_learned > 0);
        assert.strictEqual(adaptiveLearning.getStats().learned_from.malicious, 1);
    });
});

test('self-labelling only accepts corroborated high-confidence detections', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        const { threatObject, parsedEmail } = await analyze(phishingSample(8));

        threatObject.detection.verdict = 'HIGH_RISK';
        threatObject.confidence = { threat: 0.92, contributions: [{ family: 'LANGUAGE' }] };
        assert.strictEqual(adaptiveLearning.learnFromDetection(threatObject, parsedEmail), null,
            'a high score resting on one evidence family must not be self-labelled');

        threatObject.confidence = {
            threat: 0.92,
            contributions: [{ family: 'LANGUAGE' }, { family: 'AUTHENTICATION' }, { family: 'URL_RISK' }]
        };
        const learned = adaptiveLearning.learnFromDetection(threatObject, parsedEmail);
        assert.ok(learned, 'a corroborated detection across families should be self-labelled');
        assert.strictEqual(learned.source, 'HIGH_CONFIDENCE_DETECTION');
    });
});

test('the same message is never counted twice', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        const { threatObject, parsedEmail } = await analyze(phishingSample(20));
        threatObject.case_id = 'SM-TEST-DUPLICATE';

        const first = adaptiveLearning.learn(threatObject, parsedEmail, 'malicious', 'HIGH_CONFIDENCE_DETECTION');
        assert.ok(first.characteristics_learned > 0);
        assert.strictEqual(adaptiveLearning.getStats().learned_from.malicious, 1);

        // The analyst then confirms what the system already self-labelled.
        const second = adaptiveLearning.learn(threatObject, parsedEmail, 'malicious', 'ANALYST_CONFIRMED');
        assert.strictEqual(second.already_learned, true);
        assert.strictEqual(adaptiveLearning.getStats().learned_from.malicious, 1,
            'one message must still count as one example');
    });
});

test('an analyst overturning a verdict withdraws the lesson the system taught itself', async () => {
    await withIsolatedStores(async (adaptiveLearning) => {
        const { threatObject, parsedEmail } = await analyze(phishingSample(21));
        threatObject.case_id = 'SM-TEST-OVERTURNED';

        adaptiveLearning.learn(threatObject, parsedEmail, 'malicious', 'HIGH_CONFIDENCE_DETECTION');
        const sampleFeature = adaptiveLearning.extractFeatures(threatObject, parsedEmail)[0];
        assert.strictEqual(adaptiveLearning.features.get(sampleFeature).malicious, 1);

        // The analyst releases it: the earlier self-label was a false positive.
        const correction = adaptiveLearning.learn(threatObject, parsedEmail, 'benign', 'ANALYST_RELEASED');

        assert.strictEqual(correction.corrected_previous_label, 'malicious');
        assert.strictEqual(adaptiveLearning.getStats().learned_from.malicious, 0,
            'the incorrect malicious example must be withdrawn, not left in place');
        assert.strictEqual(adaptiveLearning.getStats().learned_from.legitimate, 1);
        assert.strictEqual(adaptiveLearning.features.get(sampleFeature).malicious, 0,
            'per-characteristic malicious counts must be rolled back too');
        assert.strictEqual(adaptiveLearning.features.get(sampleFeature).benign, 1);
    });
});

test('behavioural branch detects a known display name arriving from a new address', async () => {
    await withIsolatedStores(async (adaptiveLearning, behavioralAnalyzer) => {
        const legitimate = await analyze([
            'From: "Anita Desai" <anita@company.example>',
            'To: finance@company.example',
            'Subject: Budget review',
            'Message-ID: <b1@company.example>',
            'Content-Type: text/plain',
            '',
            'Attaching the budget review summary.'
        ].join('\r\n'));
        legitimate.threatObject.detection.verdict = 'SAFE';
        behavioralAnalyzer.recordObservation(legitimate.threatObject, legitimate.parsedEmail);

        // Same display name, different address - the classic known-contact impersonation.
        const impersonation = await analyze([
            'From: "Anita Desai" <anita.desai@company-payments.example>',
            'To: finance@company.example',
            'Subject: Updated bank details',
            'Message-ID: <b2@company-payments.example>',
            'Content-Type: text/plain',
            '',
            'Please update the payment details for this month.'
        ].join('\r\n'));

        const analyzed = behavioralAnalyzer.analyze(impersonation.threatObject, impersonation.parsedEmail);
        const types = analyzed.behavioral.signals.map(s => s.type);

        assert.ok(types.includes('DISPLAY_NAME_IMPERSONATION'),
            'a familiar display name from an unfamiliar address must be flagged');
        assert.ok(analyzed.behavioral.signals.find(s => s.type === 'DISPLAY_NAME_IMPERSONATION')
            .explanation.includes('anita@company.example'), 'explanation must name the address previously seen');
    });
});

test('behavioural baselines are not taught by high-risk mail', async () => {
    await withIsolatedStores(async (adaptiveLearning, behavioralAnalyzer) => {
        const malicious = await analyze(phishingSample(11));
        malicious.threatObject.detection.verdict = 'HIGH_RISK';
        behavioralAnalyzer.recordObservation(malicious.threatObject, malicious.parsedEmail);

        const followUp = await analyze(phishingSample(11));
        const analyzed = behavioralAnalyzer.analyze(followUp.threatObject, followUp.parsedEmail);

        // The sender was seen, but contributed nothing to the trusted baseline.
        assert.strictEqual(analyzed.behavioral.signals.filter(s => s.type === 'SENDER_INFRASTRUCTURE_CHANGE').length, 0);
        const stats = behavioralAnalyzer.getStats();
        assert.strictEqual(stats.display_names_tracked, 0,
            'a high-risk message must not add its display name to the trusted index');
    });
});
