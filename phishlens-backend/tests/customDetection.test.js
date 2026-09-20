const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, '../data/custom_detection.json');

/** Runs against an isolated config file so the operator's own rules are untouched. */
async function withIsolatedConfig(run) {
    const saved = fs.existsSync(CONFIG_FILE) ? fs.readFileSync(CONFIG_FILE, 'utf8') : null;
    if (saved !== null) fs.unlinkSync(CONFIG_FILE);

    ['../modules/customDetectionConfig', '../modules/ruleEngine', '../modules/nlpAnalyzer']
        .forEach(m => delete require.cache[require.resolve(m)]);
    const config = require('../modules/customDetectionConfig');
    const ruleEngine = require('../modules/ruleEngine');
    const nlpAnalyzer = require('../modules/nlpAnalyzer');

    try {
        return await run(config, ruleEngine, nlpAnalyzer);
    } finally {
        if (saved === null) { if (fs.existsSync(CONFIG_FILE)) fs.unlinkSync(CONFIG_FILE); }
        else fs.writeFileSync(CONFIG_FILE, saved);
        ['../modules/customDetectionConfig', '../modules/ruleEngine', '../modules/nlpAnalyzer']
            .forEach(m => delete require.cache[require.resolve(m)]);
    }
}

const VALID_RULE = {
    id: 'CUSTOM-GIFTCARD-01',
    name: 'Gift card request from an external sender',
    severity: 'HIGH',
    confidence: 0.8,
    source: 'Internal threat brief, September 2026',
    description: 'Finance reported repeated gift-card requests from lookalike external senders.',
    conditions: {
        all: [
            { field: 'subject_and_body', op: 'contains_any', value: ['gift card', 'giftcard'] },
            { field: 'sender_domain', op: 'not_equals', value: 'company.example' }
        ]
    }
};

test('a valid operator rule is accepted and persisted', async () => {
    await withIsolatedConfig(async (config) => {
        const result = config.addRule(VALID_RULE);
        assert.strictEqual(result.ok, true);
        assert.strictEqual(config.getAll().totals.mql_rules, 1);
        assert.ok(fs.existsSync(CONFIG_FILE), 'configuration must persist to disk');
    });
});

test('a rule without a cited source is rejected', async () => {
    await withIsolatedConfig(async (config) => {
        const { source, ...noSource } = VALID_RULE;
        const result = config.addRule(noSource);
        assert.strictEqual(result.ok, false);
        assert.ok(result.errors.some(e => /source is required/.test(e)),
            'custom rules must stay as auditable as the built-in ones');
    });
});

test('invalid severity, confidence, field and operator are all rejected', async () => {
    await withIsolatedConfig(async (config) => {
        assert.strictEqual(config.addRule({ ...VALID_RULE, severity: 'SEVERE' }).ok, false);
        assert.strictEqual(config.addRule({ ...VALID_RULE, confidence: 5 }).ok, false);
        assert.strictEqual(config.addRule({
            ...VALID_RULE,
            conditions: { all: [{ field: 'not_a_field', op: 'contains', value: 'x' }] }
        }).ok, false);
        assert.strictEqual(config.addRule({
            ...VALID_RULE,
            conditions: { all: [{ field: 'subject', op: 'no_such_operator', value: 'x' }] }
        }).ok, false);
    });
});

/**
 * The whole point of the declarative schema: operator-supplied content must
 * never become executable code, or anyone who can reach the API or drop a file
 * in the data directory gains remote code execution.
 */
test('operator-supplied content is never executed as code', async () => {
    await withIsolatedConfig(async (config) => {
        const injection = {
            ...VALID_RULE,
            id: 'CUSTOM-INJECT-01',
            conditions: { all: [{ field: 'subject', op: 'contains', value: 'x' }] }
        };
        assert.strictEqual(config.addRule(injection).ok, true);

        // A rule carrying a JS payload in place of conditions must be refused,
        // not evaluated.
        global.__phishlens_pwned = false;
        const codeRule = {
            ...VALID_RULE,
            id: 'CUSTOM-INJECT-02',
            conditions: { test: "global.__phishlens_pwned = true; return true;" }
        };
        assert.strictEqual(config.addRule(codeRule).ok, false, 'a code-shaped condition must be rejected');

        config.evaluate({ test: "global.__phishlens_pwned = true" }, { subject: 'anything' });
        assert.strictEqual(global.__phishlens_pwned, false, 'nothing supplied by an operator may execute');
        delete global.__phishlens_pwned;
    });
});

test('regex patterns prone to catastrophic backtracking are refused', async () => {
    await withIsolatedConfig(async (config) => {
        const dangerous = config.addRule({
            ...VALID_RULE,
            id: 'CUSTOM-REDOS-01',
            conditions: { all: [{ field: 'subject', op: 'matches_regex', value: '(a+)+$' }] }
        });
        assert.strictEqual(dangerous.ok, false, 'a nested-quantifier pattern would hang analysis of every message');

        const safe = config.addRule({
            ...VALID_RULE,
            id: 'CUSTOM-REGEX-OK',
            conditions: { all: [{ field: 'subject', op: 'matches_regex', value: 'invoice[0-9]{3}' }] }
        });
        assert.strictEqual(safe.ok, true);
    });
});

test('condition operators evaluate correctly over a message context', async () => {
    await withIsolatedConfig(async (config) => {
        const ctx = {
            subject: 'Urgent gift card purchase',
            body: 'Please buy gift cards today',
            senderAddress: 'ceo@external.example',
            senderDomain: 'external.example',
            senderDisplayName: 'Chief Executive',
            replyToDomain: 'other.example',
            urls: ['https://a.example/x', 'https://b.example/y'],
            urlHosts: ['a.example', 'b.example'],
            attachmentNames: ['invoice.pdf'],
            attachmentExtensions: ['pdf'],
            auth: { spf: 'fail', dkim: 'pass', dmarc: 'fail' },
            nlpSignals: ['URGENCY_PRESSURE', 'GIFT_CARD_REQUEST'],
            matchedRuleIds: ['MQL-AUTH-101'],
            senderDomainAgeDays: 4
        };

        assert.strictEqual(config.evaluate({ field: 'subject', op: 'contains', value: 'gift card' }, ctx), true);
        assert.strictEqual(config.evaluate({ field: 'sender_domain', op: 'not_equals', value: 'company.example' }, ctx), true);
        assert.strictEqual(config.evaluate({ field: 'nlp_signals', op: 'includes_any', value: ['GIFT_CARD_REQUEST'] }, ctx), true);
        assert.strictEqual(config.evaluate({ field: 'nlp_signals', op: 'includes_all', value: ['GIFT_CARD_REQUEST', 'NOT_PRESENT'] }, ctx), false);
        assert.strictEqual(config.evaluate({ field: 'url_count', op: 'gte', value: 2 }, ctx), true);
        assert.strictEqual(config.evaluate({ field: 'sender_domain_age_days', op: 'lt', value: 30 }, ctx), true);
        assert.strictEqual(config.evaluate({ field: 'spf', op: 'equals', value: 'fail' }, ctx), true);
        assert.strictEqual(config.evaluate({ not: { field: 'subject', op: 'contains', value: 'nothing' } }, ctx), true);
        assert.strictEqual(config.evaluate({
            any: [
                { field: 'subject', op: 'contains', value: 'absent' },
                { field: 'dmarc', op: 'equals', value: 'fail' }
            ]
        }, ctx), true);
    });
});

test('a custom rule fires end to end and carries its operator attribution', async () => {
    await withIsolatedConfig(async (config, ruleEngine) => {
        config.addRule(VALID_RULE);

        const emailParser = require('../modules/emailParser');
        const mqlBridge = require('../modules/mqlBridge');
        const nlpAnalyzer = require('../modules/nlpAnalyzer');

        const raw = [
            'From: "Chief Executive" <ceo@lookalike.example>',
            'To: finance@company.example',
            'Subject: Quick favour',
            'Message-ID: <cust1@lookalike.example>',
            'Content-Type: text/plain',
            '',
            'Please purchase a gift card for the team today.'
        ].join('\r\n');

        const parsedEmail = await emailParser.parse(raw);
        let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
        threatObject.forensics.authentication = { spf: 'pass', dkim: 'pass', dmarc: 'pass' };
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'message');
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');

        const custom = threatObject.detection.matched_rules.find(r => r.id === 'CUSTOM-GIFTCARD-01');
        assert.ok(custom, 'the operator rule should fire on a matching message');
        assert.strictEqual(custom.category, 'CUSTOM');
        assert.match(custom.source, /^Operator-defined:/);
        assert.strictEqual(custom.decisive, false, 'a rule that did not ask to be decisive must not be');
    });
});

test('a rule may be decisive only when explicitly declared CRITICAL', async () => {
    await withIsolatedConfig(async (config) => {
        const careless = config.addRule({ ...VALID_RULE, id: 'CUSTOM-DEC-01', decisive: true, severity: 'HIGH' });
        assert.strictEqual(careless.ok, false, 'decisive must not be attachable to a non-critical rule');
        assert.ok(careless.errors.some(e => /CRITICAL/.test(e)));

        const deliberate = config.addRule({ ...VALID_RULE, id: 'CUSTOM-DEC-02', decisive: true, severity: 'CRITICAL' });
        assert.strictEqual(deliberate.ok, true, 'an operator may deliberately make their own rule decisive');

        assert.strictEqual(config.addRule({ ...VALID_RULE, id: 'CUSTOM-DEC-03', decisive: 'yes' }).ok, false);
    });
});

test('a custom rule does not fire on a message it does not match', async () => {
    await withIsolatedConfig(async (config, ruleEngine) => {
        config.addRule(VALID_RULE);

        const emailParser = require('../modules/emailParser');
        const mqlBridge = require('../modules/mqlBridge');
        const nlpAnalyzer = require('../modules/nlpAnalyzer');

        const raw = [
            'From: "Priya Raman" <priya@partner.example>',
            'To: employee@company.example',
            'Subject: Planning notes',
            'Message-ID: <cust2@partner.example>',
            'Content-Type: text/plain',
            '',
            'Sharing the delivery schedule we agreed.'
        ].join('\r\n');

        const parsedEmail = await emailParser.parse(raw);
        let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
        threatObject.forensics.authentication = { spf: 'pass', dkim: 'pass', dmarc: 'pass' };
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');

        assert.ok(!threatObject.detection.matched_rules.some(r => r.id === 'CUSTOM-GIFTCARD-01'));
    });
});

test('a custom language pattern is analysed alongside the built-in ones', async () => {
    await withIsolatedConfig(async (config, ruleEngine, nlpAnalyzer) => {
        const added = config.addNlpPattern({
            type: 'CRYPTO_WALLET_LURE',
            severity: 'HIGH',
            confidence: 0.8,
            terms: ['seed phrase', 'wallet recovery'],
            explanation: 'Requests for wallet recovery material are used to drain cryptocurrency accounts.',
            source: 'Operator-defined'
        });
        assert.strictEqual(added.ok, true);

        const emailParser = require('../modules/emailParser');
        const mqlBridge = require('../modules/mqlBridge');

        const raw = [
            'From: "Support" <help@wallet-recovery.example>',
            'To: employee@company.example',
            'Subject: Account recovery',
            'Message-ID: <cust3@wallet-recovery.example>',
            'Content-Type: text/plain',
            '',
            'Confirm your seed phrase to complete wallet recovery.'
        ].join('\r\n');

        const parsedEmail = await emailParser.parse(raw);
        let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);

        const signal = threatObject.nlp.signals.find(s => s.type === 'CRYPTO_WALLET_LURE');
        assert.ok(signal, 'the operator-defined language pattern should produce a signal');
        assert.deepStrictEqual(signal.matched_terms.sort(), ['seed phrase', 'wallet recovery']);
        assert.match(signal.source, /^Operator-defined:/);
    });
});

test('an invalid language pattern is rejected', async () => {
    await withIsolatedConfig(async (config) => {
        assert.strictEqual(config.addNlpPattern({ type: 'lowercase', terms: ['x'], severity: 'HIGH', confidence: 0.5, explanation: 'long enough explanation' }).ok, false);
        assert.strictEqual(config.addNlpPattern({ type: 'NO_TERMS', terms: [], severity: 'HIGH', confidence: 0.5, explanation: 'long enough explanation' }).ok, false);
        assert.strictEqual(config.addNlpPattern({ type: 'NO_EXPLANATION', terms: ['x'], severity: 'HIGH', confidence: 0.5 }).ok, false);
    });
});

test('operator indicators take effect even with no feed ever synchronised', async () => {
    await withIsolatedConfig(async (config) => {
        delete require.cache[require.resolve('../modules/threatIntelStore')];
        const store = require('../modules/threatIntelStore');
        store.urls = new Set();
        store.urlHosts = new Map();
        store.domains = new Map();
        store.ips = new Map();
        store.cidrs = [];
        store.lastSync = null;

        assert.strictEqual(store.isSynced(), false);
        config.addIndicators({ domains: ['known-bad.example'], ips: ['203.0.113.55'], urls: ['http://bad.example/x'] });

        assert.strictEqual(store.lookupDomain('known-bad.example').feed, 'operator_defined');
        assert.strictEqual(store.lookupIp('203.0.113.55').feed, 'operator_defined');
        assert.strictEqual(store.lookupUrl('http://bad.example/x').feed, 'operator_defined');
        assert.strictEqual(store.lookupDomain('unrelated.example'), null);

        delete require.cache[require.resolve('../modules/threatIntelStore')];
    });
});

test('a malformed entry is skipped and reported without disabling the rest', async () => {
    await withIsolatedConfig(async (config) => {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify({
            mql_rules: [VALID_RULE, { id: 'BROKEN', name: 'no conditions or source' }],
            nlp_patterns: [],
            indicators: { urls: [], domains: [], ips: [] }
        }, null, 2));

        config.load();

        assert.strictEqual(config.rules.length, 1, 'the valid rule must survive');
        assert.strictEqual(config.rules[0].id, 'CUSTOM-GIFTCARD-01');
        assert.ok(config.loadErrors.length > 0, 'the invalid rule must be reported, not silently dropped');
        assert.strictEqual(config.loadErrors[0].id, 'BROKEN');
    });
});
