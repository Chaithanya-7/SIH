const test = require('node:test');
const assert = require('node:assert');

const correlationGuard = require('../modules/correlationGuard');
const semanticCorrelation = require('../modules/semanticCorrelation');

const providerSendingObject = {
    infrastructure: {
        origin: {
            origin_provider: 'Google Mail Infrastructure',
            confidence_factors: [{ factor: 'CLIENT_IP_OBSCURED_BY_PROVIDER', status: 'SUPPORTED' }]
        }
    }
};

const attackerSendingObject = {
    infrastructure: {
        origin: {
            origin_provider: 'External Mail Infrastructure',
            confidence_factors: [{ factor: 'PUBLIC_ROUTABLE_CANDIDATE', status: 'SUPPORTED' }]
        }
    }
};

/**
 * The defect the original audit called out: shared provider infrastructure
 * tying unrelated victims into one fabricated campaign.
 */
test('consumer mail domains never link cases into a campaign', () => {
    ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com'].forEach(domain => {
        const verdict = correlationGuard.evaluateIndicator({
            type: 'DOMAIN', value: domain, sharedCaseCount: 3, threatObject: attackerSendingObject
        });
        assert.strictEqual(verdict.allowed, false, `${domain} must not correlate`);
        assert.match(verdict.reason, /consumer mail provider/);
    });
});

test('multi-tenant platform domains never link cases into a campaign', () => {
    ['drive.google.com', 'github.com', 'cdn.discordapp.com', 's3.amazonaws.com'].forEach(domain => {
        const verdict = correlationGuard.evaluateIndicator({
            type: 'DOMAIN', value: domain, sharedCaseCount: 2, threatObject: attackerSendingObject
        });
        assert.strictEqual(verdict.allowed, false, `${domain} must not correlate`);
        assert.match(verdict.reason, /multi-tenant platform/);
    });
});

test('large provider networks never link cases into a campaign', () => {
    ['AS15169 Google LLC', 'AS16509 Amazon', 'Cloudflare, Inc.', 'AS8075 Microsoft'].forEach(asn => {
        const verdict = correlationGuard.evaluateIndicator({
            type: 'ASN', value: asn, sharedCaseCount: 2, threatObject: attackerSendingObject
        });
        assert.strictEqual(verdict.allowed, false, `${asn} must not correlate`);
    });
});

test('a provider mail relay address does not link cases into a campaign', () => {
    const verdict = correlationGuard.evaluateIndicator({
        type: 'IP', value: '209.85.220.41', sharedCaseCount: 2, threatObject: providerSendingObject
    });
    assert.strictEqual(verdict.allowed, false);
    assert.match(verdict.reason, /shared provider mail infrastructure/);
});

test('an attacker-controlled domain and address still correlate normally', () => {
    const domain = correlationGuard.evaluateIndicator({
        type: 'DOMAIN', value: 'secure-login-verify.example', sharedCaseCount: 3, threatObject: attackerSendingObject
    });
    assert.strictEqual(domain.allowed, true, 'suppression must not disable genuine correlation');

    const ip = correlationGuard.evaluateIndicator({
        type: 'IP', value: '203.0.113.45', sharedCaseCount: 3, threatObject: attackerSendingObject
    });
    assert.strictEqual(ip.allowed, true);
});

/**
 * Prevalence adapts to a deployment, catching shared infrastructure that no
 * static list anticipated.
 */
test('a low-specificity indicator seen across many cases is treated as infrastructure', () => {
    const threshold = correlationGuard.PREVALENCE_CASE_THRESHOLD;

    const belowThreshold = correlationGuard.evaluateIndicator({
        type: 'DOMAIN', value: 'relay.unknown-provider.example', sharedCaseCount: threshold - 1, threatObject: attackerSendingObject
    });
    assert.strictEqual(belowThreshold.allowed, true);

    const atThreshold = correlationGuard.evaluateIndicator({
        type: 'DOMAIN', value: 'relay.unknown-provider.example', sharedCaseCount: threshold, threatObject: attackerSendingObject
    });
    assert.strictEqual(atThreshold.allowed, false);
    assert.match(atThreshold.reason, /shared infrastructure rather than one campaign/);
});

/**
 * The counterpart rule: a mass campaign genuinely does reuse one URL or payload
 * across many messages, so prevalence must not suppress those.
 */
test('a widely reused URL or payload hash is never suppressed by prevalence', () => {
    const url = correlationGuard.evaluateIndicator({
        type: 'URL', value: 'http://phish.example/login', sharedCaseCount: 500, threatObject: attackerSendingObject
    });
    assert.strictEqual(url.allowed, true, 'suppressing a reused phishing URL would break campaign detection');

    const hash = correlationGuard.evaluateIndicator({
        type: 'HASH', value: 'a'.repeat(64), sharedCaseCount: 500, threatObject: attackerSendingObject
    });
    assert.strictEqual(hash.allowed, true);
});

/**
 * One attacker host observed as an IP, a domain and a URL is a single
 * observation, not three independent confirmations.
 */
test('correlated infrastructure facts are grouped rather than summed', () => {
    const factors = [
        { factor: 'SHARED_IP', weight: 0.25 },
        { factor: 'SHARED_DOMAIN_INFRASTRUCTURE', weight: 0.25 },
        { factor: 'SHARED_ASN_PROVIDER', weight: 0.05 }
    ];
    const scored = correlationGuard.scoreFactors(factors);

    assert.ok(scored.confidence < 0.55, `three correlated infrastructure facts must not sum to 0.55, got ${scored.confidence}`);
    assert.ok(scored.confidence >= 0.25, 'the strongest fact should still count in full');

    const infra = scored.breakdown.find(b => b.family === 'INFRASTRUCTURE');
    assert.strictEqual(infra.strongest, 'SHARED_IP');
    assert.strictEqual(infra.supporting_count, 2);
});

test('independent evidence families do accumulate', () => {
    const scored = correlationGuard.scoreFactors([
        { factor: 'EXACT_HASH_MATCH', weight: 0.30 },
        { factor: 'SHARED_URL', weight: 0.25 },
        { factor: 'SHARED_SENDER_ADDRESS', weight: 0.20 }
    ]);

    assert.ok(scored.confidence > 0.6, `genuinely independent evidence should accumulate, got ${scored.confidence}`);
    assert.strictEqual(scored.breakdown.length, 3);
});

// ---------- semantic correlation ----------

test('messages reusing the same lure are matched on wording alone', () => {
    const lure = ['token:invoice', 'token:payment', 'token:urgent', 'token:remittance', 'token:beneficiary',
        'token:settlement', 'token:authorise', 'token:transfer', 'token:outstanding', 'token:account'];

    const current = { case_id: 'SM-NEW', learning_features: lure };
    const previous = { case_id: 'SM-OLD', learning_features: lure.slice(0, 9).concat(['token:wire']) };

    const a = semanticCorrelation.tokenSet(current.learning_features);
    const b = semanticCorrelation.tokenSet(previous.learning_features);
    const score = semanticCorrelation.jaccard(a, b);

    assert.ok(score >= semanticCorrelation.SIMILARITY_THRESHOLD,
        `reused lure wording should exceed the similarity threshold, got ${score}`);
    assert.ok(semanticCorrelation.sharedTerms(a, b).length > 0, 'the shared wording must be reportable');
});

test('unrelated business messages are not linked by ordinary wording', () => {
    const a = semanticCorrelation.tokenSet([
        'token:meeting', 'token:schedule', 'token:agenda', 'token:tuesday', 'token:notes',
        'token:review', 'token:timeline', 'token:delivery', 'token:summary'
    ]);
    const b = semanticCorrelation.tokenSet([
        'token:server', 'token:deployment', 'token:release', 'token:version', 'token:rollback',
        'token:staging', 'token:migration', 'token:database', 'token:config'
    ]);

    assert.ok(semanticCorrelation.jaccard(a, b) < semanticCorrelation.SIMILARITY_THRESHOLD,
        'unrelated messages must not be correlated');
});

test('a message with too little distinctive wording is not compared', () => {
    const result = semanticCorrelation.findSimilarCases(
        { case_id: 'SM-SHORT', learning_features: ['token:thanks', 'token:regards'] },
        null
    );
    assert.strictEqual(result.comparable, false);
    assert.strictEqual(result.matches.length, 0);
    assert.match(result.reason, /Too little distinctive wording/);
});
