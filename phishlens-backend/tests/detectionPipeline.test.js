const test = require('node:test');
const assert = require('node:assert');

const emailParser = require('../modules/emailParser');
const mqlBridge = require('../modules/mqlBridge');
const authAnalyzer = require('../modules/authAnalyzer');
const attachmentAnalyzer = require('../modules/attachmentAnalyzer');
const iocExtractor = require('../modules/iocExtractor');
const nlpAnalyzer = require('../modules/nlpAnalyzer');
const ruleEngine = require('../modules/ruleEngine');
const evidenceFusion = require('../modules/evidenceFusion');
const confidenceEngine = require('../modules/confidenceEngine');

/**
 * These fixtures are synthetic. They exercise the detection pipeline offline:
 * authentication results are injected directly rather than calling
 * authAnalyzer.analyze(), which performs live DNS lookups. authAnalyzer's own
 * header parsing is covered separately below as a pure function.
 */
function buildRaw(lines, body) {
    return `${lines.join('\r\n')}\r\n\r\n${body}`;
}

/** Runs the offline portion of the pipeline: parse -> normalize -> analyze -> rules -> score. */
async function runPipeline(raw, authentication) {
    const parsedEmail = await emailParser.parse(raw);
    let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
    threatObject.forensics.authentication = authentication;
    threatObject = await attachmentAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = iocExtractor.extract(threatObject, parsedEmail);
    threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = ruleEngine.evaluate(threatObject, parsedEmail);
    threatObject = evidenceFusion.fuse(threatObject);
    threatObject = confidenceEngine.calculate(threatObject);
    return threatObject;
}

const PASSING_AUTH = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } };
const FAILING_AUTH = { spf: 'fail', dkim: 'fail', dmarc: 'fail', dmarc_policy: { status: 'AVAILABLE', policy: 'reject' } };

test('credential-phishing message matches the expected native MQL rules and scores HIGH_RISK', async () => {
    const raw = buildRaw([
        'From: "PayPal Security" <billing-notice@gmail.com>',
        'Reply-To: recovery-desk@unrelated-domain.example',
        'To: employee@company.example',
        'Subject: Urgent: verify your account today',
        'Message-ID: <case1@gmail.com>',
        'Date: Mon, 1 Sep 2026 10:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'Dear Customer,',
        'Unusual activity detected on your account. Your account will be suspended unless you act now.',
        'Please login to your account and confirm your password here: http://203.0.113.45/verify',
        'Click here immediately to avoid interruption.'
    ].join('\r\n'));

    const result = await runPipeline(raw, FAILING_AUTH);
    const ruleIds = result.detection.matched_rules.map(r => r.id);

    assert.ok(ruleIds.includes('MQL-DOM-101'), 'brand display name from a free-mail domain should match');
    assert.ok(ruleIds.includes('MQL-AUTH-101'), 'Reply-To domain mismatch should match');
    assert.ok(ruleIds.includes('MQL-URL-101'), 'raw IP-literal link should match');
    assert.ok(ruleIds.includes('MQL-NLP-101'), 'credential request + link call-to-action should match');
    assert.ok(ruleIds.includes('MQL-AUTH-104'), 'DMARC failure against an enforcing policy should match');
    assert.strictEqual(result.detection.verdict, 'HIGH_RISK');
    assert.strictEqual(result.detection.verification_status, 'PHISHLENS_NATIVE_MQL_VERIFIED');
});

test('every matched rule carries a citable source and a specific reason', async () => {
    const raw = buildRaw([
        'From: "Microsoft Support" <no-reply@gmail.com>',
        'To: employee@company.example',
        'Subject: Action required',
        'Message-ID: <case2@gmail.com>',
        'Content-Type: text/plain'
    ], 'Please review the document at http://bit.ly/abc123 immediately.');

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.ok(result.detection.matched_rules.length > 0, 'expected at least one rule to match');
    for (const rule of result.detection.matched_rules) {
        assert.ok(rule.source && rule.source.length > 5, `rule ${rule.id} must cite a source`);
        assert.ok(rule.matched_because && rule.matched_because.length > 5, `rule ${rule.id} must explain why it matched`);
        assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(rule.severity));
    }
});

test('BEC gift-card request with urgency is detected through combined NLP signals', async () => {
    const raw = buildRaw([
        'From: "Chief Executive" <ceo@company-invoices.example>',
        'Reply-To: ceo.private@unrelated-domain.example',
        'To: finance@company.example',
        'Subject: Quick task',
        'Message-ID: <case3@company-invoices.example>',
        'Content-Type: text/plain'
    ], 'I need you to process payment urgently. Please purchase gift cards and keep this confidential.');

    const result = await runPipeline(raw, PASSING_AUTH);
    const ruleIds = result.detection.matched_rules.map(r => r.id);
    const nlpTypes = result.nlp.signals.map(s => s.type);

    assert.ok(nlpTypes.includes('GIFT_CARD_REQUEST'), 'gift-card language should be identified');
    assert.ok(nlpTypes.includes('SECRECY_PRESSURE'), 'secrecy language should be identified');
    assert.ok(ruleIds.includes('MQL-NLP-102'), 'financial pressure + urgency combination should match');
    assert.ok(ruleIds.includes('MQL-NLP-103'), 'impersonation language + Reply-To mismatch should match');
    assert.ok(ruleIds.includes('MQL-NLP-104'), 'secrecy pressure should match');
    assert.strictEqual(result.detection.verdict, 'HIGH_RISK');
});

test('executable attachment is detected and hashed without being executed', async () => {
    const payload = Buffer.from('this is inert test content, not an executable').toString('base64');
    const raw = [
        'From: "Accounts" <billing@supplier.example>',
        'To: employee@company.example',
        'Subject: Invoice',
        'Message-ID: <case4@supplier.example>',
        'Content-Type: multipart/mixed; boundary="X-BOUNDARY"',
        '',
        '--X-BOUNDARY',
        'Content-Type: text/plain',
        '',
        'Please see the attached invoice.',
        '--X-BOUNDARY',
        'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
        'Content-Transfer-Encoding: base64',
        'Content-Disposition: attachment; filename="invoice.pdf.exe"',
        '',
        payload,
        '--X-BOUNDARY--'
    ].join('\r\n');

    const result = await runPipeline(raw, PASSING_AUTH);
    const ruleIds = result.detection.matched_rules.map(r => r.id);

    assert.strictEqual(result.attachments.length, 1);
    assert.strictEqual(result.attachments[0].file_name, 'invoice.pdf.exe');
    // Was METADATA_ONLY, when attachments were described and never opened. The
    // bytes are now read - still never executed - so the status changed with it.
    assert.strictEqual(result.attachments[0].analysis_status, 'CONTENT_INSPECTED');
    assert.match(result.attachments[0].sha256, /^[a-f0-9]{64}$/);

    // The name alone already matched a rule. Reading the file adds what the name
    // cannot settle: this particular payload is inert text, so the inspector must
    // report the misleading name without claiming to have found a program.
    const findings = result.attachments[0].findings.map(f => f.code);
    assert.ok(findings.includes('DOUBLE_EXTENSION'), 'the hidden second extension is a property of the name');
    assert.ok(findings.includes('EXECUTABLE_ATTACHMENT'), 'a .exe is run rather than opened');
    assert.strictEqual(result.attachments[0].format.detected, 'UNRECOGNISED', 'the test payload is inert text, and must not be reported as a program');
    assert.strictEqual(result.attachments[0].macro_analysis, null, 'nothing here carries macros');
    assert.ok(ruleIds.includes('MQL-ATT-101'), 'executable-class extension should match');
    assert.ok(ruleIds.includes('MQL-ATT-103'), 'double extension should match');
    assert.ok(result.iocs.hashes.includes(result.attachments[0].sha256), 'attachment hash should be an IOC');
});

test('ordinary business correspondence is not flagged as a threat', async () => {
    const raw = buildRaw([
        'From: "Priya Raman" <priya.raman@partner.example>',
        'To: employee@company.example',
        'Subject: Notes from Tuesday planning call',
        'Message-ID: <case5@partner.example>',
        'Date: Mon, 1 Sep 2026 10:00:00 +0000',
        'Content-Type: text/plain'
    ], 'Thanks for the discussion. I have summarized the timeline we agreed on and will send the draft schedule next week.');

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.strictEqual(result.detection.matched_rules.length, 0, 'benign mail should match no rules');
    assert.strictEqual(result.nlp.signals.length, 0, 'benign mail should raise no language signals');
    assert.strictEqual(result.detection.verdict, 'SAFE');
});

test('pipeline produces a populated case with no external detection provider configured', async () => {
    const raw = buildRaw([
        'From: "Ravi Kumar" <ravi@partner.example>',
        'To: employee@company.example',
        'Subject: Quarterly report',
        'Message-ID: <case6@partner.example>',
        'Content-Type: text/plain'
    ], 'Attaching the quarterly summary for review.');

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.strictEqual(result.detection.provider, 'PHISHLENS_NATIVE_MQL');
    assert.strictEqual(result.detection.external_provider_result.attempted, false);
    assert.strictEqual(result.message.sender, 'Ravi Kumar <ravi@partner.example>');
    assert.strictEqual(result.message.subject, 'Quarterly report');
    assert.match(result.message.raw_hash, /^[a-f0-9]{64}$/);
});

/**
 * False-positive guards. A detection tool that flags ordinary mail is worse than
 * useless in a SOC, so these legitimate-but-noisy messages must stay below the
 * HIGH_RISK threshold even though they contain individually suspicious-looking
 * language ("click here", "reset your password", "act now", "process payment").
 */
test('legitimate password-reset notification is not escalated to HIGH_RISK', async () => {
    const raw = buildRaw([
        'From: "GitHub" <noreply@github.example>',
        'To: employee@company.example',
        'Subject: Password reset request',
        'Message-ID: <fp1@github.example>',
        'Content-Type: text/plain'
    ], 'We received a request to reset your password. Click here to reset your password. If you did not request this, you can ignore this email.');

    const result = await runPipeline(raw, PASSING_AUTH);
    assert.notStrictEqual(result.detection.verdict, 'HIGH_RISK');
});

test('legitimate marketing mail with urgency language is not escalated to HIGH_RISK', async () => {
    const raw = buildRaw([
        'From: "Shop Deals" <news@retailer.example>',
        'To: employee@company.example',
        'Subject: Final notice: sale ends today',
        'Message-ID: <fp2@retailer.example>',
        'Content-Type: text/plain'
    ], 'Dear Customer, act now! Our sale ends today. View the deals at https://retailer.example/sale');

    const result = await runPipeline(raw, PASSING_AUTH);
    assert.notStrictEqual(result.detection.verdict, 'HIGH_RISK');
});

test('genuine internal payment request without BEC indicators is not escalated', async () => {
    const raw = buildRaw([
        'From: "Anita Desai" <anita@company.example>',
        'To: finance@company.example',
        'Subject: Invoice payment for vendor',
        'Message-ID: <fp3@company.example>',
        'Content-Type: text/plain'
    ], 'Please process payment for the vendor invoice by Friday as agreed in the contract.');

    const result = await runPipeline(raw, PASSING_AUTH);
    const ruleIds = result.detection.matched_rules.map(r => r.id);

    assert.ok(!ruleIds.includes('MQL-BEC-101'), 'a single financial mention must not trigger the BEC composite');
    assert.notStrictEqual(result.detection.verdict, 'HIGH_RISK');
});

test('Authentication-Results header parsing follows RFC 8601 result tokens', () => {
    const parsed = authAnalyzer.parseAuthenticationResults(
        'mx.google.com; spf=fail smtp.mailfrom=evil.example; dkim=pass header.i=@evil.example; dmarc=fail header.from=evil.example'
    );
    assert.strictEqual(parsed.spf, 'fail');
    assert.strictEqual(parsed.dkim, 'pass');
    assert.strictEqual(parsed.dmarc, 'fail');
    assert.strictEqual(parsed.authserv_id, 'mx.google.com');
});

test('absent Authentication-Results header yields unknown rather than a fabricated result', () => {
    const parsed = authAnalyzer.parseAuthenticationResults(undefined);
    assert.strictEqual(parsed.spf, 'unknown');
    assert.strictEqual(parsed.dkim, 'unknown');
    assert.strictEqual(parsed.dmarc, 'unknown');
});
