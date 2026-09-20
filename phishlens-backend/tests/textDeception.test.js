const test = require('node:test');
const assert = require('node:assert');

const textDeception = require('../modules/textDeception');
const nlpAnalyzer = require('../modules/nlpAnalyzer');
const ruleEngine = require('../modules/ruleEngine');

const ZWSP = '​';
const ZWNJ = '‌';
const RLO = '‮';

/**
 * The premise behind this module, stated as a test.
 *
 * Attackers are said to have stopped using obvious keywords. Often they have
 * not - the keywords are simply arranged so a filter cannot see them, which
 * costs one line of code and defeats every substring match ever written.
 */

function analysed(parsedEmail) {
    let threatObject = {
        detection: {},
        nlp: {},
        message: { subject: parsedEmail.subject },
        iocs: { urls: [] },
        qr: { codes: [], not_scanned: [] }
    };
    threatObject = textDeception.analyze(threatObject, parsedEmail);
    threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
    return ruleEngine.evaluate(threatObject, parsedEmail);
}

function deceptionRules(result) {
    return result.detection.matched_rules.filter(r => r.id.startsWith('MQL-DECEPT')).map(r => r.id);
}

// ---------------------------------------------------------------------------
// The bypass this closes
// ---------------------------------------------------------------------------

/**
 * Measured on this analyser before the fix: two signals and a score of 0.48
 * became zero and zero, while the message rendered identically in every mail
 * client. The keyword layer was switchable off by the attacker at will.
 */
test('invisible characters no longer switch the language analysis off', () => {
    const sentence = 'Please verify your password immediately. This is your final notice to sign in to your account.';
    const obfuscated = sentence.split('').join(ZWSP);

    const plainResult = analysed({ subject: 'Account notice', textBody: sentence, from: { name: 'IT', address: 'a@b.test' } });
    const hiddenResult = analysed({ subject: 'Account notice', textBody: obfuscated, from: { name: 'IT', address: 'a@b.test' } });

    assert.ok(plainResult.nlp.signals.length >= 2, 'the plain sentence must be detected at all');
    assert.strictEqual(hiddenResult.nlp.signals.length, plainResult.nlp.signals.length,
        'obfuscated text must produce the same language signals as the text it renders as');
    assert.strictEqual(hiddenResult.nlp.score, plainResult.nlp.score);
});

test('normalisation restores the exact text a reader sees', () => {
    const sentence = 'Please verify your password immediately.';
    assert.strictEqual(textDeception.normalise(sentence.split('').join(ZWSP)), sentence);
    assert.strictEqual(textDeception.normalise(sentence), sentence, 'clean text must pass through unchanged');
});

test('lookalike letters fold to what they impersonate', () => {
    assert.strictEqual(textDeception.normalise('раypal.com'), 'paypal.com');
    assert.strictEqual(textDeception.normalise('micrоsоft.com'), 'microsoft.com');
    assert.strictEqual(textDeception.normalise('Аpple'), 'Apple');
    assert.strictEqual(textDeception.normalise('paypal.com'), 'paypal.com', 'a genuine domain must be untouched');
});

/** NFKC handles these exactly, without any lookup table. */
test('fullwidth and mathematical variants are folded', () => {
    assert.strictEqual(textDeception.normalise('ｐａｙｐａｌ'), 'paypal');
    assert.strictEqual(textDeception.normalise('\u{1D5C9}\u{1D5EE}\u{1D606}'), 'pay');
});

// ---------------------------------------------------------------------------
// The obfuscation is itself the finding
// ---------------------------------------------------------------------------

test('invisible characters scattered through the body are flagged', () => {
    const result = analysed({
        subject: 'Notice',
        textBody: 'Please verify your password'.split('').join(ZWSP),
        from: { name: 'IT', address: 'a@b.test' }
    });
    assert.ok(deceptionRules(result).includes('MQL-DECEPT-101'));
});

test('invisible characters in the subject or display name are flagged separately', () => {
    const result = analysed({
        subject: `Account${ZWSP} notice`,
        textBody: 'Hello',
        from: { name: 'Support', address: 'a@b.test' }
    });
    assert.ok(deceptionRules(result).includes('MQL-DECEPT-102'),
        'those two fields are shown before a message is opened');
});

test('a word mixing two alphabets is flagged and resolved', () => {
    const result = analysed({
        subject: 'Invoice',
        textBody: 'See attached',
        from: { name: 'Аpple Support', address: 'a@b.test' }
    });

    assert.ok(deceptionRules(result).includes('MQL-DECEPT-103'));
    const rule = result.detection.matched_rules.find(r => r.id === 'MQL-DECEPT-103');
    assert.match(rule.matched_because, /reads as "Apple"/);
});

/** The classic use: making a name display as though it ends in a different extension. */
test('a text-direction override is flagged', () => {
    const result = analysed({
        subject: `CV${RLO}fdp.exe`,
        textBody: 'Attached',
        from: { name: 'HR', address: 'a@b.test' }
    });
    assert.ok(deceptionRules(result).includes('MQL-DECEPT-104'));
});

// ---------------------------------------------------------------------------
// What must NOT be flagged
// ---------------------------------------------------------------------------

test('ordinary business correspondence is untouched', () => {
    const result = analysed({
        subject: 'Q3 planning notes',
        textBody: 'Hi, here are the notes from this morning. Let me know if anything needs changing before Thursday.',
        from: { name: 'Jane Patel', address: 'jane@corp.example' }
    });
    assert.deepStrictEqual(deceptionRules(result), []);
});

/**
 * The check is per word, not per message, precisely so this passes. A message
 * containing both English and Greek sentences is unremarkable; a single word
 * built from both alphabets is not.
 */
test('a genuinely non-Latin email is not mistaken for a homograph attack', () => {
    const result = analysed({
        subject: 'Re: Συνάντηση',
        textBody: 'Γεια σου, τα λέω αύριο.',
        from: { name: 'Γιώργος', address: 'g@corp.gr' }
    });
    assert.deepStrictEqual(deceptionRules(result), [],
        'writing in Greek is not deception');
});

/** Copying from a web page genuinely leaves one behind now and then. */
test('a single stray zero-width character is not treated as an attack', () => {
    const result = analysed({
        subject: 'Meeting',
        textBody: `Agenda attached${ZWSP}.`,
        from: { name: 'Sam', address: 's@corp.example' }
    });
    assert.ok(!deceptionRules(result).includes('MQL-DECEPT-101'));
});

test('joiners meaningful in other writing systems are not flagged on sight', () => {
    // ZWNJ is grammatically significant in Persian and several Indic scripts.
    const result = analysed({
        subject: 'Notes',
        textBody: `Here are the notes${ZWNJ} for review.`,
        from: { name: 'Priya', address: 'p@corp.example' }
    });
    assert.ok(!deceptionRules(result).includes('MQL-DECEPT-101'),
        'a single joiner is not an attack; scattering them through the text is');
});

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

test('a clean message says plainly that nothing was hidden', () => {
    let threatObject = textDeception.analyze({ message: {} }, {
        subject: 'Lunch', textBody: 'One o clock works.', from: { name: 'Ali', address: 'a@corp.example' }
    });
    assert.strictEqual(threatObject.text_deception.normalisation_changed_the_text, false);
    assert.match(threatObject.text_deception.summary, /means to a filter what it shows to a reader/);
});

test('the summary names what was concealed and what it resolves to', () => {
    let threatObject = textDeception.analyze({ message: {} }, {
        subject: 'Notice',
        textBody: 'verify your password'.split('').join(ZWSP),
        from: { name: 'Аpple', address: 'a@b.test' }
    });
    const summary = threatObject.text_deception.summary;
    assert.match(summary, /invisible/);
    assert.match(summary, /reads as "Apple"/);
});
