import test from 'node:test';
import assert from 'node:assert';
import { compileFilter, fieldSuggestions, FILTER_EXAMPLES, FIELDS } from '../src/services/displayFilter.js';

/**
 * The display filter for the mail flow list.
 *
 * ## Why this is tested harder than a search box would be
 *
 * The filter decides which mail an analyst sees. There is one failure mode that
 * matters more than all the others: **a broken expression must never silently
 * behave like a working one.** If `verdict == HIGH_RSK` (a typo) quietly matched
 * nothing, the list would come back empty and read as "no dangerous mail" - a
 * reassuring, confident, wrong answer produced by a spelling mistake.
 *
 * So every invalid expression has to return an error the interface can show, and
 * the interface has to keep displaying the unfiltered list while it is invalid.
 * Several tests below exist only to pin that down.
 */

const row = (over = {}) => ({
    no: 1,
    case_id: 'SM-1',
    colour: 'GREEN',
    severity: 'LOW',
    verdict: 'SAFE',
    name: 'Quarterly report attached',
    sender: 'priya@supplier.example',
    recipient: 'me@company.example',
    source: '203.0.113.5',
    source_host: 'mta.supplier.example',
    source_country: 'India',
    source_asn: 'AS64500',
    source_port: null,
    destination: '198.51.100.2',
    destination_host: 'mx.company.example',
    destination_port: 2525,
    protocol: 'ESMTPS',
    channel: 'SMTP_GATEWAY',
    length: 20481,
    confidence: 0.05,
    info: '9 checks clean',
    attachments: 1,
    rules_matched: 0,
    connection_observed: false,
    analysis_mode: 'LIVE',
    ...over
});

const matches = (expression, r) => {
    const compiled = compileFilter(expression);
    assert.ok(!compiled.error, `"${expression}" should compile, got: ${compiled.error?.message}`);
    return compiled.test(r);
};

// ---------------------------------------------------------------------------
// The failure mode that matters
// ---------------------------------------------------------------------------

test('an invalid expression reports an error rather than matching nothing', () => {
    // A typo that quietly matched nothing would render an empty list, and an
    // empty list reads as "no dangerous mail found".
    for (const bad of ['verdct == SAFE', 'verdict ==', 'verdict == SAFE &&', '(verdict == SAFE', 'verdict @@ SAFE']) {
        const compiled = compileFilter(bad);
        assert.ok(compiled.error, `"${bad}" must be reported as invalid`);
        assert.ok(compiled.error.message, 'and must say what is wrong');
    }
});

test('an unknown field is named, not ignored', () => {
    const compiled = compileFilter('subjekt contains invoice');
    assert.ok(compiled.error);
    assert.match(compiled.error.message, /no field called "subjekt"/i);
    assert.strictEqual(typeof compiled.error.at, 'number', 'and it must say where, for the bar to point at it');
});

test('a bad regular expression is an error, not a crash', () => {
    const compiled = compileFilter('subject matches "([unclosed"');
    assert.ok(compiled.error);
    assert.match(compiled.error.message, /regular expression/i);
});

test('an empty filter shows everything and is not an error', () => {
    const compiled = compileFilter('   ');
    assert.ok(!compiled.error);
    assert.strictEqual(compiled.empty, true);
    assert.strictEqual(compiled.test(row()), true);
});

test('compiling never throws, whatever is typed', () => {
    // It runs on every keystroke, so every half-finished expression passes
    // through it.
    const partials = ['v', 've', 'verdict', 'verdict ', 'verdict =', 'verdict ==', 'verdict == H', '!', '!(', '&&', '""', "'", '((()))', 'a b c d'];
    for (const p of partials) {
        assert.doesNotThrow(() => compileFilter(p), `"${p}" must not throw`);
    }
});

// ---------------------------------------------------------------------------
// The language
// ---------------------------------------------------------------------------

test('equality, inequality and case-insensitive text', () => {
    assert.strictEqual(matches('verdict == SAFE', row()), true);
    assert.strictEqual(matches('verdict == safe', row()), true, 'values are matched case-insensitively');
    assert.strictEqual(matches('verdict != SAFE', row()), false);
    assert.strictEqual(matches('verdict == HIGH_RISK', row({ verdict: 'HIGH_RISK' })), true);
});

test('contains and matches', () => {
    assert.strictEqual(matches('subject contains report', row()), true);
    assert.strictEqual(matches('subject contains REPORT', row()), true);
    assert.strictEqual(matches('subject contains invoice', row()), false);
    assert.strictEqual(matches('sender matches "@supplier\\.example$"', row()), true);
    assert.strictEqual(matches('sender matches "^admin"', row()), false);
});

test('numeric comparison, and quoted values keeping their spaces', () => {
    assert.strictEqual(matches('dport == 2525', row()), true);
    assert.strictEqual(matches('dport > 1024', row()), true);
    assert.strictEqual(matches('len >= 20481', row()), true);
    assert.strictEqual(matches('attachments > 0', row()), true);
    assert.strictEqual(matches('subject contains "Quarterly report"', row()), true,
        'a quoted value keeps its spaces, which is how a subject is matched');
});

test('a bare field name means the row has a value for it', () => {
    // As in Wireshark: `tcp` means "this frame has a TCP layer".
    assert.strictEqual(matches('sport', row()), false, 'no source port was recorded');
    assert.strictEqual(matches('sport', row({ source_port: 49152 })), true);
    assert.strictEqual(matches('conn', row({ connection_observed: true })), true);
    assert.strictEqual(matches('conn', row()), false);
});

test('a missing numeric field matches no comparison at all', () => {
    // The trap: treating an unrecorded port as zero would make `sport < 1024`
    // true for the great majority of mail, which never records one.
    const r = row({ source_port: null });
    assert.strictEqual(matches('sport < 1024', r), false);
    assert.strictEqual(matches('sport > 0', r), false);
    assert.strictEqual(matches('sport == 0', r), false);
});

test('and, or, not, and brackets', () => {
    const dangerous = row({ verdict: 'HIGH_RISK', colour: 'RED', attachments: 2 });

    assert.strictEqual(matches('verdict == HIGH_RISK && attachments > 1', dangerous), true);
    assert.strictEqual(matches('verdict == HIGH_RISK && attachments > 5', dangerous), false);
    assert.strictEqual(matches('verdict == SAFE || verdict == HIGH_RISK', dangerous), true);
    assert.strictEqual(matches('!(verdict == SAFE)', dangerous), true);
    assert.strictEqual(matches('not verdict == SAFE', dangerous), true);
    assert.strictEqual(matches('proto == ESMTPS and dport == 2525', dangerous), true);

    // Brackets must actually group, or a filter reads as the opposite of itself.
    assert.strictEqual(matches('(verdict == SAFE || verdict == SUSPICIOUS) && attachments > 1', dangerous), false);
    assert.strictEqual(matches('(verdict == SAFE || verdict == HIGH_RISK) && attachments > 1', dangerous), true);
});

test('and binds tighter than or', () => {
    // `a || b && c` must be `a || (b && c)`. Getting this backwards silently
    // changes what every compound filter means.
    const r = row({ verdict: 'SAFE', attachments: 0 });
    assert.strictEqual(matches('verdict == SAFE || verdict == HIGH_RISK && attachments > 3', r), true);
    assert.strictEqual(matches('verdict == HIGH_RISK && attachments > 3 || verdict == SAFE', r), true);
});

// ---------------------------------------------------------------------------
// Discoverability
// ---------------------------------------------------------------------------

test('every documented example actually compiles', () => {
    // Examples are how anybody learns a filter language. One that errors when
    // clicked teaches the opposite of what it is for.
    for (const example of FILTER_EXAMPLES) {
        const compiled = compileFilter(example.expression);
        assert.ok(!compiled.error, `"${example.expression}" is offered as an example but does not compile: ${compiled.error?.message}`);
        assert.doesNotThrow(() => compiled.test(row()));
    }
});

test('every field is readable and described', () => {
    for (const [name, field] of Object.entries(FIELDS)) {
        assert.strictEqual(typeof field.read, 'function', `${name} must be readable`);
        assert.doesNotThrow(() => field.read(row()), `${name} must not throw on a row`);
        assert.ok(field.help && field.help.length > 3, `${name} must be described, or the hint list is useless`);
        assert.ok(['text', 'number', 'enum', 'bool'].includes(field.type), `${name} has an unknown type`);
    }
});

test('suggestions complete a partial field name', () => {
    const names = fieldSuggestions('verd').map(s => s.name);
    assert.ok(names.includes('verdict'));

    // Mid-expression, it must complete the word being typed rather than the
    // whole line.
    assert.ok(fieldSuggestions('verdict == SAFE && att').map(s => s.name).includes('attachments'));

    assert.deepStrictEqual(fieldSuggestions(''), [], 'nothing typed, nothing suggested');
});
