const test = require('node:test');
const assert = require('node:assert');

const mailTransportFlow = require('../modules/mailTransportFlow');

/**
 * Mail projected as a transport flow.
 *
 * ## What these are guarding
 *
 * A packet-analyser layout carries an implicit promise: every column was
 * observed. Most of a message's journey happened before this system saw it, and
 * a `Received:` header is free text that the great majority of mail servers
 * write without a port.
 *
 * So the risk here is not a crash, it is a **convincing fabrication**. Filling
 * the port columns for every row would be trivial, would look far more
 * complete, and would put numbers in a forensic view that were never real -
 * numbers somebody would eventually quote. Most of what follows asserts that a
 * value which was not recorded comes back null.
 */

const caseWith = (over = {}) => ({
    case_id: 'SM-2026-1',
    detection: { verdict: 'SAFE', matched_rules: [] },
    message: { subject: 'Delivery Thursday', sender: 'priya@supplier.example', recipient: 'me@company.example', delivered_at: '2026-09-26T09:00:00Z', source: 'SMTP_GATEWAY' },
    timestamps: { ingested_at: '2026-09-26T09:00:05Z' },
    forensics: { smtp_relay: [] },
    infrastructure: {},
    attachments: [],
    evidence: [],
    ...over
});

// ---------------------------------------------------------------------------
// Never inventing a value
// ---------------------------------------------------------------------------

test('a source port absent from the headers comes back null, not zero or a guess', () => {
    const row = mailTransportFlow.project(caseWith(), 1);

    assert.strictEqual(row.source_port, null,
        'no mail server recorded a port here, so there is no port to show');
    assert.notStrictEqual(row.source_port, 0, 'and it is certainly not zero');
});

test('a source port the headers did state is used', () => {
    // Some MTAs, Exchange among them, do write one. Where the fact exists it
    // should be shown - the objection is to inventing it, not to reporting it.
    const row = mailTransportFlow.project(caseWith({
        forensics: {
            smtp_relay: [
                { ip: '203.0.113.5', is_public: true, classification: 'ORIGIN_CANDIDATE', raw: 'Received: from mta.supplier.example ([203.0.113.5]) by mx.company.example with ESMTPS port 49152; Mon, 21 Sep 2026 09:00:00 +0000' }
            ]
        }
    }), 1);

    assert.strictEqual(row.source_port, 49152);
    assert.strictEqual(row.protocol, 'ESMTPS', 'the header said so, and the header wins over the channel default');
    assert.match(row.protocol_basis, /headers/i);
});

test('the destination port is the one this installation listened on', () => {
    // The only port in the row that is not somebody else's claim.
    const smtp = mailTransportFlow.project(caseWith(), 1);
    assert.strictEqual(smtp.destination_port, 2525);
    assert.strictEqual(smtp.protocol, 'SMTP');

    // Mail read out of a browser has no port at all, and must say so rather
    // than borrowing 443 because that sounds plausible.
    const browser = mailTransportFlow.project(caseWith({
        message: { ...caseWith().message, source: 'BROWSER:mail.google.com' }
    }), 1);
    assert.strictEqual(browser.destination_port, null);
    assert.strictEqual(browser.channel, 'BROWSER');
});

test('an address the relay reconstruction could not determine stays empty', () => {
    const row = mailTransportFlow.project(caseWith({ infrastructure: { origin_ip: 'UNAVAILABLE' } }), 1);
    assert.strictEqual(row.source, null);
});

test('with no receiving gateway in the headers, the destination falls back and says so', () => {
    const row = mailTransportFlow.project(caseWith(), 1);

    assert.strictEqual(row.destination, null, 'no hop identified one, so there is no address');
    assert.strictEqual(row.destination_host, 'company.example', 'the recipient domain is the honest stand-in');
    assert.match(row.destination_basis, /recipient's domain/i,
        'and the row must carry where that came from, so it is not read as an observed hop');
});

test('a receiving gateway named in the headers is used in preference', () => {
    const row = mailTransportFlow.project(caseWith({
        forensics: {
            smtp_relay: [
                { ip: '203.0.113.5', is_public: true, classification: 'ORIGIN_CANDIDATE' },
                { ip: '198.51.100.2', is_public: true, classification: 'TRUSTED_RECEIVER', hostname: 'mx.company.example' }
            ]
        }
    }), 1);

    assert.strictEqual(row.destination, '198.51.100.2');
    assert.match(row.destination_basis, /headers/i);
});

// ---------------------------------------------------------------------------
// The coloured ball
// ---------------------------------------------------------------------------

test('the verdict maps to exactly three colours', () => {
    assert.strictEqual(mailTransportFlow.project(caseWith({ detection: { verdict: 'HIGH_RISK' } }), 1).colour, 'RED');
    assert.strictEqual(mailTransportFlow.project(caseWith({ detection: { verdict: 'SUSPICIOUS' } }), 1).colour, 'YELLOW');
    assert.strictEqual(mailTransportFlow.project(caseWith({ detection: { verdict: 'SAFE' } }), 1).colour, 'GREEN');

    // An unscored case must not be quietly painted green. "Not scored" and
    // "checked and clean" are different things and only one is reassuring.
    const unknown = mailTransportFlow.project(caseWith({ detection: { verdict: 'UNKNOWN' } }), 1);
    assert.strictEqual(unknown.colour, 'GREY');
    assert.strictEqual(unknown.verdict_label, 'Not scored');
});

// ---------------------------------------------------------------------------
// Sequence and ordering
// ---------------------------------------------------------------------------

test('sequence numbers run oldest first, the way a capture numbers frames', () => {
    const rows = mailTransportFlow.projectAll([
        caseWith({ case_id: 'C', timestamps: { ingested_at: '2026-09-26T12:00:00Z' } }),
        caseWith({ case_id: 'A', timestamps: { ingested_at: '2026-09-26T10:00:00Z' } }),
        caseWith({ case_id: 'B', timestamps: { ingested_at: '2026-09-26T11:00:00Z' } })
    ]);

    assert.deepStrictEqual(rows.map(r => r.case_id), ['A', 'B', 'C']);
    assert.deepStrictEqual(rows.map(r => r.no), [1, 2, 3]);
});

// ---------------------------------------------------------------------------
// The frame detail
// ---------------------------------------------------------------------------

test('the last hop is always this system, and is marked as the one it witnessed', () => {
    const row = mailTransportFlow.project(caseWith({
        forensics: { smtp_relay: [{ ip: '203.0.113.5', is_public: true, classification: 'ORIGIN_CANDIDATE' }] }
    }), 1);

    const last = row.frames[row.frames.length - 1];
    assert.strictEqual(last.classification, 'INGESTED_HERE');
    assert.strictEqual(last.observed_by_us, true);
    assert.strictEqual(last.protocol, 'SMTP');
    assert.strictEqual(last.port, 2525);

    // Every earlier hop is a claim from a header and must not be marked as
    // witnessed.
    for (const frame of row.frames.slice(0, -1)) {
        assert.notStrictEqual(frame.observed_by_us, true);
    }
});

test('a message with no reconstructable path still has the leg this system saw', () => {
    const row = mailTransportFlow.project(caseWith(), 1);
    assert.strictEqual(row.frames.length, 1);
    assert.strictEqual(row.frames[0].observed_by_us, true);
});

// ---------------------------------------------------------------------------
// The Info column
// ---------------------------------------------------------------------------

test('the summary leads with the strongest finding, and flags an observed connection', () => {
    const row = mailTransportFlow.project(caseWith({
        detection: { verdict: 'HIGH_RISK', matched_rules: [{ name: 'Credential form posting offsite' }, { name: 'Lookalike domain' }] },
        evidence: [{ finding: 'Credential form posting offsite', signal_strength: 0.9 }],
        attachments: [{ file_name: 'a.html' }],
        connection_evidence: { status: 'OBSERVED' }
    }), 1);

    assert.match(row.info, /^Credential form posting offsite/);
    assert.match(row.info, /\+1 more rule/);
    assert.match(row.info, /1 attachment/);
    // Last, where the eye finishes, because nothing else on the row matters more.
    assert.match(row.info, /CONNECTION OBSERVED$/);
    assert.strictEqual(row.connection_observed, true);
});

test('a clean message says how many checks passed rather than nothing', () => {
    const row = mailTransportFlow.project(caseWith({ assurance: { passed: 9 } }), 1);
    assert.match(row.info, /9 checks clean/);
});

// ---------------------------------------------------------------------------
// The promise the layout makes
// ---------------------------------------------------------------------------

test('the columns that are often empty explain themselves', () => {
    const provenance = mailTransportFlow.columnProvenance();

    // A dash with no explanation reads as a fault in the tool rather than as an
    // absent fact.
    assert.match(provenance.source_port, /never inferred/i);
    assert.match(provenance.destination_port, /listened on/i);
    assert.match(provenance.protocol, /Received header/i);
    assert.match(provenance.colour, /Red.*yellow.*green/i);
});
