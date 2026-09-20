const test = require('node:test');
const assert = require('node:assert');
const { Writable } = require('stream');
const { PDFParse } = require('pdf-parse');

const pdfReportGenerator = require('../modules/pdfReportGenerator');

/** Renders a report to a buffer instead of an HTTP response. */
function renderToBuffer(threatObject) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const sink = new Writable({
            write(chunk, _enc, cb) { chunks.push(chunk); cb(); }
        });
        sink.on('finish', () => resolve(Buffer.concat(chunks)));
        sink.on('error', reject);
        pdfReportGenerator.generateReport(threatObject, sink);
    });
}

async function renderText(threatObject) {
    const buffer = await renderToBuffer(threatObject);
    const parsed = await new PDFParse({ data: buffer }).getText();
    return { text: parsed.text, pages: parsed.pages?.length ?? 0 };
}

const FULL_CASE = {
    case_id: 'SM-TEST-REPORT',
    org_id: 'org_test',
    timestamps: { ingested_at: '2026-09-20T09:00:00.000Z' },
    message: {
        sender: 'PayPal Security <billing@gmail.com>',
        recipient: 'finance@company.example',
        subject: 'Urgent: verify your account',
        delivered_at: '2026-09-20T08:59:00.000Z',
        raw_hash: 'b'.repeat(64)
    },
    detection: {
        verdict: 'HIGH_RISK',
        provider: 'PHISHLENS_NATIVE_MQL',
        verification_status: 'PHISHLENS_NATIVE_MQL_VERIFIED',
        rule_engine: { engine: 'PHISHLENS_NATIVE_MQL_V1', rules_evaluated: 27, rules_matched: 2 },
        matched_rules: [
            {
                id: 'MQL-AUTH-101', name: 'Reply-To domain differs from From domain',
                severity: 'HIGH', confidence: 0.8, decisive: false,
                source: 'APWG eCrime Trends Report; OWASP Email Security Cheat Sheet',
                matched_because: 'Reply-To domain (other.example) differs from the From domain (gmail.com).'
            },
            {
                id: 'MQL-INTEL-101', name: 'Link matches a known malicious URL', severity: 'CRITICAL',
                confidence: 0.95, decisive: true, source: 'abuse.ch URLhaus',
                matched_because: 'The exact URL http://bad.example/x is listed in the urlhaus feed.'
            }
        ],
        external_provider_result: { attempted: false, provider: null, status: 'NOT_CONFIGURED' }
    },
    review: { status: 'PENDING_ADMIN' },
    mailbox: { status: 'INBOX' },
    provider_action: { status: 'NOT_REQUESTED' },
    forensics: {
        authentication: {
            spf: 'fail', dkim: 'fail', dmarc: 'fail',
            source: { spf: 'HEADER_CLAIMED', dkim: 'HEADER_CLAIMED', dmarc: 'HEADER_CLAIMED' },
            authserv_id: 'mx.google.com',
            dkim_independent_verification: { status: 'AVAILABLE', overall: 'none', results: [{ result: 'none', comment: 'message not signed' }] },
            dmarc_policy: { status: 'AVAILABLE', policy: 'reject', percentage: 100 },
            limitation: 'SPF and DMARC are trusted from the receiving server.'
        },
        return_path_mismatch: true,
        smtp_relay: [{ hop_index: 0, hostname: 'mx.google.com', ip: '209.85.1.1', classification: 'TRUSTED_RECEIVER', trust_level: 0.95, trust_explanation: 'Recipient gateway' }]
    },
    infrastructure: {
        origin_ip: '203.0.113.45', asn: 'AS64500 Example', isp: 'Example ISP',
        origin: { origin_provider: 'External Mail Infrastructure', selection_reason: 'Earliest public relay', origin_confidence: 0.7, limitation: 'Client network not exposed.' },
        geolocation: { status: 'AVAILABLE', city: 'Anytown', country: 'Exampleland' }
    },
    threat_intelligence: {
        feed_state: { synced: true, age_hours: 2, indicator_totals: { urls: 13000, domains: 1700, ips: 2300, netblocks: 1700 } },
        matches: [{ indicator_type: 'URL', indicator: 'http://bad.example/x', matched: 'EXACT_URL', feed: 'urlhaus' }],
        domain_ages: [{ domain: 'gmail.com', is_sender_domain: true, status: 'AVAILABLE', age_days: 11360, registered_at: '1995-08-13T04:00:00Z' }],
        limitation: 'Feeds are a snapshot.'
    },
    iocs: { ips: ['203.0.113.45'], domains: ['gmail.com'], urls: ['http://bad.example/x'], hashes: ['c'.repeat(64)] },
    attachments: [{ file_name: 'invoice.pdf.exe', extension: 'exe', mime_type: 'application/octet-stream', size_bytes: 42, sha256: 'c'.repeat(64), limitation: 'Not opened or executed.' }],
    nlp: {
        engine: 'EXPLAINABLE_LOCAL_HEURISTICS', score: 0.8,
        signals: [{ type: 'GIFT_CARD_REQUEST', severity: 'CRITICAL', confidence: 0.88, matched_terms: ['gift card'], explanation: 'Gift-card requests are a common BEC tactic.', source: 'FBI IC3' }],
        limitation: 'Language signals are supporting evidence.'
    },
    behavioral: {
        known_sender: false, messages_seen_from_sender: 0,
        signals: [{ type: 'FIRST_CONTACT_SENDER', severity: 'LOW', confidence: 0.4, explanation: 'No prior message from this sender.' }],
        limitation: 'Baselines describe only what this installation observed.'
    },
    adaptive: {
        status: 'SCORED', score: 0.72, matched_characteristics: 4,
        learned_from: { malicious: 6, legitimate: 7 },
        contributions: [{ characteristic: 'token:remittance', weight: 1.2, seen_in_malicious: 5, seen_in_legitimate: 0 }],
        limitation: 'Corroborating evidence only.'
    },
    evidence: [{ severity: 'HIGH', finding: 'SPF Authentication Failed', explanation: 'Sending IP not authorised.', source: 'HEADER_PARSER', timestamp: '2026-09-20T09:00:00.000Z', provenance: { source_type: 'EMAIL_HEADER', source_reference: 'Authentication-Results' } }],
    confidence: {
        threat: 0.94, infrastructure_origin: 0.7, campaign_association: 0.3,
        actor_attribution: 'INSUFFICIENT EVIDENCE', scoring_version: 'PHISHLENS_EVIDENCE_FUSION_V2',
        contributions: [{ family: 'AUTHENTICATION', contribution: 0.3, representative_finding: 'SPF Authentication Failed', explanation: 'Strongest in family counts in full.' }]
    },
    campaign_association: {
        status: 'POSSIBLY_ASSOCIATED', confidence: 0.3, related_cases: ['SM-OTHER-1'],
        factors: [{ factor: 'SEMANTIC_SIMILARITY', evidence: 'Wording is 92% similar to case SM-OTHER-1' }],
        suppressed_factors: [{ indicator: 'gmail.com', reason: 'gmail.com is a consumer mail provider used by unrelated senders.' }],
        semantic_matches: [{ case_id: 'SM-OTHER-1', similarity: 0.92, shared_terms: ['settlement', 'remittance'], subject: 'Remittance' }],
        limitation: 'Shared infrastructure does not establish actor identity.'
    },
    remediation: { status: 'PENDING', policy_matched: 'SUSPICIOUS_USER_WARNING' },
    containment_context: { decision_reason: 'Confirmed phishing', admin_note: 'Escalated to IT.', contained_at: null, released_at: null }
};

test('the report contains every section the plan requires', async () => {
    const { text } = await renderText(FULL_CASE);

    [
        'Case Information', 'Message Metadata', 'Authentication Results',
        'Relay Path Reconstruction', 'Infrastructure and Geolocation', 'Threat Intelligence',
        'Indicators of Compromise', 'Attachment Analysis', 'Language and Social-Engineering Findings',
        'Detection Rule Matches', 'Behavioural Findings', 'Learned-Pattern Assessment',
        'Evidence Register', 'Risk Assessment', 'Campaign Relationships',
        'Response and Remediation', 'Case Timeline', 'Analyst Decision and Notes', 'Scope and Limitations'
    ].forEach(section => {
        assert.ok(text.includes(section), `report must contain the "${section}" section`);
    });
});

test('the verdict and a recommended action appear before the evidence', async () => {
    const { text } = await renderText(FULL_CASE);
    assert.ok(text.includes('DISPOSITION: HIGH RISK'));
    assert.ok(text.includes('Recommended action:'));
    assert.ok(text.indexOf('DISPOSITION') < text.indexOf('Evidence Register'),
        'the conclusion should be stated before the supporting evidence');
});

/** A rule match without its source is unauditable, which the plan forbids. */
test('every detection rule is printed with its citable source', async () => {
    const { text } = await renderText(FULL_CASE);
    assert.ok(text.includes('MQL-AUTH-101'));
    assert.ok(text.includes('MQL-INTEL-101'));
    assert.ok(text.includes('APWG eCrime Trends Report'), 'the rule source must be printed');
    assert.ok(text.includes('abuse.ch URLhaus'));
    assert.ok(text.includes('Why it matched:'));
});

test('findings carry their limitations rather than being presented as certainties', async () => {
    const { text } = await renderText(FULL_CASE);
    assert.ok(text.includes('not the location of the person'), 'geolocation must be qualified');
    assert.ok(text.includes('INSUFFICIENT EVIDENCE'), 'actor attribution must stay unattributed');
    assert.ok(text.includes('No attachment was opened, executed, or detonated'));
    assert.ok(text.includes('unknown, not established as safe'), 'feed absence must not read as safe');
});

test('campaign links that were deliberately not made are recorded', async () => {
    const { text } = await renderText(FULL_CASE);
    assert.ok(text.includes('Links deliberately not made'));
    assert.ok(text.includes('consumer mail provider used by unrelated senders'));
    assert.ok(text.includes('Messages reusing the same wording'));
});

test('page footers match the real page count', async () => {
    const { text, pages } = await renderText(FULL_CASE);
    assert.ok(pages > 0, 'the report must render at least one page');
    // Writing inside the bottom margin previously made PDFKit append one blank
    // page per footer, leaving the printed totals wrong.
    assert.ok(text.includes(`Page 1 of ${pages}`), `footer total must equal the real page count (${pages})`);
    assert.ok(text.includes(`Page ${pages} of ${pages}`), 'the last page must be numbered correctly');
});

test('a sparse case renders without placeholder artefacts', async () => {
    const sparse = {
        case_id: 'SM-TEST-SPARSE',
        message: { sender: 'a@b.example', recipient: 'c@d.example', subject: 'Hello', raw_hash: 'd'.repeat(64) },
        detection: { verdict: 'SAFE' },
        confidence: { threat: 0.02 }
    };
    const { text } = await renderText(sparse);

    ['[object Object]', 'undefined', 'NaN'].forEach(artefact => {
        assert.ok(!text.includes(artefact), `report must not leak "${artefact}"`);
    });
    // Missing data is stated, never silently omitted.
    assert.ok(text.includes('Not available') || text.includes('No '), 'absent data should be stated explicitly');
    assert.ok(text.includes('Scope and Limitations'), 'the disclaimer must survive a sparse case');
});
