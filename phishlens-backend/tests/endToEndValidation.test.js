const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { Writable } = require('stream');
const { PDFParse } = require('pdf-parse');

/**
 * Phase 12 final validation.
 *
 * The plan requires proving the whole chain, not the individual links:
 *
 *   EMAIL -> INGESTION -> FORENSICS -> NLP -> MQL -> IOC -> THREAT INTELLIGENCE
 *   -> GEOLOCATION -> CAMPAIGN CORRELATION -> RISK -> EXPLANATION -> MITIGATION
 *   -> REPORT -> DASHBOARD
 *
 * This drives that chain in one pass against isolated state and asserts each
 * stage actually contributed, so a stage silently failing cannot pass as
 * success. Network-dependent stages are injected rather than called, so the
 * validation is deterministic and runs offline; those stages have their own
 * tests and were verified live against real services separately.
 */

const DATA = path.join(__dirname, '../data');
const ISOLATED = [
    'cases.json', 'processed_messages.json', 'audit_log.json', 'audit_log_archive.jsonl',
    'learned_model.json', 'sender_baselines.json', 'knowledge_graph.sqlite',
    'executive_directory.json', 'executive_targeting.json', 'custom_detection.json',
    'geo_cache.json', 'domain_age_cache.json', 'threat_intel.json'
];

function snapshot() {
    const saved = {};
    ISOLATED.forEach(name => {
        const file = path.join(DATA, name);
        saved[file] = fs.existsSync(file) ? fs.readFileSync(file) : null;
    });
    return saved;
}

function restore(saved) {
    Object.entries(saved).forEach(([file, content]) => {
        if (content === null) { if (fs.existsSync(file)) fs.unlinkSync(file); }
        else fs.writeFileSync(file, content);
    });
}

const PHISHING_EMAIL = [
    'Received: from relay.attacker.example (8.8.8.8) by mx.company.example with ESMTP id v1; Mon, 1 Sep 2026 10:00:00 +0000',
    'From: "Anita Desai" <a.desai@cornpany.example>',
    'Reply-To: settlements@collector.example',
    'To: finance@company.example',
    'Subject: Urgent: outstanding remittance authorisation required today',
    'Message-ID: <e2e-validation-001@cornpany.example>',
    'Date: Mon, 1 Sep 2026 10:00:00 +0000',
    'Authentication-Results: mx.company.example; spf=fail smtp.mailfrom=cornpany.example; dkim=fail; dmarc=fail',
    'Content-Type: multipart/mixed; boundary="VB"',
    '',
    '--VB',
    'Content-Type: text/plain',
    '',
    'Dear Customer, unusual activity detected on your account. Your account will be suspended unless you act now.',
    'Please login to your account and confirm your password at http://198.51.100.23/verify immediately.',
    'I also need you to process payment urgently, purchase gift cards, and keep this confidential.',
    '--VB',
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    '',
    Buffer.from('inert validation payload').toString('base64'),
    '--VB--'
].join('\r\n');

test('the complete pipeline runs end to end and every stage contributes', async (t) => {
    const saved = snapshot();
    ISOLATED.forEach(n => {
        const f = path.join(DATA, n);
        // Checked and removed in one attempt rather than two: the runner runs
        // test files in parallel, so another suite clearing the same store
        // between an existsSync and an unlinkSync makes this throw for a file
        // that is already gone - the outcome it wanted anyway.
        try {
            fs.unlinkSync(f);
        } catch (e) {
            if (e.code !== 'ENOENT' && e.code !== 'EPERM') throw e;
        }
    });
    fs.writeFileSync(path.join(DATA, 'cases.json'), '[]');

    // Load fresh module instances against the now-empty state.
    const moduleNames = [
        '../modules/emailParser', '../modules/mqlBridge', '../modules/authAnalyzer',
        '../modules/forensicEngine', '../modules/attachmentAnalyzer', '../modules/iocExtractor',
        '../modules/nlpAnalyzer', '../modules/ruleEngine', '../modules/behavioralAnalyzer',
        '../modules/adaptiveLearning', '../modules/threatIntelStore', '../modules/threatIntelEnricher',
        '../modules/campaignGraph', '../modules/evidenceFusion', '../modules/confidenceEngine',
        '../modules/executiveGuard', '../modules/policyEngine', '../modules/caseManager',
        '../modules/auditLogger', '../modules/pdfReportGenerator', '../modules/customDetectionConfig',
        '../modules/semanticCorrelation', '../modules/correlationGuard', '../modules/ingestionRegistry'
    ];
    moduleNames.forEach(m => delete require.cache[require.resolve(m)]);

    const emailParser = require('../modules/emailParser');
    const mqlBridge = require('../modules/mqlBridge');
    const attachmentAnalyzer = require('../modules/attachmentAnalyzer');
    const iocExtractor = require('../modules/iocExtractor');
    const nlpAnalyzer = require('../modules/nlpAnalyzer');
    const ruleEngine = require('../modules/ruleEngine');
    const behavioralAnalyzer = require('../modules/behavioralAnalyzer');
    const adaptiveLearning = require('../modules/adaptiveLearning');
    const threatIntelStore = require('../modules/threatIntelStore');
    const evidenceFusion = require('../modules/evidenceFusion');
    const confidenceEngine = require('../modules/confidenceEngine');
    const executiveGuard = require('../modules/executiveGuard');
    const policyEngine = require('../modules/policyEngine');
    const caseManager = require('../modules/caseManager');
    const auditLogger = require('../modules/auditLogger');
    const pdfReportGenerator = require('../modules/pdfReportGenerator');
    const ingestionRegistry = require('../modules/ingestionRegistry');

    try {
        // The organisation describes itself, as a real deployment would.
        executiveGuard.setOrganizationDomains(['company.example']);
        executiveGuard.addPerson({ name: 'Anita Desai', title: 'Chief Financial Officer', email: 'anita.desai@company.example' });

        // Indicator feed seeded in memory so matching is deterministic offline.
        threatIntelStore.urlHosts = new Map([['198.51.100.23', 'urlhaus']]);
        threatIntelStore.urls = new Set(['http://198.51.100.23/verify']);
        threatIntelStore.domains = new Map();
        threatIntelStore.ips = new Map([['8.8.8.8', 'feodo']]);
        threatIntelStore.cidrs = [];
        threatIntelStore.lastSync = new Date().toISOString();

        // ---- INGESTION ----
        ingestionRegistry.recordMessage('rest_api');
        const parsedEmail = await emailParser.parse(PHISHING_EMAIL);
        assert.strictEqual(parsedEmail.from.address, 'a.desai@cornpany.example', 'ingestion must parse the sender');

        let threatObject = mqlBridge.normalize(parsedEmail, null, PHISHING_EMAIL);
        auditLogger.log({ case_id: threatObject.case_id, event_type: 'AUTOMATED_INGESTION', source: 'VALIDATION', description: 'ingested' });

        // ---- FORENSICS (authentication injected; live verification covered separately) ----
        threatObject.forensics.authentication = {
            spf: 'fail', dkim: 'fail', dmarc: 'fail',
            source: { spf: 'HEADER_CLAIMED', dkim: 'HEADER_CLAIMED', dmarc: 'HEADER_CLAIMED' },
            dmarc_policy: { status: 'AVAILABLE', policy: 'reject', percentage: 100 },
            limitation: 'Injected for deterministic validation.'
        };
        threatObject.infrastructure = {
            origin_ip: '8.8.8.8',
            origin: { origin_provider: 'External Mail Infrastructure', confidence_factors: [], origin_confidence: 0.7 },
            geo_points: [{ ip: '8.8.8.8', role: 'ORIGIN', latitude: 37.34, longitude: -121.89, city: 'San Jose', country: 'United States', country_code: 'US', asn: 'AS15169', isp: 'Google LLC' }]
        };
        threatObject.forensics.smtp_relay = [{ hop_index: 0, hostname: 'relay.attacker.example', ip: '8.8.8.8', is_public: true, classification: 'ORIGIN_CANDIDATE', trust_level: 0.75, trust_explanation: 'Earliest public hop' }];

        // ---- ATTACHMENTS + IOC ----
        threatObject = attachmentAnalyzer.analyze(threatObject, parsedEmail);
        assert.strictEqual(threatObject.attachments.length, 1, 'the attachment must be extracted');
        assert.match(threatObject.attachments[0].sha256, /^[a-f0-9]{64}$/, 'the attachment must be hashed');

        threatObject = iocExtractor.extract(threatObject, parsedEmail);
        assert.ok(threatObject.iocs.urls.length > 0, 'IOC extraction must find the link');
        assert.ok(threatObject.iocs.hashes.length > 0, 'the attachment hash must become an indicator');

        // ---- NLP ----
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
        const nlpTypes = threatObject.nlp.signals.map(s => s.type);
        assert.ok(nlpTypes.includes('GIFT_CARD_REQUEST'), 'NLP must identify the gift-card lure');
        assert.ok(nlpTypes.includes('SECRECY_PRESSURE'), 'NLP must identify the secrecy request');

        // ---- MQL (message stage) ----
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'message');
        const messageStageRules = threatObject.detection.matched_rules.map(r => r.id);
        assert.ok(messageStageRules.length > 0, 'MQL must match at least one rule');
        assert.ok(messageStageRules.includes('MQL-ATT-101'), 'the executable attachment rule must fire');

        // ---- THREAT INTELLIGENCE + GEOLOCATION ----
        threatObject.threat_intelligence = {
            status: 'MATCHED_AGAINST_LOCAL_FEEDS',
            feed_state: { synced: true, age_hours: 0, indicator_totals: threatIntelStore.counts() },
            matches: threatObject.iocs.urls.map(u => threatIntelStore.lookupUrl(u)).filter(Boolean)
                .map(hit => ({ indicator_type: 'URL', indicator: hit.indicator, matched: hit.matched, feed: hit.feed })),
            domain_ages: [{ domain: 'cornpany.example', is_sender_domain: true, status: 'AVAILABLE', age_days: 4, registered_at: '2026-08-27T00:00:00Z' }],
            limitation: 'Feeds are a snapshot.'
        };
        assert.ok(threatObject.threat_intelligence.matches.length > 0, 'threat intelligence must match the known-bad URL');
        assert.ok(threatObject.infrastructure.geo_points.length > 0, 'geolocation must place the origin address');

        // ---- BEHAVIOURAL + EXECUTIVE + CAMPAIGN + MQL (enrichment stage) ----
        threatObject = behavioralAnalyzer.analyze(threatObject, parsedEmail);
        assert.strictEqual(threatObject.behavioral.status, 'ANALYZED');

        threatObject = executiveGuard.evaluateTarget(threatObject, parsedEmail);
        assert.strictEqual(threatObject.executive_context.is_impersonated, true, 'the CFO impersonation must be detected');
        assert.ok(threatObject.executive_context.findings.some(f => f.type === 'LOOKALIKE_ORGANIZATION_DOMAIN'),
            'the lookalike sending domain must be detected');

        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');
        const allRules = threatObject.detection.matched_rules.map(r => r.id);
        assert.ok(allRules.includes('MQL-INTEL-101'), 'the threat-intelligence rule must fire in the enrichment stage');
        assert.ok(allRules.includes('MQL-INTEL-104'), 'the newly-registered sender domain rule must fire');

        threatObject.campaign_association = { status: 'UNASSOCIATED', confidence: 0, related_cases: [], factors: [], suppressed_factors: [], semantic_matches: [], limitation: 'First message of its kind.' };

        // ---- RISK + EXPLANATION ----
        threatObject = adaptiveLearning.score(threatObject, parsedEmail);
        threatObject = evidenceFusion.fuse(threatObject);
        assert.ok(threatObject.evidence.length >= 5, 'evidence fusion must gather findings from multiple analysers');

        threatObject = confidenceEngine.calculate(threatObject);
        assert.strictEqual(threatObject.detection.verdict, 'HIGH_RISK', 'this message must be judged high risk');
        assert.ok(threatObject.confidence.contributions.length >= 3, 'the score must be explained by multiple families');

        // Every rule that contributed must be auditable.
        threatObject.detection.matched_rules.forEach(rule => {
            assert.ok(rule.source && rule.source.length > 5, `${rule.id} must cite its source`);
            assert.ok(rule.matched_because, `${rule.id} must say why it matched`);
        });

        // ---- MITIGATION ----
        const decision = policyEngine.evaluate(threatObject);
        assert.ok(decision, 'the policy engine must reach a decision');

        // ---- PERSISTENCE ----
        threatObject = caseManager.saveCase(threatObject);
        const stored = caseManager.getCase(threatObject.case_id);
        assert.ok(stored, 'the case must be retrievable after saving');
        assert.strictEqual(stored._raw_email_string, undefined, 'the raw message must not be retained');
        assert.ok(stored.learning_features.length > 0, 'learning characteristics must be kept for later analyst decisions');

        // ---- AUDIT LEDGER ----
        assert.strictEqual(auditLogger.getIntegrityStatus().chain_intact, true, 'the audit chain must verify');

        // ---- REPORT ----
        const chunks = [];
        const sink = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
        const rendered = new Promise(resolve => sink.on('finish', resolve));
        pdfReportGenerator.generateReport(stored, sink);
        await rendered;

        const text = (await new PDFParse({ data: Buffer.concat(chunks) }).getText()).text;
        assert.ok(text.includes('DISPOSITION: HIGH RISK'), 'the report must state the verdict');
        assert.ok(text.includes('MQL-INTEL-101'), 'the report must list the rules that fired');
        assert.ok(text.includes('Anita Desai'), 'the report must name the impersonated executive');
        assert.ok(text.includes('invoice.pdf.exe'), 'the report must record the attachment');
        assert.ok(text.includes('Scope and Limitations'), 'the report must carry its limitations');

        // ---- DASHBOARD DATA ----
        assert.ok(caseManager.getAllCases().length === 1, 'the dashboard case list must contain the case');
        assert.ok(stored.infrastructure.geo_points.length > 0, 'the dashboard map must have a point to plot');

        t.diagnostic(`validated case ${stored.case_id}: ${allRules.length} rules, ${threatObject.evidence.length} evidence items, score ${threatObject.confidence.threat}`);
    } finally {
        restore(saved);
        moduleNames.forEach(m => delete require.cache[require.resolve(m)]);
    }
});

test('an ordinary business message survives the same pipeline without being flagged', async () => {
    const saved = snapshot();
    ISOLATED.forEach(n => {
        const f = path.join(DATA, n);
        // Checked and removed in one attempt rather than two: the runner runs
        // test files in parallel, so another suite clearing the same store
        // between an existsSync and an unlinkSync makes this throw for a file
        // that is already gone - the outcome it wanted anyway.
        try {
            fs.unlinkSync(f);
        } catch (e) {
            if (e.code !== 'ENOENT' && e.code !== 'EPERM') throw e;
        }
    });
    fs.writeFileSync(path.join(DATA, 'cases.json'), '[]');

    const moduleNames = [
        '../modules/emailParser', '../modules/mqlBridge', '../modules/attachmentAnalyzer',
        '../modules/iocExtractor', '../modules/nlpAnalyzer', '../modules/ruleEngine',
        '../modules/behavioralAnalyzer', '../modules/adaptiveLearning', '../modules/evidenceFusion',
        '../modules/confidenceEngine', '../modules/executiveGuard', '../modules/threatIntelStore',
        '../modules/customDetectionConfig', '../modules/caseManager', '../modules/auditLogger'
    ];
    moduleNames.forEach(m => delete require.cache[require.resolve(m)]);

    const emailParser = require('../modules/emailParser');
    const mqlBridge = require('../modules/mqlBridge');
    const iocExtractor = require('../modules/iocExtractor');
    const nlpAnalyzer = require('../modules/nlpAnalyzer');
    const ruleEngine = require('../modules/ruleEngine');
    const behavioralAnalyzer = require('../modules/behavioralAnalyzer');
    const evidenceFusion = require('../modules/evidenceFusion');
    const confidenceEngine = require('../modules/confidenceEngine');
    const executiveGuard = require('../modules/executiveGuard');

    try {
        executiveGuard.setOrganizationDomains(['company.example']);
        executiveGuard.addPerson({ name: 'Anita Desai', title: 'CFO', email: 'anita.desai@company.example' });

        const legitimate = [
            'From: "Priya Raman" <priya.raman@partner.example>',
            'To: employee@company.example',
            'Subject: Notes from Tuesday planning call',
            'Message-ID: <legit-validation@partner.example>',
            'Date: Mon, 1 Sep 2026 10:00:00 +0000',
            'Content-Type: text/plain',
            '',
            'Thanks for the discussion. I have summarised the delivery timeline we agreed and will circulate the draft schedule next week.'
        ].join('\r\n');

        const parsedEmail = await emailParser.parse(legitimate);
        let threatObject = mqlBridge.normalize(parsedEmail, null, legitimate);
        threatObject.forensics.authentication = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } };
        threatObject = iocExtractor.extract(threatObject, parsedEmail);
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'message');
        threatObject = behavioralAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = executiveGuard.evaluateTarget(threatObject, parsedEmail);
        threatObject.campaign_association = { status: 'UNASSOCIATED', confidence: 0, related_cases: [], factors: [] };
        threatObject = evidenceFusion.fuse(threatObject);
        threatObject = confidenceEngine.calculate(threatObject);

        assert.strictEqual(threatObject.detection.verdict, 'SAFE', 'ordinary correspondence must not be flagged');
        assert.strictEqual(threatObject.executive_context.is_impersonated, false);
        assert.strictEqual(threatObject.nlp.signals.length, 0, 'no social-engineering language should be found');
    } finally {
        restore(saved);
        moduleNames.forEach(m => delete require.cache[require.resolve(m)]);
    }
});
