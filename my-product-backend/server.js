const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const config = require('./config');

// Adapters
const detectionAdapter = require('./adapters/detectionAdapter');
const mailIngestionAdapter = require('./adapters/mailIngestionAdapter');

// P0 & P1 Modules Pipeline
const mqlBridge = require('./modules/mqlBridge');
const forensicEngine = require('./modules/forensicEngine');
const iocExtractor = require('./modules/iocExtractor');
const infraEnricher = require('./modules/infraEnricher');
const evidenceFusion = require('./modules/evidenceFusion');
const confidenceEngine = require('./modules/confidenceEngine');
const caseManager = require('./modules/caseManager');
const auditLogger = require('./modules/auditLogger');
const campaignGraph = require('./modules/campaignGraph');
const executiveGuard = require('./modules/executiveGuard');
const policyEngine = require('./modules/policyEngine');
const remediationEngine = require('./modules/remediationEngine');
const campaignResponsePlanner = require('./modules/campaignResponsePlanner');
const iocResponseManager = require('./modules/iocResponseManager');
const pdfReportGenerator = require('./modules/pdfReportGenerator');
const dedupStore = require('./modules/dedupStore');

const app = express();
const PORT = config.port;

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));

console.log('='.repeat(70));
console.log('🚀 SECUREMAIL AI BACKEND — REAL-TIME AUTOMATED INGESTION & PIPELINE');
console.log(`🔑 Detection Provider: ${config.detection.provider}`);
console.log(`🌐 Detection Endpoint: ${config.detection.endpoint}`);
console.log(`📡 Server Listening on: http://localhost:${PORT}`);
console.log(`🛡️ Remediation Mode: ${process.env.REMEDIATION_MODE || 'simulation'} (${process.env.MAILBOX_PROVIDER || 'gmail'})`);
console.log('='.repeat(70));

// ==================== CORE AUTOMATED PIPELINE EXECUTION ====================
async function processPipeline(emailContent, source = 'MANUAL_API', clientMessageKey = null) {
    console.log(`\n📨 ===== AUTOMATED FORENSIC PIPELINE TRIGGERED (${source}) =====`);
    try {
        // Base64 encode raw message if needed
        let encodedMessage = emailContent;
        if (!emailContent.match(/^[A-Za-z0-9+/=]+$/) || emailContent.includes('From:')) {
            encodedMessage = Buffer.from(emailContent).toString('base64');
        }

        // 0. Deduplication & Idempotency Check
        const rfcMatch = emailContent ? emailContent.match(/^Message-ID:\s*(<[^>]+>)/mi) : null;
        const rfcMessageId = rfcMatch ? rfcMatch[1] : null;
        const rawHash = crypto.createHash('sha256').update(emailContent || '').digest('hex');
        const messageKey = clientMessageKey || dedupStore.computeMessageKey(rfcMessageId, emailContent);

        const dedupCheck = dedupStore.reserveMessageKey(messageKey, {
            source,
            rfc_message_id: rfcMessageId,
            raw_sha256: rawHash
        });

        if (dedupCheck.isDuplicate && dedupCheck.record.case_id) {
            console.log(`[Dedup] DUPLICATE MESSAGE (${messageKey}) -> Returning existing Case ${dedupCheck.record.case_id}`);
            const existingCase = caseManager.getCase(dedupCheck.record.case_id);
            if (existingCase) {
                return existingCase;
            }
        }

        // 1. Detection Layer via Adapter (Sublime/MQL)
        const detectionResult = await detectionAdapter.analyze(encodedMessage);

        // 2. Bridge & Canonical ThreatObject Initialization
        let threatObject = mqlBridge.normalize(detectionResult, emailContent);

        // Audit ingestion
        auditLogger.log({
            case_id: threatObject.case_id,
            event_type: 'AUTOMATED_INGESTION',
            source: source,
            description: `Email automatically ingested from ${source} (SHA-256: ${threatObject.message.raw_hash})`
        });

        // 3. Header Forensics & Trust-Aware SMTP Relay Reconstruction
        threatObject = await forensicEngine.analyzeHeaders(threatObject);

        // 4. IOC Extraction (IPs, Domains, URLs, Hashes)
        threatObject = iocExtractor.extract(threatObject);

        // 5. Infrastructure & Geolocation Enrichment
        threatObject = await infraEnricher.enrich(threatObject);

        // 6. Persistent Knowledge Graph & Cross-Case Campaign Correlation (SQLite)
        threatObject = await campaignGraph.processThreatObject(threatObject);

        // 7. Evidence Fusion Engine (Normalizes all findings into EvidenceObject[])
        threatObject = evidenceFusion.fuse(threatObject);

        // 8. Executive Protection Guard (VIP Target Context)
        threatObject = executiveGuard.evaluateTarget(threatObject);

        // 9. 3-Tier Confidence Calculation Engine
        threatObject = confidenceEngine.calculate(threatObject);

        // 10. Contextual Policy Engine Evaluation
        const policyDecision = policyEngine.evaluate(threatObject);

        // 11. Active Disruption & Real Remediation Lifecycle Execution
        threatObject = await remediationEngine.executePolicyDecision(threatObject, policyDecision);

        // 12. Persistent Case Storage & Deduplication Binding
        threatObject = caseManager.saveCase(threatObject);
        dedupStore.bindCaseId(messageKey, threatObject.case_id);

        console.log(`🎉 AUTOMATED PIPELINE COMPLETE! Case ID: ${threatObject.case_id} | Verdict: ${threatObject.detection.verdict} | Threat Confidence: ${threatObject.confidence.threat} | Remediation: ${threatObject.remediation.status}`);

        return threatObject;

    } catch (error) {
        console.error('❌ Automated Pipeline Execution Error:', error.stack || error.message);
        throw error;
    }
}

// Start Real-Time Mail Ingestion Layer (Local SMTP Gateway on :2525 + IMAP Inbox Poller)
mailIngestionAdapter.startIngestion(processPipeline);

// ==================== HEALTH & METRICS ====================
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        system: 'SecureMail AI Platform Engine',
        mailIngestionStatus: 'ACTIVE (Port 2525 SMTP Gateway + IMAP)',
        dedupMetrics: dedupStore.getStats(),
        remediationMode: process.env.REMEDIATION_MODE || 'simulation',
        mailboxProvider: process.env.MAILBOX_PROVIDER || 'gmail',
        detectionProvider: config.detection.provider
    });
});

// ==================== MANUAL TESTING & WEBHOOK INGESTION ENDPOINTS ====================
app.post('/api/analyze', async (req, res) => {
    try {
        const { emailContent } = req.body;
        if (!emailContent) return res.status(400).json({ success: false, error: 'emailContent is required' });
        const threatObject = await processPipeline(emailContent, 'MANUAL_TEST_API');
        res.json({ success: true, threatObject });
    } catch (error) {
        res.status(500).json({ success: false, error: error.stack || error.message });
    }
});

app.post('/api/ingest/email', async (req, res) => {
    try {
        const { emailContent, source } = req.body;
        if (!emailContent) return res.status(400).json({ success: false, error: 'emailContent is required' });
        const threatObject = await processPipeline(emailContent, source || 'WEBHOOK_INBOUND');
        res.json({ success: true, threatObject });
    } catch (error) {
        res.status(500).json({ success: false, error: error.stack || error.message });
    }
});

// ==================== CASES API ====================
app.get('/api/cases', (req, res) => {
    res.json({ success: true, count: caseManager.getAllCases().length, cases: caseManager.getAllCases() });
});

app.get('/api/cases/:id', (req, res) => {
    const caseItem = caseManager.getCase(req.params.id);
    if (!caseItem) return res.status(404).json({ success: false, error: 'Case not found' });
    res.json({ success: true, case: caseItem });
});

// ==================== KNOWLEDGE GRAPH API ====================
app.get('/api/graph', async (req, res) => {
    const graphData = await campaignGraph.getGraphData();
    res.json({ success: true, graph: graphData });
});

// ==================== VIP EXECUTIVE API ====================
app.get('/api/vips', (req, res) => {
    res.json({ success: true, vips: executiveGuard.getVipList() });
});

// ==================== AUDIT LOGS API ====================
app.get('/api/audit', (req, res) => {
    res.json({ success: true, events: auditLogger.getAllEvents() });
});

// ==================== ACTIVE DISRUPTION & REMEDIATION APIs ====================
app.get('/api/remediate/actions', (req, res) => {
    res.json({ success: true, actions: remediationEngine.getAllActions() });
});

app.post('/api/remediate/approve', async (req, res) => {
    try {
        const { actionId, analystUser, reason } = req.body;
        if (!actionId) return res.status(400).json({ success: false, error: 'actionId is required' });
        const updatedAction = await remediationEngine.approveAction(actionId, analystUser || 'SOC_ANALYST', reason);
        res.json({ success: true, action: updatedAction });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/remediate/rollback', async (req, res) => {
    try {
        const { actionId, analystUser, reason } = req.body;
        if (!actionId) return res.status(400).json({ success: false, error: 'actionId is required' });
        const updatedAction = await remediationEngine.rollbackAction(actionId, analystUser || 'SOC_ANALYST', reason);
        res.json({ success: true, action: updatedAction });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/remediate/iocs', (req, res) => {
    res.json({ success: true, iocs: iocResponseManager.getResponseList() });
});

app.get('/api/remediate/campaign/:id', async (req, res) => {
    const campaignId = req.params.id;
    const allCases = caseManager.getAllCases();
    const relatedCases = allCases.filter(c => c.campaign?.campaign_id === campaignId);
    const plan = campaignResponsePlanner.generateResponsePlan({ campaign_id: campaignId }, relatedCases);
    res.json({ success: true, plan });
});

app.post('/api/remediate/override', async (req, res) => {
    const { caseId, action, adminUser } = req.body;
    if (!caseId || !action) return res.status(400).json({ success: false, error: 'caseId and action are required' });
    const result = await remediationEngine.adminOverride(caseId, action, adminUser || 'SOC_ADMIN');
    res.json({ success: true, result });
});

// ==================== FORENSIC PDF REPORT GENERATOR API ====================
app.get('/api/reports/pdf/:id', (req, res) => {
    const caseItem = caseManager.getCase(req.params.id);
    if (!caseItem) return res.status(404).json({ success: false, error: 'Case not found' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="SecureMail_Forensic_Report_${caseItem.case_id}.pdf"`);
    pdfReportGenerator.generateReport(caseItem, res);
});

app.listen(PORT, () => {
    console.log(`✅ SecureMail AI Platform active on port ${PORT}`);
});