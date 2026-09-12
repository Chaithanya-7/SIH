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

// Google Auth, Organization & Gmail Modules
const userManager = require('./modules/userManager');
const organizationManager = require('./modules/organizationManager');
const tokenStore = require('./modules/tokenStore');
const mailboxConnectionManager = require('./modules/mailboxConnectionManager');
const gmailIngestionAdapter = require('./adapters/gmailIngestionAdapter');

const { requireAuth, requireRole } = require('./middleware/authMiddleware');
const axios = require('axios');

const app = express();
const PORT = config.port;

const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3005', 'http://localhost:5173'];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
            callback(null, true);
        } else {
            callback(new Error('CORS policy restricted access.'));
        }
    },
    credentials: true
}));

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

// Start Real-Time Mail Ingestion Layer
mailIngestionAdapter.startIngestion(processPipeline);
gmailIngestionAdapter.setPipelineHandler(processPipeline);

// Protect sensitive SOC administration and data APIs
app.use(['/api/cases', '/api/graph', '/api/audit', '/api/remediate', '/api/reports', '/api/auth/me', '/api/org', '/api/mailbox'], requireAuth);

// ==================== GOOGLE AUTHENTICATION ENDPOINTS ====================
app.post('/api/auth/google/verify', (req, res) => {
    try {
        const { googleAccountId, email, name, avatarUrl } = req.body;
        if (!email) return res.status(400).json({ success: false, error: 'Email is required for authentication.' });

        const { user, sessionToken } = userManager.findOrCreateFromGoogleProfile({
            googleAccountId: googleAccountId || `g_${crypto.randomBytes(6).toString('hex')}`,
            email,
            name,
            avatarUrl
        });

        const org = user.organization_id ? organizationManager.getOrganizationById(user.organization_id) : null;
        const connection = mailboxConnectionManager.getConnectionByUser(user.id);

        res.json({
            success: true,
            sessionToken,
            user,
            organization: org,
            mailboxConnection: connection
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/auth/me', (req, res) => {
    const org = req.user.organization_id ? organizationManager.getOrganizationById(req.user.organization_id) : null;
    const connection = mailboxConnectionManager.getConnectionByUser(req.user.id);
    res.json({
        success: true,
        user: req.user,
        organization: org,
        mailboxConnection: connection
    });
});

// ==================== ORGANIZATION ENDPOINTS ====================
app.post('/api/org/create', (req, res) => {
    try {
        const { name, approvedDomain } = req.body;
        const result = organizationManager.createOrganization(req.user.id, name, approvedDomain);
        res.json({ success: true, organization: result.organization, user: result.user });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

app.post('/api/org/join', (req, res) => {
    try {
        const { inviteCode } = req.body;
        const result = organizationManager.joinOrganizationWithInviteCode(req.user.id, inviteCode);
        res.json({ success: true, organization: result.organization, user: result.user });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

app.get('/api/org/current', (req, res) => {
    if (!req.user.organization_id) {
        return res.json({ success: true, organization: null, members: [] });
    }
    const org = organizationManager.getOrganizationById(req.user.organization_id);
    const members = userManager.getAllUsersInOrg(req.user.organization_id);
    res.json({ success: true, organization: org, members });
});

app.post('/api/org/rotate-invite', requireRole('ADMIN'), (req, res) => {
    try {
        const org = organizationManager.rotateInviteCode(req.user.organization_id, req.user.id);
        res.json({ success: true, organization: org });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

// ==================== GMAIL AUTHORIZATION & MAILBOX ENDPOINTS ====================
app.get('/api/auth/gmail/url', (req, res) => {
    const url = gmailIngestionAdapter.getAuthUrl(req.user.id);
    res.json({ success: true, url });
});

app.post('/api/auth/gmail/exchange', async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) return res.status(400).json({ success: false, error: 'Authorization code is required.' });

        const tokenData = await gmailIngestionAdapter.exchangeCodeForTokens(code);
        const profile = await gmailIngestionAdapter.getGmailProfile(tokenData.access_token);

        tokenStore.saveTokens(req.user.id, profile.emailAddress, tokenData);

        const connection = mailboxConnectionManager.saveConnection({
            userId: req.user.id,
            organizationId: req.user.organization_id,
            providerAccount: profile.emailAddress,
            historyId: profile.historyId,
            status: 'CONNECTED'
        });

        res.json({ success: true, connection });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/mailbox/status', (req, res) => {
    const connection = mailboxConnectionManager.getConnectionByUser(req.user.id);
    const orgConnections = req.user.organization_id 
        ? mailboxConnectionManager.getAllConnectionsInOrg(req.user.organization_id)
        : (connection ? [connection] : []);

    res.json({
        success: true,
        connection: connection || null,
        orgConnections: req.user.role === 'ADMIN' ? orgConnections : undefined
    });
});

app.post('/api/mailbox/sync', async (req, res) => {
    try {
        const connection = mailboxConnectionManager.getConnectionByUser(req.user.id);
        if (!connection || connection.status !== 'CONNECTED') {
            return res.status(400).json({ success: false, error: 'No active connected Gmail mailbox found for sync.' });
        }

        const syncResult = await gmailIngestionAdapter.syncGmailHistory(connection);
        res.json({ success: true, result: syncResult });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/mailbox/disconnect', (req, res) => {
    const connection = mailboxConnectionManager.getConnectionByUser(req.user.id);
    if (connection) {
        mailboxConnectionManager.updateStatus(connection.id, 'DISCONNECTED');
        tokenStore.revokeTokens(req.user.id);
    }
    res.json({ success: true, status: 'DISCONNECTED' });
});

// ==================== GMAIL OAUTH SCOPE STATUS ENDPOINT ====================
app.get('/api/auth/gmail/scope-status', (req, res) => {
    const hasModify = gmailIngestionAdapter.hasModifyScope(req.user.id);
    const reauthUrl = gmailIngestionAdapter.getAuthUrl(req.user.id, 'modify');
    res.json({
        success: true,
        hasModifyScope: hasModify,
        reauthUrl: hasModify ? null : reauthUrl
    });
});

// ==================== ADMIN QUARANTINE QUEUE & REVIEW ENDPOINTS ====================
app.get('/api/admin/quarantine', requireRole('ADMIN'), (req, res) => {
    try {
        const orgId = req.user.organization_id;
        const allCases = caseManager.getAllCases();

        // Admin Quarantine Queue: Filter by Organization & Reviewable/Quarantined Statuses
        const queueCases = allCases.filter(c => {
            const matchesOrg = !c.org_id || !orgId || c.org_id === orgId;
            const isQuarantinedOrReviewable = 
                c.mailbox?.status === 'QUARANTINED' ||
                c.mailbox?.status === 'CONTAINMENT_REQUESTED' ||
                c.mailbox?.status === 'RELEASE_REQUESTED' ||
                c.mailbox?.status === 'ACTION_FAILED' ||
                c.review?.status === 'PENDING_ADMIN' ||
                c.review?.status === 'UNDER_REVIEW' ||
                c.review?.status === 'CONFIRMED_THREAT' ||
                c.review?.status === 'RELEASED_BY_ADMIN';
            
            return matchesOrg && isQuarantinedOrReviewable;
        });

        res.json({
            success: true,
            cases: queueCases,
            count: queueCases.length,
            organization_id: orgId
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/quarantine/:caseId/release', requireRole('ADMIN'), async (req, res) => {
    try {
        const { caseId } = req.params;
        const { decisionReason, note } = req.body;

        if (!decisionReason) {
            return res.status(400).json({ success: false, error: 'Release decision reason is required.' });
        }

        const result = await remediationEngine.releaseCase(caseId, req.user, decisionReason, note);
        res.json({ success: true, ...result });
    } catch (e) {
        const statusCode = e.message.includes('Insufficient permissions') || e.message.includes('Access denied') ? 403 : 400;
        res.status(statusCode).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/quarantine/:caseId/confirm-threat', requireRole('ADMIN'), async (req, res) => {
    try {
        const { caseId } = req.params;
        const { decisionReason, note } = req.body;

        const result = await remediationEngine.confirmThreat(caseId, req.user, decisionReason || 'CONFIRMED_THREAT', note);
        res.json({ success: true, ...result });
    } catch (e) {
        const statusCode = e.message.includes('Insufficient permissions') || e.message.includes('Access denied') ? 403 : 400;
        res.status(statusCode).json({ success: false, error: e.message });
    }
});

// ==================== PUB/SUB WEBHOOK ENDPOINT (AUTHENTICATED & SECURE) ====================
async function verifyPubSubRequest(req) {
    const authHeader = req.headers['authorization'];
    const secretParam = req.query.secret || req.headers['x-pubsub-secret'];
    const rotatedSecret = process.env.PUBSUB_SECRET;
    const isProduction = process.env.NODE_ENV === 'production';
    const devSecretEnabled = process.env.ENABLE_DEV_PUBSUB_SECRET === 'true' || !isProduction;

    // 1. Production OIDC / Bearer Token Verification (Google Pub/Sub Push Authentication)
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const idToken = authHeader.substring(7).trim();
        try {
            // Validate Google OIDC ID Token server-side via Google OAuth2 tokeninfo API
            const verifyRes = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`, { timeout: 5000 });
            const tokenData = verifyRes.data;
            const validIssuer = tokenData.iss === 'https://accounts.google.com' || tokenData.iss === 'accounts.google.com';
            
            if (validIssuer && tokenData.email_verified) {
                console.log(`[PubSub Verification] Verified Google Cloud Pub/Sub Service Account Push Token (${tokenData.email || 'Google PubSub'}).`);
                return { valid: true, type: 'GOOGLE_OIDC' };
            }
        } catch (e) {
            console.warn('[PubSub Verification] Failed to verify Google Bearer ID Token:', e.response?.data?.error_description || e.message);
        }
    }

    // 2. Dev-only secret verification (Disabled in Production unless explicitly permitted)
    if (devSecretEnabled && secretParam && secretParam === rotatedSecret) {
        return { valid: true, type: 'DEV_SECRET' };
    }

    // 3. Fail closed if neither authenticated OIDC nor dev secret is valid
    console.warn('[PubSub Verification] Unauthorized Pub/Sub notification attempt blocked. Rejection enforced.');
    return { valid: false, reason: 'UNAUTHORIZED_NOTIFICATION_SOURCE' };
}

app.post('/api/webhooks/gmail', async (req, res) => {
    try {
        const authCheck = await verifyPubSubRequest(req);
        if (!authCheck.valid) {
            return res.status(403).json({ success: false, error: 'Unauthorized Pub/Sub notification source.' });
        }

        const message = req.body?.message;
        if (!message || !message.data) {
            return res.status(400).json({ success: false, error: 'Invalid Pub/Sub payload.' });
        }

        const decodedString = Buffer.from(message.data, 'base64').toString('utf8');
        const pubsubData = JSON.parse(decodedString || '{}');

        console.log(`📡 [PubSub Webhook] Received Gmail Push Event for ${pubsubData.emailAddress} (HistoryId: ${pubsubData.historyId}) [Auth: ${authCheck.type}]`);

        const connection = mailboxConnectionManager.getConnectionByMailbox(pubsubData.emailAddress);
        if (!connection || connection.status !== 'CONNECTED') {
            return res.status(200).json({ status: 'IGNORED', reason: 'No active connected mailbox found.' });
        }

        // Trigger history sync asynchronously
        gmailIngestionAdapter.syncGmailHistory(connection, pubsubData.historyId).catch(err => {
            console.error('[PubSub Webhook] Async sync error:', err.message);
        });

        res.json({ success: true, status: 'RECEIVED', verification: authCheck.type });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ==================== HEALTH & METRICS ====================
app.get('/api/health', async (req, res) => {
    let detectionStatus = 'UNAVAILABLE';
    try {
        const probeRes = await axios.get(`${config.detection.endpoint}/v1/health`, { timeout: 2500 });
        if (probeRes.status === 200) {
            detectionStatus = 'READY';
        }
    } catch (e) {
        detectionStatus = process.env.DEV_DETECTION_FALLBACK === 'true' ? 'UNAVAILABLE (DEV FALLBACK ACTIVE)' : 'UNAVAILABLE';
    }

    const overallStatus = detectionStatus === 'READY' ? 'OPERATIONAL' : 'DEGRADED';

    res.json({
        status: overallStatus,
        services: {
            backend: 'READY',
            detection: detectionStatus,
            database: 'READY',
            ingestion: 'ACTIVE',
            remediation: (process.env.REMEDIATION_MODE || 'simulation').toUpperCase()
        },
        dedupMetrics: dedupStore.getStats(),
        mailboxProvider: process.env.MAILBOX_PROVIDER || 'gmail',
        detectionProvider: config.detection.provider,
        devDetectionFallback: process.env.DEV_DETECTION_FALLBACK === 'true'
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

// ==================== CASES API (DATA ISOLATION) ====================
app.get('/api/cases', (req, res) => {
    let allCases = caseManager.getAllCases();

    if (req.user) {
        if (req.user.role === 'EMPLOYEE') {
            allCases = allCases.filter(c => 
                (c.message?.recipient || '').toLowerCase().includes(req.user.email.toLowerCase()) ||
                (c.message?.sender || '').toLowerCase().includes(req.user.email.toLowerCase())
            );
        } else if (req.user.organization_id) {
            allCases = allCases.filter(c => !c.organization_id || c.organization_id === req.user.organization_id);
        }
    }

    res.json({ success: true, count: allCases.length, cases: allCases });
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

app.post('/api/remediate/approve', requireRole('ADMIN'), async (req, res) => {
    try {
        const { actionId, analystUser, reason } = req.body;
        if (!actionId) return res.status(400).json({ success: false, error: 'actionId is required' });
        const updatedAction = await remediationEngine.approveAction(actionId, analystUser || 'SOC_ANALYST', reason);
        res.json({ success: true, action: updatedAction });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/remediate/rollback', requireRole('ADMIN'), async (req, res) => {
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

app.post('/api/remediate/override', requireRole('ADMIN'), async (req, res) => {
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