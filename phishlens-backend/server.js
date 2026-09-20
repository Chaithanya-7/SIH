const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const config = require('./config');

// Adapters
const detectionAdapter = require('./adapters/detectionAdapter');
const mailIngestionAdapter = require('./adapters/mailIngestionAdapter');

// P0 & P1 Modules Pipeline
const emailParser = require('./modules/emailParser');
const mqlBridge = require('./modules/mqlBridge');
const authAnalyzer = require('./modules/authAnalyzer');
const forensicEngine = require('./modules/forensicEngine');
const attachmentAnalyzer = require('./modules/attachmentAnalyzer');
const iocExtractor = require('./modules/iocExtractor');
const nlpAnalyzer = require('./modules/nlpAnalyzer');
const ruleEngine = require('./modules/ruleEngine');
const customDetectionConfig = require('./modules/customDetectionConfig');
const behavioralAnalyzer = require('./modules/behavioralAnalyzer');
const adaptiveLearning = require('./modules/adaptiveLearning');
const infraEnricher = require('./modules/infraEnricher');
const threatIntelStore = require('./modules/threatIntelStore');
const threatIntelEnricher = require('./modules/threatIntelEnricher');
const rdapAdapter = require('./adapters/rdapAdapter');
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
        // Browser clients must always be explicitly allow-listed. Requests without an
        // Origin header are non-browser clients and are separately authenticated.
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS policy restricted access.'));
        }
    },
    credentials: true
}));

app.use(bodyParser.json({ limit: '50mb' }));

console.log('='.repeat(70));
console.log('🚀 PHISHLENS BACKEND — REAL-TIME AUTOMATED INGESTION & PIPELINE');
console.log(`🔑 Detection Provider: ${config.detection.provider}`);
console.log(`🌐 Detection Endpoint: ${config.detection.endpoint}`);
console.log(`📡 Server Listening on: http://localhost:${PORT}`);
console.log(`🛡️ Remediation Mode: ${process.env.REMEDIATION_MODE || 'simulation'} (${process.env.MAILBOX_PROVIDER || 'gmail'})`);
console.log('='.repeat(70));

// ==================== CORE AUTOMATED PIPELINE EXECUTION ====================
async function processPipeline(emailContent, source = 'MANUAL_API', clientMessageKey = null) {
    console.log(`\n📨 ===== AUTOMATED FORENSIC PIPELINE TRIGGERED (${source}) =====`);
    let messageKey = null;
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
        messageKey = clientMessageKey || dedupStore.computeMessageKey(rfcMessageId, emailContent);

        // SMTP, IMAP and Gmail reserve their key before calling the shared pipeline.
        // Manual API requests reserve here. Reserving a pre-reserved key again makes
        // a concurrent request look eligible for processing and can create two cases.
        if (clientMessageKey) {
            const reservation = dedupStore.getRecord(messageKey);
            if (!reservation || reservation.processing_status !== 'PROCESSING') {
                throw new Error(`Pipeline requires an active dedup reservation for ${messageKey}.`);
            }
        } else {
            const dedupCheck = dedupStore.reserveMessageKey(messageKey, {
                source,
                rfc_message_id: rfcMessageId,
                raw_sha256: rawHash
            });

            if (dedupCheck.isDuplicate && dedupCheck.isCompleted && dedupCheck.record.case_id) {
                console.log(`[Dedup] DUPLICATE MESSAGE (${messageKey}) -> Returning existing Case ${dedupCheck.record.case_id}`);
                const existingCase = caseManager.getCase(dedupCheck.record.case_id);
                if (existingCase) {
                    return existingCase;
                }
                throw new Error(`Dedup record ${messageKey} references missing case ${dedupCheck.record.case_id}.`);
            }

            if (dedupCheck.isDuplicate && dedupCheck.isProcessing) {
                throw new Error(`Message ${messageKey} is already being processed.`);
            }
        }

        // 1. Independent MIME parsing (headers, body, attachments) - owned entirely by
        //    PhishLens, no external service required.
        const parsedEmail = await emailParser.parse(emailContent);

        // 2. Optional supplementary external provider (never a hard dependency - see
        //    adapters/detectionAdapter.js). Defaults to skipped (DETECTION_PROVIDER=native).
        const detectionResult = await detectionAdapter.analyze(encodedMessage);

        // 3. Canonical ThreatObject Initialization from PhishLens' own parsed email
        let threatObject = mqlBridge.normalize(parsedEmail, detectionResult, emailContent);

        // Audit ingestion
        auditLogger.log({
            case_id: threatObject.case_id,
            event_type: 'AUTOMATED_INGESTION',
            source: source,
            description: `Email automatically ingested from ${source} (SHA-256: ${threatObject.message.raw_hash})`
        });

        // ===== PREPROCESSING: per-message facts the detection layer reasons over =====

        // 4. Independent SPF/DKIM/DMARC authentication analysis
        threatObject = await authAnalyzer.analyze(threatObject, parsedEmail, emailContent);

        // 5. Safe attachment metadata and hash analysis (no execution)
        threatObject = attachmentAnalyzer.analyze(threatObject, parsedEmail);

        // 6. IOC Extraction (IPs, Domains, URLs, Hashes)
        threatObject = iocExtractor.extract(threatObject, parsedEmail);

        // ===== DETECTION LAYER: MQL + NLP =====
        // Initial threat determination from the message itself, before any
        // enrichment that depends on the network or on stored history.

        // 7. Explainable NLP / social-engineering signal analysis
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);

        // 8. Native MQL / detection-rule engine
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail);

        // ===== FOUR ANALYSIS BRANCHES =====
        // Execution order is dictated by real data dependencies, not by
        // preference: the forensic branch selects the origin IP that both the
        // behavioural and infrastructure branches reason about, and campaign
        // correlation needs the enriched indicators the infrastructure branch
        // produces. The two branches that are genuinely independent of each
        // other are run concurrently.

        // Branch 1 - Forensic engine: trust-aware SMTP relay reconstruction
        threatObject = await forensicEngine.analyzeHeaders(threatObject);

        // Branch 2 - Behavioural analysis   ]
        // Branch 3 - IOC + infrastructure   ]  mutually independent,
        //            + threat intelligence  ]  so run concurrently
        // Each enriches a different region of the same ThreatObject.
        await Promise.all([
            Promise.resolve(behavioralAnalyzer.analyze(threatObject, parsedEmail)),
            infraEnricher.enrich(threatObject),
            threatIntelEnricher.enrich(threatObject)
        ]);

        // Branch 4 - Campaign correlation across cases (persistent SQLite graph)
        threatObject = await campaignGraph.processThreatObject(threatObject);

        // ===== CONVERGENCE: fusion, scoring, decision =====

        // Second MQL pass for rules that reason over what the branches produced
        // (indicator-feed matches, domain registration age) rather than over the
        // message alone. Detection logic stays in one auditable, cited place.
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');

        // 9. Adaptive scoring against characteristics learned from confirmed mail
        threatObject = adaptiveLearning.score(threatObject, parsedEmail);

        // 10. Evidence Fusion Engine (Normalizes all findings into EvidenceObject[])
        threatObject = evidenceFusion.fuse(threatObject);

        // 11. Executive Protection Guard (VIP Target Context)
        threatObject = executiveGuard.evaluateTarget(threatObject);

        // 12. 3-Tier Confidence Calculation Engine (also determines the final verdict)
        threatObject = confidenceEngine.calculate(threatObject);

        // 13. Contextual Policy Engine Evaluation
        const policyDecision = policyEngine.evaluate(threatObject);

        // 14. Active Disruption & Real Remediation Lifecycle Execution
        threatObject = await remediationEngine.executePolicyDecision(threatObject, policyDecision);

        // 15. Persistent Case Storage & Deduplication Binding
        threatObject = caseManager.saveCase(threatObject);
        dedupStore.bindCaseId(messageKey, threatObject.case_id);

        // 16. Post-verdict learning. The behavioural baseline records what this
        //     sender looks like, and a corroborated high-risk verdict teaches the
        //     adaptive model the characteristics that made this message malicious
        //     so later messages sharing them are recognised.
        behavioralAnalyzer.recordObservation(threatObject, parsedEmail);
        adaptiveLearning.learnFromDetection(threatObject, parsedEmail);

        console.log(`🎉 AUTOMATED PIPELINE COMPLETE! Case ID: ${threatObject.case_id} | Verdict: ${threatObject.detection.verdict} | Threat Confidence: ${threatObject.confidence.threat} | Remediation: ${threatObject.remediation.status}`);

        return threatObject;

    } catch (error) {
        if (messageKey) {
            dedupStore.markFailed(messageKey, error.message);
        }
        console.error('❌ Automated Pipeline Execution Error:', error.stack || error.message);
        throw error;
    }
}

// Start Real-Time Mail Ingestion Layer
mailIngestionAdapter.startIngestion(processPipeline);
gmailIngestionAdapter.setPipelineHandler(processPipeline);

// Protect sensitive SOC administration and data APIs
app.use([
    '/api/analyze',
    '/api/ingest/email',
    '/api/cases',
    '/api/summary',
    '/api/learning',
    '/api/threat-intelligence',
    '/api/detection-config',
    '/api/graph',
    '/api/vips',
    '/api/audit',
    '/api/remediate',
    '/api/reports',
    '/api/auth/me',
    '/api/auth/gmail',
    '/api/org',
    '/api/mailbox',
    '/api/admin'
], requireAuth);

// ==================== GOOGLE AUTHENTICATION ENDPOINTS ====================
app.post('/api/auth/google/verify', (req, res) => {
    try {
        const { googleAccountId, email, name, avatarUrl, idToken } = req.body;
        const isProduction = process.env.NODE_ENV === 'production';
        const demoIdentityEnabled = process.env.ENABLE_DEMO_IDENTITY === 'true';

        // This endpoint used to trust a user-supplied email address and call it
        // Google authentication. Only an explicitly enabled local demo may use
        // that behavior; production identity must be verified separately.
        if (isProduction) {
            return res.status(501).json({
                success: false,
                error: 'Google ID-token verification is not configured. Production identity login is disabled.'
            });
        }

        if (!demoIdentityEnabled) {
            return res.status(403).json({
                success: false,
                error: 'Demo identity is disabled. Configure real Google ID-token verification before enabling user login.'
            });
        }

        if (!email || !email.includes('@')) {
            return res.status(400).json({ success: false, error: 'A valid email is required for the explicitly enabled demo identity.' });
        }

        const { user, sessionToken } = userManager.findOrCreateFromGoogleProfile({
            googleAccountId: googleAccountId || `demo_${crypto.randomBytes(6).toString('hex')}`,
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

/**
 * Records an analyst's verdict as a training label.
 *
 * A confirmed threat is the strongest label the system can get, and a release
 * is the correction that stops a false positive recurring. Both are learned
 * immediately, so the next message sharing those characteristics is recognised
 * without waiting for any retraining cycle.
 */
function recordAnalystDecision(caseId, label, source) {
    const reviewedCase = caseManager.getCase(caseId);
    if (!reviewedCase) return null;
    return adaptiveLearning.learn(reviewedCase, null, label, source);
}

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
        res.json({ success: true, ...result, learning: recordAnalystDecision(caseId, 'benign', 'ANALYST_RELEASED') });
    } catch (e) {
        // Whether the mailbox could be reached is an operational matter; the
        // analyst's judgement that this message was legitimate is a fact about
        // the message either way, and is the single most valuable correction
        // the system can receive. Losing it because an OAuth token was missing
        // would mean the same false positive recurs forever.
        const learned = recordAnalystDecision(req.params.caseId, 'benign', 'ANALYST_RELEASED');
        const statusCode = e.message.includes('Insufficient permissions') || e.message.includes('Access denied') ? 403 : 400;
        res.status(statusCode).json({ success: false, error: e.message, learning: learned });
    }
});

app.post('/api/admin/quarantine/:caseId/confirm-threat', requireRole('ADMIN'), async (req, res) => {
    try {
        const { caseId } = req.params;
        const { decisionReason, note } = req.body;

        const result = await remediationEngine.confirmThreat(caseId, req.user, decisionReason || 'CONFIRMED_THREAT', note);
        res.json({ success: true, ...result, learning: recordAnalystDecision(caseId, 'malicious', 'ANALYST_CONFIRMED') });
    } catch (e) {
        const learned = recordAnalystDecision(req.params.caseId, 'malicious', 'ANALYST_CONFIRMED');
        const statusCode = e.message.includes('Insufficient permissions') || e.message.includes('Access denied') ? 403 : 400;
        res.status(statusCode).json({ success: false, error: e.message, learning: learned });
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
    // The native MQL/NLP/forensics detection path requires no external service
    // and is therefore always ready. An external provider, if configured, is
    // separately probed as optional supplementary enrichment.
    const nativeDetectionStatus = 'READY';
    let externalProviderStatus = 'NOT_CONFIGURED';

    if (config.detection.provider === 'sublime') {
        try {
            const probeRes = await axios.get(`${config.detection.endpoint}/v1/health`, { timeout: 2500 });
            externalProviderStatus = probeRes.status === 200 ? 'READY' : 'UNAVAILABLE';
        } catch (e) {
            externalProviderStatus = 'UNAVAILABLE';
        }
    }

    res.json({
        status: 'OPERATIONAL',
        services: {
            backend: 'READY',
            nativeDetection: nativeDetectionStatus,
            externalDetectionProvider: externalProviderStatus,
            database: 'READY',
            ingestion: 'ACTIVE',
            remediation: (process.env.REMEDIATION_MODE || 'simulation').toUpperCase()
        },
        dedupMetrics: dedupStore.getStats(),
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

/**
 * Compact verdict counts for the browser extension popup. The popup is a thin
 * client: it shows only these totals and then hands off to the desktop app or
 * dashboard for the full investigation view, so it never needs full case data.
 */
app.get('/api/summary', (req, res) => {
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

    const counts = { high_risk: 0, suspicious: 0, safe: 0, unknown: 0 };
    allCases.forEach(c => {
        const verdict = (c.detection?.verdict || 'UNKNOWN').toLowerCase();
        if (counts[verdict] === undefined) counts.unknown += 1;
        else counts[verdict] += 1;
    });

    const quarantined = allCases.filter(c => c.mailbox?.status === 'QUARANTINED').length;
    const awaitingReview = allCases.filter(c => c.review?.status === 'PENDING_ADMIN' || c.review?.status === 'UNDER_REVIEW').length;

    const latest = allCases
        .slice()
        .sort((a, b) => new Date(b.timestamps?.ingested_at || 0) - new Date(a.timestamps?.ingested_at || 0))
        .slice(0, 5)
        .map(c => ({
            case_id: c.case_id,
            subject: c.message?.subject || '(No Subject)',
            sender: c.message?.sender || '',
            verdict: c.detection?.verdict || 'UNKNOWN',
            threat_confidence: c.confidence?.threat || 0,
            ingested_at: c.timestamps?.ingested_at || null
        }));

    res.json({
        success: true,
        counts,
        total: allCases.length,
        quarantined,
        awaiting_review: awaitingReview,
        recent: latest,
        generated_at: new Date().toISOString()
    });
});

/**
 * What the system has taught itself. Exposed so the adaptive layer can be
 * inspected and audited rather than taken on trust: which characteristics it
 * associates with malicious mail, how strongly, and from how many examples.
 */
app.get('/api/learning', (req, res) => {
    res.json({
        success: true,
        adaptive: adaptiveLearning.getStats(),
        top_learned_indicators: adaptiveLearning.getTopIndicators(25),
        behavioral: behavioralAnalyzer.getStats()
    });
});

/**
 * Threat-intelligence state: which open feeds are loaded, how current they are,
 * how many indicators are held, and each feed's licence. Surfaced so an
 * operator can see exactly what the matching is based on, and under what terms.
 */
app.get('/api/threat-intelligence', (req, res) => {
    res.json({
        success: true,
        status: threatIntelStore.getStatus(),
        available_feeds: threatIntelStore.availableFeeds(),
        domain_age_cache: rdapAdapter.getStats()
    });
});

app.post('/api/threat-intelligence/sync', requireRole('ADMIN'), async (req, res) => {
    try {
        const result = await threatIntelStore.sync();
        res.json({ success: true, ...result });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ==================== OPERATOR-DEFINED DETECTION CONTENT ====================
/**
 * Lets a deployment extend detection with its own MQL rules, language patterns
 * and indicators, without editing source. Conditions are declarative and are
 * never executed as code; see modules/customDetectionConfig.js.
 */
app.get('/api/detection-config', (req, res) => {
    res.json({ success: true, ...customDetectionConfig.getAll(), schema: customDetectionConfig.getSchema() });
});

app.post('/api/detection-config/rules', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.addRule(req.body);
    if (!result.ok) return res.status(400).json({ success: false, errors: result.errors });
    auditLogger.log({
        case_id: 'CONFIG',
        event_type: 'CUSTOM_RULE_ADDED',
        source: req.user.email,
        description: `Custom detection rule ${result.rule.id} added by ${req.user.email}`
    });
    res.json({ success: true, rule: result.rule });
});

app.delete('/api/detection-config/rules/:id', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.removeRule(req.params.id);
    if (!result.ok) return res.status(404).json({ success: false, errors: result.errors });
    auditLogger.log({
        case_id: 'CONFIG',
        event_type: 'CUSTOM_RULE_REMOVED',
        source: req.user.email,
        description: `Custom detection rule ${req.params.id} removed by ${req.user.email}`
    });
    res.json({ success: true });
});

app.post('/api/detection-config/nlp-patterns', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.addNlpPattern(req.body);
    if (!result.ok) return res.status(400).json({ success: false, errors: result.errors });
    res.json({ success: true, pattern: result.pattern });
});

app.delete('/api/detection-config/nlp-patterns/:type', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.removeNlpPattern(req.params.type);
    if (!result.ok) return res.status(404).json({ success: false, errors: result.errors });
    res.json({ success: true });
});

app.post('/api/detection-config/indicators', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.addIndicators(req.body || {});
    res.json({ success: true, ...result });
});

app.delete('/api/detection-config/indicators/:value', requireRole('ADMIN'), (req, res) => {
    const result = customDetectionConfig.removeIndicator(req.params.value);
    if (!result.ok) return res.status(404).json({ success: false, errors: result.errors });
    res.json({ success: true });
});

/** Re-reads the configuration file after a direct edit, without a restart. */
app.post('/api/detection-config/reload', requireRole('ADMIN'), (req, res) => {
    customDetectionConfig.load();
    res.json({ success: true, ...customDetectionConfig.getAll() });
});

/** Checks a rule against a sample message before committing it. */
app.post('/api/detection-config/test', requireRole('ADMIN'), async (req, res) => {
    try {
        const { rule, emailContent } = req.body;
        if (!rule || !emailContent) {
            return res.status(400).json({ success: false, error: 'rule and emailContent are both required' });
        }

        const errors = customDetectionConfig.validateRule(rule);
        if (errors.length) return res.status(400).json({ success: false, errors });

        const parsedEmail = await emailParser.parse(emailContent);
        let threatObject = mqlBridge.normalize(parsedEmail, null, emailContent);
        threatObject = await authAnalyzer.analyze(threatObject, parsedEmail, emailContent);
        threatObject = attachmentAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = iocExtractor.extract(threatObject, parsedEmail);
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);

        const context = ruleEngine.buildCustomContext(threatObject, parsedEmail);
        const matched = customDetectionConfig.evaluate(rule.conditions, context);

        res.json({ success: true, matched, evaluated_context: context });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
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
    res.setHeader('Content-Disposition', `attachment; filename="PhishLens_Forensic_Report_${caseItem.case_id}.pdf"`);
    pdfReportGenerator.generateReport(caseItem, res);
});

/**
 * Keeps the local indicator set current without ever blocking startup or
 * message processing. Detection works from whatever is already on disk; a
 * refresh simply improves coverage when the network allows it. Set
 * THREAT_INTEL_AUTO_SYNC=false for a deployment that must never reach out.
 */
function scheduleThreatIntelSync() {
    if (process.env.THREAT_INTEL_AUTO_SYNC === 'false') {
        console.log('ℹ️  [ThreatIntel] Automatic feed sync disabled. Detection uses the indicators already stored locally.');
        return;
    }

    const intervalHours = Number(process.env.THREAT_INTEL_SYNC_HOURS) || 6;
    const runIfStale = () => {
        const age = threatIntelStore.ageHours();
        if (age === null || age >= intervalHours) {
            threatIntelStore.sync().catch(err => console.warn('[ThreatIntel] Scheduled sync failed:', err.message));
        }
    };

    setTimeout(runIfStale, 5000).unref?.();
    setInterval(runIfStale, intervalHours * 3600 * 1000).unref?.();
}

app.listen(PORT, () => {
    console.log(`✅ PhishLens Platform active on port ${PORT}`);
    scheduleThreatIntelSync();
});
