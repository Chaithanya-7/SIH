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
const arcAnalyzer = require('./modules/arcAnalyzer');
const textDeception = require('./modules/textDeception');
const threadIntegrity = require('./modules/threadIntegrity');
const mailConnections = require('./modules/mailConnections');
const googleOAuth = require('./modules/googleOAuth');
const qrAnalyzer = require('./modules/qrAnalyzer');
const forensicEngine = require('./modules/forensicEngine');
const attachmentAnalyzer = require('./modules/attachmentAnalyzer');
const securityTools = require('./modules/securityTools');
const connectionEvidence = require('./modules/connectionEvidence');
const yaraRules = require('./modules/yaraRules');
const iocExtractor = require('./modules/iocExtractor');
const nlpAnalyzer = require('./modules/nlpAnalyzer');
const payloadChannel = require('./modules/payloadChannel');
const trustedServiceAbuse = require('./modules/trustedServiceAbuse');
const historicalMode = require('./modules/historicalMode');
const ruleEngine = require('./modules/ruleEngine');
const customDetectionConfig = require('./modules/customDetectionConfig');
const ingestionRegistry = require('./modules/ingestionRegistry');
const behavioralAnalyzer = require('./modules/behavioralAnalyzer');
const adaptiveLearning = require('./modules/adaptiveLearning');
const infraEnricher = require('./modules/infraEnricher');
const threatIntelStore = require('./modules/threatIntelStore');
const threatIntelEnricher = require('./modules/threatIntelEnricher');
const rdapAdapter = require('./adapters/rdapAdapter');
const geoIntelAdapter = require('./adapters/geoIntelAdapter');
const evidenceFusion = require('./modules/evidenceFusion');
const confidenceEngine = require('./modules/confidenceEngine');
const caseManager = require('./modules/caseManager');
const auditLogger = require('./modules/auditLogger');
const campaignGraph = require('./modules/campaignGraph');
const executiveGuard = require('./modules/executiveGuard');
const policyEngine = require('./modules/policyEngine');
const remediationEngine = require('./modules/remediationEngine');
const remediationGateway = require('./modules/remediationGateway');
const containmentGuard = require('./modules/containmentGuard');
const dmarcAdvisor = require('./modules/dmarcAdvisor');
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
/**
 * `provenance` is how the pipeline learns that a message can be acted on.
 *
 * It used to be absent, so every case defaulted to provider GMAIL with a null
 * provider_message_id, and remediation could never resolve a target: each
 * HIGH_RISK case ended ACTION_FAILED whether or not anything was wrong. The
 * ingestion adapters had the identifiers all along - the Gmail loop held the
 * message id and mailbox, and the IMAP poller was already passing its UID into
 * an argument the pipeline did not accept - they simply were not carried
 * through to the object that needed them.
 */
async function processPipeline(emailContent, source = 'MANUAL_API', clientMessageKey = null, provenance = null, options = {}) {
    // A backlog scan runs this same pipeline deliberately - a second detection
    // path would be a second thing to keep correct. What changes is only the
    // handful of checks that describe the present rather than the moment the
    // message arrived. See modules/historicalMode.js for which and why.
    const historical = historicalMode.isHistorical(options.mode);
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

        // Recorded before anything else reads it, so containment resolves a real
        // target rather than the ThreatObject's defaults. A message with no
        // provenance is one PhishLens was handed rather than fetched, and saying
        // so plainly is what lets the remediation layer report it as
        // "not actionable" instead of "action failed".
        threatObject.message.source = source;
        if (provenance) {
            threatObject.mailbox_provenance = {
                ...threatObject.mailbox_provenance,
                ...provenance
            };
        } else {
            threatObject.mailbox_provenance.provider = 'NONE';
            threatObject.mailbox_provenance.provider_message_id = null;
        }

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

        // 4b. ARC chain (RFC 8617). Recorded as context, never as reassurance:
        //     a valid chain identifies who handled the message, not whether they
        //     can be trusted. Its one use is explaining an authentication
        //     failure caused by ordinary forwarding rather than by spoofing.
        threatObject = arcAnalyzer.analyze(threatObject, emailContent);

        // 4c. On a backlog scan, reconcile the DKIM result before anything
        //     reasons about it. The signing key is fetched live, domains rotate
        //     selectors routinely, and an old message whose selector is gone
        //     produces a header-versus-verification disagreement that fires a
        //     CRITICAL rule written for forged headers. A retired key is not a
        //     forged header, and untreated this would flag a large share of
        //     ordinary old mail.
        if (historical) {
            historicalMode.markSkippedChecks(threatObject, parsedEmail?.date);
            threatObject = historicalMode.reconcileDkim(threatObject);
        } else {
            historicalMode.markLive(threatObject);
        }

        // 5. Safe attachment metadata and hash analysis (no execution)
        threatObject = await attachmentAnalyzer.analyze(threatObject, parsedEmail);

        // 5b. QR codes in attached images, decoded locally. This runs before
        //     IOC extraction on purpose: a link inside a QR code is invisible to
        //     everything that reads the message text, and recovering it here
        //     means the feeds, domain-age and lookalike checks all apply to it
        //     exactly as they would to a link somebody typed.
        threatObject = qrAnalyzer.analyze(threatObject, parsedEmail);

        // 6. IOC Extraction (IPs, Domains, URLs, Hashes)
        threatObject = iocExtractor.extract(threatObject, parsedEmail);

        // The QR links join the IOC set rather than sitting in a separate
        // field nothing looks at.
        if (threatObject.qr?.extracted_urls?.length) {
            threatObject.iocs = threatObject.iocs || {};
            threatObject.iocs.urls = Array.from(new Set([...(threatObject.iocs.urls || []), ...threatObject.qr.extracted_urls]));
            threatObject.iocs.urls_from_qr = [...threatObject.qr.extracted_urls];
        }

        // ===== DETECTION LAYER: MQL + NLP =====
        // Initial threat determination from the message itself, before any
        // enrichment that depends on the network or on stored history.

        // 6b. Text deception. Runs before any language analysis because the
        //     language analysis reads its output: a zero-width space between
        //     each character defeats every substring match, and folding the
        //     text back is what makes the patterns applicable at all. The
        //     obfuscation itself is the stronger signal - ordinary mail does
        //     not hide characters inside words.
        threatObject = textDeception.analyze(threatObject, parsedEmail);

        // 6c. Conversation integrity. The one check AI fluency cannot help an
        //     attacker with: in a hijacked thread the prose is genuinely
        //     perfect, because it is a real conversation. What is wrong is
        //     structural - who the reply came from, and whether the thread it
        //     claims to continue ever happened here.
        threatObject = threadIntegrity.analyze(threatObject, parsedEmail);

        // 7. Explainable NLP / social-engineering signal analysis
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);

        // 7b. Where the payload actually is. Everything above this line assumes
        //     there is something to read: the language analysis needs text, the
        //     link checks need links, the inspector needs a file. Two families
        //     of attack are built so that none of those have anything to work
        //     on - the message whose only action is a phone number, and the
        //     message that is a picture. Both score near zero on every check
        //     above, and both are common. This records the shape instead.
        threatObject = payloadChannel.analyze(threatObject, parsedEmail);

        // 7c. Abuse of services that cannot be blocked. The mirror image of the
        //     authentication family: these messages pass SPF, DKIM and DMARC
        //     because they genuinely were sent by the platform they claim to
        //     come from, so the strongest evidence here contributes nothing to
        //     them. What is left wrong is structural, and that is what this
        //     looks for.
        threatObject = trustedServiceAbuse.analyze(threatObject, parsedEmail);

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
        // On a backlog scan the two enrichment branches are not run at all.
        // They would answer about the infrastructure as it is today, and for an
        // old message that is a different question from the one being asked -
        // domain age inverts, feeds have delisted what was listed, addresses
        // have changed hands. Recorded as not applicable rather than run and
        // scored as having found nothing.
        await Promise.all([
            Promise.resolve(behavioralAnalyzer.analyze(threatObject, parsedEmail)),
            historical ? Promise.resolve(null) : infraEnricher.enrich(threatObject),
            historical ? Promise.resolve(null) : threatIntelEnricher.enrich(threatObject)
        ]);

        // Branch 4 - Campaign correlation across cases (persistent SQLite graph)
        threatObject = await campaignGraph.processThreatObject(threatObject, parsedEmail);

        // ===== CONVERGENCE: fusion, scoring, decision =====

        // Second MQL pass for rules that reason over what the branches produced
        // (indicator-feed matches, domain registration age) rather than over the
        // message alone. Detection logic stays in one auditable, cited place.
        threatObject = ruleEngine.evaluate(threatObject, parsedEmail, 'enrichment');

        // 9. Adaptive scoring against characteristics learned from confirmed mail
        threatObject = adaptiveLearning.score(threatObject, parsedEmail);

        // 10. Executive protection. Runs before fusion so its findings become
        //     evidence through the same path as every other signal.
        threatObject = executiveGuard.evaluateTarget(threatObject, parsedEmail);

        // 11. Evidence Fusion Engine (Normalizes all findings into EvidenceObject[])
        threatObject = evidenceFusion.fuse(threatObject);

        // 12. 3-Tier Confidence Calculation Engine (also determines the final verdict)
        threatObject = confidenceEngine.calculate(threatObject);

        // 13. Contextual Policy Engine Evaluation
        const policyDecision = policyEngine.evaluate(threatObject);

        // 14. Active Disruption & Real Remediation Lifecycle Execution.
        //     Suppressed on a backlog scan. The decision is still computed and
        //     recorded, so a case says what would have happened - but a scan of
        //     old mail must not quarantine forty messages the recipient read
        //     two years ago. It reports; it does not act.
        if (historical) {
            threatObject.remediation = {
                status: 'SUPPRESSED_HISTORICAL',
                would_have_been: policyDecision?.action || 'NONE',
                detail: 'This message was analysed as part of a backlog scan. The policy decision was computed and is recorded, but no action was taken against a mailbox for mail that was delivered long ago.'
            };
        } else {
            threatObject = await remediationEngine.executePolicyDecision(threatObject, policyDecision);
        }

        // 15. Persistent Case Storage & Deduplication Binding
        threatObject = caseManager.saveCase(threatObject);
        dedupStore.bindCaseId(messageKey, threatObject.case_id);

        // 16. Post-verdict learning. The behavioural baseline records what this
        //     sender looks like, and a corroborated high-risk verdict teaches the
        //     adaptive model the characteristics that made this message malicious
        //     so later messages sharing them are recognised.
        behavioralAnalyzer.recordObservation(threatObject, parsedEmail);
        // Recorded after the verdict and never for high-risk mail: indexing a
        // hijacker's address as a legitimate thread participant would make the
        // next message in that conversation look normal.
        threadIntegrity.record(threatObject, parsedEmail);

        // The adaptive model does not learn from a backlog scan. Those verdicts
        // rest on a deliberately reduced evidence set, and a mailbox-sized batch
        // of them would teach the model from the weakest output this system
        // produces. The behavioural baseline above is different and does run:
        // it records what a sender's mail looks like, which is exactly what
        // history is good for, and it is why a backlog is processed oldest
        // first rather than newest.
        if (!historical) {
            adaptiveLearning.learnFromDetection(threatObject, parsedEmail);
        }

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
// Mailboxes connected through the console start watching again on restart.
mailConnections.setPipeline(processPipeline);

/**
 * Everything under /api requires authentication unless it is named below.
 *
 * This used to be the other way round: a list of protected prefixes, with
 * anything unlisted open. That shape has now failed three times. Express
 * matches mount paths on segment boundaries, so '/api/ingest' did not cover
 * '/api/ingestion' and '/api/remediate' did not cover '/api/remediation'; and
 * '/api/overview' was simply never added, so it returned every case in every
 * organisation to anyone who asked - its own isolation logic keys off req.user,
 * which nothing had populated.
 *
 * Each of those was one forgotten line. Inverting the default makes forgetting
 * the safe outcome: a new route is authenticated until somebody deliberately
 * exempts it here, and an exemption is a visible edit in a list of six rather
 * than an omission nobody can see.
 */
const PUBLIC_API_ROUTES = new Set([
    // Liveness. Deliberately answerable without a credential so the desktop
    // supervisor can tell a starting backend from an occupied port.
    '/api/health',
    // Signing in to PhishLens itself, which cannot require being signed in.
    // Note that /api/auth/gmail/* is deliberately NOT here: those connect a
    // mailbox to an existing account and read req.user.id, so they need a
    // session. Exempting them would have turned an authorization check into a
    // TypeError on undefined.
    '/api/auth/google/verify',
    // Google's push endpoint. It cannot carry our session token, and is
    // separately verified by checking the Pub/Sub JWT in verifyPubSubRequest.
    '/api/webhooks/gmail',
    // The OAuth redirect lands here from the user's browser, which has no
    // session token and cannot be given one. What protects it is the `state`
    // parameter: unguessable, single-use, and expiring in ten minutes, so a
    // request without one this server issued cannot complete a connection.
    '/api/auth/gmail/callback'
]);

app.use('/api', (req, res, next) => {
    // req.path here is relative to the '/api' mount point.
    const fullPath = '/api' + (req.path === '/' ? '' : req.path);
    if (PUBLIC_API_ROUTES.has(fullPath)) return next();
    return requireAuth(req, res, next);
});

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
/**
 * Signing in with Google.
 *
 * The client belongs to whoever runs this copy, not to us. Embedding ours would
 * make every install depend on our credential and would hand a distributed
 * secret to anyone who opened the package, so the console asks for one instead
 * and explains how to make it. It is free.
 */
app.get('/api/auth/google/client', requireRole('ADMIN'), (req, res) => {
    res.json({ success: true, ...googleOAuth.status() });
});

app.post('/api/auth/google/client', requireRole('ADMIN'), (req, res) => {
    try {
        const status = googleOAuth.saveClient({
            clientId: req.body?.clientId,
            clientSecret: req.body?.clientSecret
        });
        auditLogger.log({
            org_id: req.user.organization_id, user_id: req.user.id,
            event_type: 'GOOGLE_CLIENT_CONFIGURED', source: `ADMIN:${req.user.email}`,
            description: `Google OAuth client ${status.client_id} registered for mailbox sign-in.`
        });
        res.json({ success: true, ...status });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message, hint: e.hint || null });
    }
});

app.delete('/api/auth/google/client', requireRole('ADMIN'), (req, res) => {
    res.json({ success: true, ...googleOAuth.forgetClient() });
});

/** Starts the flow and hands back the URL for the user's real browser. */
app.post('/api/auth/google/begin', requireRole('ADMIN'), (req, res) => {
    try {
        const { url, state } = googleOAuth.begin({
            port: config.port,
            folder: req.body?.folder || 'INBOX',
            scope: req.body?.scope || 'read'
        });
        res.json({ success: true, url, state });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message, hint: e.hint || null });
    }
});

/**
 * Where Google sends the browser back.
 *
 * Responds with a page rather than JSON, because a person is looking at it.
 */
app.get('/api/auth/gmail/callback', async (req, res) => {
    const page = (title, body, tone) => `<!doctype html>
<html><head><meta charset="utf-8"><title>PhishLens</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#0f1115; color:#e6e8ec;
         display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }
  .card { max-width: 520px; padding: 32px 36px; background:#171a21; border:1px solid #262b36; border-radius:12px; }
  h1 { font-size: 1.15rem; margin:0 0 10px; color:${tone}; }
  p { font-size: 0.92rem; line-height:1.6; color:#aeb4bf; margin:0 0 8px; }
</style></head>
<body><div class="card"><h1>${title}</h1>${body}</div></body></html>`;

    try {
        if (req.query.error) {
            return res.status(400).send(page('Sign-in cancelled',
                `<p>Google reported: ${String(req.query.error).replace(/[<>]/g, '')}</p><p>Nothing was connected. You can close this tab.</p>`,
                '#e5a03a'));
        }

        const result = await googleOAuth.complete({ code: req.query.code, state: req.query.state });
        const connection = await mailConnections.addOAuth(result);

        auditLogger.log({
            event_type: 'MAILBOX_CONNECTED', source: 'GOOGLE_SSO',
            description: `Connected ${connection.email} (${connection.folder}) by signing in with Google.`
        });

        res.send(page('Connected',
            `<p><strong>${connection.email}</strong> is connected, watching <strong>${connection.folder}</strong>.</p>
             <p>PhishLens will examine new messages as they arrive. You can close this tab and return to the app.</p>`,
            '#4ade80'));
    } catch (e) {
        res.status(400).send(page('Could not connect that mailbox',
            `<p>${String(e.message).replace(/[<>]/g, '')}</p><p>Nothing was stored. You can close this tab and try again.</p>`,
            '#f87171'));
    }
});

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
        ingestionRegistry.recordMessage('rest_api');
        res.json({ success: true, threatObject });
    } catch (error) {
        ingestionRegistry.recordFailure('rest_api', error);
        res.status(500).json({ success: false, error: error.stack || error.message });
    }
});

app.post('/api/ingest/email', async (req, res) => {
    try {
        const { emailContent, source } = req.body;
        if (!emailContent) return res.status(400).json({ success: false, error: 'emailContent is required' });
        const threatObject = await processPipeline(emailContent, source || 'WEBHOOK_INBOUND');
        ingestionRegistry.recordMessage('webhook');
        res.json({ success: true, threatObject });
    } catch (error) {
        ingestionRegistry.recordFailure('webhook', error);
        res.status(500).json({ success: false, error: error.stack || error.message });
    }
});

/**
 * Messages the browser extension found in webmail, examined before they are opened.
 *
 * Two shapes arrive here, and the difference between them is not cosmetic.
 *
 * `FULL_HEADERS` carries the original message, fetched from the provider with
 * the session already in the browser. It is analysed exactly as mail from any
 * other path, because it is the same bytes.
 *
 * `BODY_ONLY` carries what could be read from the message list - a subject, a
 * sender, a snippet - because the original could not be retrieved. That is
 * enough for lookalike domains, urgent language and bad links, and not enough
 * for SPF, DKIM, DMARC or the Received chain. The distinction is recorded on
 * the case rather than smoothed over: a message whose authentication was never
 * visible must not end up looking like one that failed it.
 */
// A message is a message, not a payload.
//
// This route inherited the global 50MB JSON limit, so a single submission could
// push fifty megabytes through MIME parsing, QR decoding and language analysis.
// The file-upload route already caps at 30MB; a browser is reading what a mail
// provider chose to show somebody, which is smaller still. RFC 5321 §4.5.3.1.7
// sets no ceiling, but providers do: Gmail and Outlook both refuse beyond 25MB
// plus encoding overhead.
app.post('/api/ingest/browser', express.json({ limit: '35mb' }), async (req, res) => {
    try {
        const { raw, evidence, source, provider_message_id: providerMessageId, subject, sender, snippet, analysis_mode: analysisMode } = req.body || {};
        const complete = evidence !== 'BODY_ONLY' && typeof raw === 'string' && raw.trim().length > 0;

        let message = raw;
        if (!complete) {
            if (!subject && !sender && !snippet) {
                return res.status(400).json({ success: false, error: 'Nothing was submitted to examine.' });
            }
            // Assembled so the parser has something well-formed to read. No
            // authentication headers are invented - their absence is the honest
            // state, and the analyser already treats absent as absent rather
            // than as failed.
            message = [
                `From: ${sender || 'unknown@unknown.invalid'}`,
                'To: (recipient not visible to the browser extension)',
                `Subject: ${subject || '(no subject)'}`,
                providerMessageId ? `X-PhishLens-Provider-Message-Id: ${providerMessageId}` : null,
                'X-PhishLens-Evidence: BODY_ONLY',
                '',
                snippet || ''
            ].filter(Boolean).join('\r\n');
        }

        // A backlog sweep says so, and the pipeline then declines to run the
        // checks that would describe today's infrastructure rather than the
        // state when the message arrived. Only this exact value switches it;
        // anything else is treated as live mail.
        const mode = analysisMode === 'HISTORICAL' ? 'HISTORICAL' : 'LIVE';

        const label = `BROWSER:${String(source || 'webmail').slice(0, 80)}`;
        const threatObject = await processPipeline(message, label, null, {
            provider: 'BROWSER_EXTENSION',
            provider_account: String(source || 'webmail'),
            provider_message_id: providerMessageId ? String(providerMessageId) : null,
            evidence_completeness: complete ? 'FULL_HEADERS' : 'BODY_ONLY'
        }, { mode });

        ingestionRegistry.recordMessage('browser_watch');
        ingestionRegistry.heartbeat('browser_watch');

        // Only what the extension needs to annotate the row. The rest of the
        // case stays in the console rather than being handed back to a script
        // running inside a mail page.
        res.json({
            success: true,
            case_id: threatObject.case_id,
            verdict: threatObject.detection?.verdict || 'UNKNOWN',
            confidence: threatObject.confidence?.threat ?? null,
            evidence_completeness: complete ? 'FULL_HEADERS' : 'BODY_ONLY',
            // So the extension can label a backlog result differently from a
            // live one rather than showing them as the same kind of answer.
            analysis_mode: mode
        });
    } catch (error) {
        // Logged with its stack, not only recorded as a count. The registry
        // keeps failures in memory and loses them on restart, which is how one
        // of these became undiagnosable: by the time it was looked for, the
        // application had been restarted and the only trace was a 500 the
        // extension had already reduced to a status code.
        console.error('[BrowserIngest] Failed to examine a submitted message:', error);
        ingestionRegistry.recordFailure('browser_watch', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * Message file ingestion (.eml / .msg), for analyst-submitted samples and
 * user-reported phishing forwarded as an attachment. The body is the raw
 * message itself rather than a multipart form, so the same bytes that were on
 * disk are what get parsed and hashed.
 */
app.post('/api/ingest/file', express.text({ type: '*/*', limit: '30mb' }), async (req, res) => {
    try {
        const rawMessage = typeof req.body === 'string' ? req.body : '';
        if (!rawMessage.trim()) {
            return res.status(400).json({ success: false, error: 'Request body must contain the raw message file content' });
        }
        // A multipart form is refused rather than analysed.
        //
        // This endpoint takes the raw message, but a file input posts
        // multipart/form-data by default, and that envelope *parses* - as a
        // message with no headers carrying one attachment. So it does not
        // fail: it succeeds, reports "(No Subject)" from "unknown@domain.com",
        // finds nothing to object to, and returns SAFE. A phishing detector
        // that answers SAFE because it was handed the wrong shape is worse
        // than one that errors, because nothing downstream can tell the
        // difference. Recognised by the envelope's own signature as well as by
        // the header, so a caller that sets neither is still caught.
        const contentType = String(req.headers['content-type'] || '');
        const looksLikeFormEnvelope = /^--\S+\r?\nContent-Disposition:\s*form-data/i.test(rawMessage);
        if (contentType.includes('multipart/form-data') || looksLikeFormEnvelope) {
            return res.status(415).json({
                success: false,
                error: 'This endpoint takes the raw message, not a multipart form upload.',
                hint: 'Send the bytes of the .eml file as the request body with Content-Type: message/rfc822. Posting it as a form field would mean the form envelope is analysed instead of the message inside it.'
            });
        }

        // A .msg (Outlook OLE) file is a compound binary document, not MIME.
        if (rawMessage.startsWith('\xD0\xCF\x11\xE0')) {
            return res.status(415).json({
                success: false,
                error: 'Outlook .msg files are a compound binary format and are not supported. Export the message as .eml and submit that instead.'
            });
        }

        const filename = (req.query.filename || '').toString().slice(0, 255);
        const threatObject = await processPipeline(rawMessage, filename ? `FILE_UPLOAD:${filename}` : 'FILE_UPLOAD');
        ingestionRegistry.recordMessage('file_upload');
        res.json({ success: true, threatObject });
    } catch (error) {
        ingestionRegistry.recordFailure('file_upload', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * Ingestion coverage: every way mail can enter, whether it is actually being
 * watched, and whether anything that should be reporting in has gone quiet.
 * This is what answers "could a message reach a user without being examined".
 */
app.get('/api/ingestion', (req, res) => {
    res.json({
        success: true,
        ...ingestionRegistry.getCoverage(),
        // Deliberately not reporting where the browser extension lives.
        //
        // The backend guessed it from its own location, which is right only
        // when nothing has been configured otherwise - and the desktop
        // application may have been pointed at a checkout elsewhere. Two
        // answers to one question meant the console could print a folder that
        // was not the one being kept up to date. The application knows, and
        // tells the console directly.
        gmail: gmailIngestionAdapter.preflight()
    });
});

/**
 * Which optional open-source tools this machine has, and what their absence costs.
 *
 * Answers a question people ask about a security tool that has none of them
 * installed - "is it working?" - in a way that does not imply either that it is
 * broken or that it is complete. Every message is analysed without any of these.
 * Each one present adds a kind of evidence the message itself cannot carry.
 */
app.get('/api/security-tools', async (req, res) => {
    try {
        const detected = await securityTools.detectAll();
        res.json({
            success: true,
            ...detected,
            // Kept separate from the tool list because this is the one whose
            // absence changes what a report can claim rather than how deeply it
            // can look.
            connection_evidence: await connectionEvidence.availability(),
            // Rule matching is not optional and is not in the tool list: the
            // rules ship with PhishLens and run on an engine that is already
            // here. Installing YARA does not switch it on, it only widens what a
            // rule may be written in.
            rule_matching: yaraRules.status()
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Could not determine which tools are installed.', detail: error.message });
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
        // Carried alongside the count, because "Quarantined: 0" is ambiguous on
        // its own: it reads as "nothing was malicious" when it may mean "this
        // installation does not move mail". A reader should not have to infer
        // which.
        remediation: remediationGateway.capability(),
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
        threatObject = await attachmentAnalyzer.analyze(threatObject, parsedEmail);
        threatObject = iocExtractor.extract(threatObject, parsedEmail);
        threatObject = nlpAnalyzer.analyze(threatObject, parsedEmail);

        const context = ruleEngine.buildCustomContext(threatObject, parsedEmail);
        const matched = customDetectionConfig.evaluate(rule.conditions, context);

        res.json({ success: true, matched, evaluated_context: context });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * Aggregated view for the operations overview: every geolocated address across
 * all cases, activity over time, and detection counts by rule.
 *
 * Severity travels with each point so the map can show where the serious
 * traffic is coming from, rather than plotting every address identically.
 */
app.get('/api/overview', (req, res) => {
    let cases = caseManager.getAllCases();

    if (req.user?.role === 'EMPLOYEE') {
        cases = cases.filter(c =>
            (c.message?.recipient || '').toLowerCase().includes(req.user.email.toLowerCase()) ||
            (c.message?.sender || '').toLowerCase().includes(req.user.email.toLowerCase()));
    } else if (req.user?.organization_id) {
        cases = cases.filter(c => !c.organization_id || c.organization_id === req.user.organization_id);
    }

    const severityOf = verdict => (verdict === 'HIGH_RISK' ? 'HIGH' : verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW');

    // One marker per address per case, so repeated abuse of the same address is
    // visible as weight on the map rather than collapsing into a single dot.
    const pointsByKey = new Map();
    cases.forEach(caseItem => {
        const severity = severityOf(caseItem.detection?.verdict);
        (caseItem.infrastructure?.geo_points || []).forEach(point => {
            const key = point.ip;
            const existing = pointsByKey.get(key);
            const rank = { LOW: 0, MEDIUM: 1, HIGH: 2 };

            // The messages themselves, not just their identifiers.
            //
            // A marker that says "seen in 4 cases" answers nothing an analyst
            // wants to know. The question a dot on a map provokes is "what
            // arrived from there", and that needs the subject, who sent it and
            // what was decided - carried here so clicking a marker can answer
            // it without a second request.
            const message = {
                case_id: caseItem.case_id,
                subject: caseItem.message?.subject || '(no subject)',
                sender: caseItem.message?.sender || '(unknown sender)',
                recipient: caseItem.message?.recipient || '',
                verdict: caseItem.detection?.verdict || 'UNKNOWN',
                confidence: caseItem.confidence?.threat ?? null,
                received_at: caseItem.timestamps?.ingested_at || null,
                // The single clearest reason, so the popup can say why rather
                // than only what.
                top_finding: (caseItem.evidence || [])
                    .slice()
                    .sort((a, b) => (b.signal_strength || 0) - (a.signal_strength || 0))[0]?.finding || null
            };

            if (!existing) {
                pointsByKey.set(key, {
                    ip: point.ip,
                    latitude: point.latitude,
                    longitude: point.longitude,
                    city: point.city,
                    country: point.country,
                    country_code: point.country_code,
                    asn: point.asn,
                    isp: point.isp,
                    role: point.role,
                    severity,
                    observations: 1,
                    case_ids: [caseItem.case_id],
                    messages: [message]
                });
            } else {
                existing.observations += 1;
                if (existing.case_ids.length < 25) existing.case_ids.push(caseItem.case_id);
                // Capped: a marker popup is for orientation, not for reading an
                // entire mailbox. The full set stays one click away in the case
                // list.
                if (existing.messages.length < 10) existing.messages.push(message);
                if (rank[severity] > rank[existing.severity]) existing.severity = severity;
            }
        });
    });

    // Activity over the last 24 hours in 30-minute buckets, matching the range
    // an analyst reviewing a shift would care about.
    const bucketMs = 30 * 60 * 1000;
    const now = Date.now();
    const windowStart = now - 24 * 3600 * 1000;
    const buckets = new Map();
    for (let t = Math.floor(windowStart / bucketMs) * bucketMs; t <= now; t += bucketMs) {
        buckets.set(t, { timestamp: new Date(t).toISOString(), total: 0, high_risk: 0, suspicious: 0, safe: 0 });
    }
    cases.forEach(caseItem => {
        const at = new Date(caseItem.timestamps?.ingested_at || 0).getTime();
        if (!Number.isFinite(at) || at < windowStart) return;
        const key = Math.floor(at / bucketMs) * bucketMs;
        const bucket = buckets.get(key);
        if (!bucket) return;
        bucket.total += 1;
        const verdict = caseItem.detection?.verdict;
        if (verdict === 'HIGH_RISK') bucket.high_risk += 1;
        else if (verdict === 'SUSPICIOUS') bucket.suspicious += 1;
        else bucket.safe += 1;
    });

    // Which rules are actually firing, which is what tells an analyst what kind
    // of attack the organisation is receiving.
    const ruleCounts = new Map();
    cases.forEach(caseItem => {
        (caseItem.detection?.matched_rules || []).forEach(rule => {
            const existing = ruleCounts.get(rule.id) || { id: rule.id, name: rule.name, severity: rule.severity, events: 0 };
            existing.events += 1;
            ruleCounts.set(rule.id, existing);
        });
    });

    const sourceCounts = ingestionRegistry.getCoverage().sources
        .filter(s => s.messages_ingested > 0)
        .map(s => ({ source: s.name, count: s.messages_ingested }));

    res.json({
        success: true,
        counts: {
            total: cases.length,
            high_risk: cases.filter(c => c.detection?.verdict === 'HIGH_RISK').length,
            suspicious: cases.filter(c => c.detection?.verdict === 'SUSPICIOUS').length,
            safe: cases.filter(c => c.detection?.verdict === 'SAFE').length,
            quarantined: cases.filter(c => c.mailbox?.status === 'QUARANTINED').length,
            awaiting_review: cases.filter(c => c.review?.status === 'PENDING_ADMIN' || c.review?.status === 'UNDER_REVIEW').length,
            campaigns: new Set(cases.map(c => c.campaign?.campaign_id).filter(Boolean)).size,
            executive_incidents: cases.filter(c => c.executive_context?.is_impersonated || c.executive_context?.is_targeted).length
        },
        map_points: Array.from(pointsByKey.values()),
        timeline: Array.from(buckets.values()),
        rule_summary: Array.from(ruleCounts.values()).sort((a, b) => b.events - a.events),
        ingestion_breakdown: sourceCounts,
        geo_coverage: {
            located_addresses: pointsByKey.size,
            ...geoIntelAdapter.getStats(),
            limitation: 'Locations describe observed sending infrastructure, not the physical location of any sender. Addresses in reserved ranges, and those a provider does not expose, cannot be placed.'
        },
        generated_at: new Date().toISOString()
    });
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
/**
 * The executive directory. Only people listed here are protected against
 * impersonation and targeting detection, so the list is operator-managed
 * rather than shipped with placeholder names.
 */
app.get('/api/vips', (req, res) => {
    res.json({ success: true, vips: executiveGuard.getVipList(), directory: executiveGuard.getDirectory() });
});

app.post('/api/vips', requireRole('ADMIN'), (req, res) => {
    const result = executiveGuard.addPerson(req.body || {});
    if (!result.ok) return res.status(400).json({ success: false, errors: result.errors });
    auditLogger.log({
        case_id: 'CONFIG',
        event_type: 'PROTECTED_PERSON_ADDED',
        source: req.user.email,
        description: `${result.person.name} (${result.person.email}) added to the executive directory by ${req.user.email}`
    });
    res.json({ success: true, person: result.person });
});

app.delete('/api/vips/:id', requireRole('ADMIN'), (req, res) => {
    const result = executiveGuard.removePerson(req.params.id);
    if (!result.ok) return res.status(404).json({ success: false, errors: result.errors });
    auditLogger.log({
        case_id: 'CONFIG',
        event_type: 'PROTECTED_PERSON_REMOVED',
        source: req.user.email,
        description: `Protected person ${req.params.id} removed from the executive directory by ${req.user.email}`
    });
    res.json({ success: true });
});

/** Organisation domains, used to recognise lookalike sending domains. */
app.put('/api/vips/organization-domains', requireRole('ADMIN'), (req, res) => {
    const result = executiveGuard.setOrganizationDomains(req.body?.domains);
    if (!result.ok) return res.status(400).json({ success: false, errors: result.errors });
    res.json({ success: true, organization_domains: result.organization_domains });
});

// ==================== AUDIT LOGS API ====================
app.get('/api/audit', (req, res) => {
    res.json({
        success: true,
        events: auditLogger.getAllEvents(),
        // Surfaced with the events themselves: a log whose chain is broken
        // should never be read as though it were trustworthy.
        integrity: auditLogger.getIntegrityStatus()
    });
});

// ==================== ACTIVE DISRUPTION & REMEDIATION APIs ====================
app.get('/api/remediate/actions', (req, res) => {
    res.json({ success: true, actions: remediationEngine.getAllActions() });
});

/**
 * Approve a containment a policy raised but deliberately did not carry out.
 *
 * The acting analyst is taken from the authenticated session. It used to be
 * read out of the request body, which let a caller name anybody as the
 * approver of an action that moves somebody's mail - the one field in an audit
 * record that has to be trustworthy.
 */
app.post('/api/remediate/approve', requireRole('ADMIN'), async (req, res) => {
    try {
        const { actionId, reason } = req.body;
        if (!actionId) return res.status(400).json({ success: false, error: 'actionId is required' });
        const updatedAction = await remediationEngine.approveAction(actionId, req.user, reason || 'Analyst approved');
        res.json({ success: true, action: updatedAction });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

/** Containment requests raised by policy and waiting on a person. */
app.get('/api/remediate/pending', requireRole('ADMIN'), (req, res) => {
    res.json({ success: true, actions: remediationEngine.getPendingApprovals() });
});

app.post('/api/remediate/rollback', requireRole('ADMIN'), async (req, res) => {
    try {
        const { actionId, reason } = req.body;
        if (!actionId) return res.status(400).json({ success: false, error: 'actionId is required' });
        const updatedAction = await remediationEngine.rollbackAction(actionId, req.user, reason || 'Analyst rollback');
        res.json({ success: true, action: updatedAction });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
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
    try {
        const { caseId, action } = req.body;
        if (!caseId || !action) return res.status(400).json({ success: false, error: 'caseId and action are required' });
        const result = await remediationEngine.adminOverride(caseId, action, req.user);
        res.json({ success: true, result });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

// ==================== CONNECTED MAILBOXES ====================

/**
 * Connecting a mailbox over IMAP with an app password.
 *
 * The Gmail API route needs the operator to register an OAuth application,
 * which leaves the product unusable until that administrative work is done. An
 * app password takes a minute to create and reaches the same mail.
 */
app.get('/api/connections', requireRole('ADMIN'), (req, res) => {
    res.json({
        success: true,
        providers: mailConnections.providers(),
        ...mailConnections.coverage()
    });
});

app.post('/api/connections', requireRole('ADMIN'), async (req, res) => {
    try {
        const connection = await mailConnections.add(req.body || {});
        auditLogger.log({
            org_id: req.user.organization_id, user_id: req.user.id,
            event_type: 'MAILBOX_CONNECTED', source: `ADMIN:${req.user.email}`,
            description: `Connected mailbox ${connection.email} over IMAP (${connection.host}).`
        });
        res.json({ success: true, connection });
    } catch (e) {
        // The hint carries the provider-specific guidance, because "password
        // rejected" tells somebody with two-step verification nothing about
        // what to do next.
        res.status(400).json({ success: false, error: e.message, hint: e.hint || null });
    }
});

/** Checks credentials without storing anything. */
app.post('/api/connections/test', requireRole('ADMIN'), async (req, res) => {
    const { email, password, host, port, folder, provider } = req.body || {};
    const preset = require('./modules/mailConnections').PROVIDERS[provider] || {};
    const result = await mailConnections.test({
        email, password,
        host: host || preset.host,
        port: Number(port || preset.port || 993),
        folder: folder || 'INBOX'
    });
    res.json({ success: result.ok, ...result });
});

app.delete('/api/connections/:id', requireRole('ADMIN'), (req, res) => {
    try {
        const result = mailConnections.remove(req.params.id);
        auditLogger.log({
            org_id: req.user.organization_id, user_id: req.user.id,
            event_type: 'MAILBOX_DISCONNECTED', source: `ADMIN:${req.user.email}`,
            description: `Disconnected mailbox ${result.removed}.`
        });
        res.json({ success: true, ...result });
    } catch (e) {
        res.status(404).json({ success: false, error: e.message });
    }
});

// ==================== REMEDIATION POSTURE & SAFETY CONTROLS ====================

/**
 * What this installation can and cannot do to mail, stated without overstating.
 *
 * An operator should be able to answer "is anything actually being contained?"
 * from one request, rather than inferring it from a boot log.
 */
app.get('/api/remediation/posture', (req, res) => {
    res.json({
        success: true,
        capability: remediationGateway.capability(),
        guard: containmentGuard.state(),
        pending_approvals: remediationEngine.getPendingApprovals().length
    });
});

/** What would happen to one case, without anything happening. */
app.get('/api/remediation/preview/:caseId', requireRole('ADMIN'), (req, res) => {
    const threatObject = caseManager.getCase(req.params.caseId);
    if (!threatObject) return res.status(404).json({ success: false, error: 'Case not found' });
    res.json({ success: true, preview: remediationGateway.preview(threatObject) });
});

/**
 * The never-contain list: senders PhishLens must not move automatically.
 * The realistic failure it prevents is a detection change quarantining payroll
 * or the service desk - mail whose delay costs more than the phishing it might
 * occasionally carry.
 */
app.get('/api/remediation/never-contain', requireRole('ADMIN'), (req, res) => {
    res.json({ success: true, entries: containmentGuard.state().never_contain });
});

app.post('/api/remediation/never-contain', requireRole('ADMIN'), (req, res) => {
    try {
        const entries = containmentGuard.addNeverContain(req.body?.entry);
        auditLogger.log({
            org_id: req.user.organization_id, user_id: req.user.id,
            event_type: 'NEVER_CONTAIN_ADDED', source: `ADMIN:${req.user.email}`,
            description: `Added '${req.body.entry}' to the never-contain list.`
        });
        res.json({ success: true, entries });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

/**
 * The only control here that stops a phishing message being deliverable at all,
 * rather than catching it after it arrives: what your own domains publish.
 */
app.get('/api/remediation/domain-posture', async (req, res) => {
    try {
        res.json({ success: true, ...(await dmarcAdvisor.assessOwnDomains()) });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/remediation/domain-posture/:domain', async (req, res) => {
    try {
        res.json({ success: true, assessment: await dmarcAdvisor.assess(req.params.domain) });
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

app.delete('/api/remediation/never-contain/:entry', requireRole('ADMIN'), (req, res) => {
    const entries = containmentGuard.removeNeverContain(decodeURIComponent(req.params.entry));
    auditLogger.log({
        org_id: req.user.organization_id, user_id: req.user.id,
        event_type: 'NEVER_CONTAIN_REMOVED', source: `ADMIN:${req.user.email}`,
        description: `Removed '${req.params.entry}' from the never-contain list.`
    });
    res.json({ success: true, entries });
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
