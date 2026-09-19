const detectionAdapter = require('../adapters/detectionAdapter');
const mqlBridge = require('../modules/mqlBridge');
const forensicEngine = require('../modules/forensicEngine');
const iocExtractor = require('../modules/iocExtractor');
const infraEnricher = require('../modules/infraEnricher');
const campaignGraph = require('../modules/campaignGraph');
const evidenceFusion = require('../modules/evidenceFusion');
const executiveGuard = require('../modules/executiveGuard');
const confidenceEngine = require('../modules/confidenceEngine');
const policyEngine = require('../modules/policyEngine');
const remediationEngine = require('../modules/remediationEngine');

async function test() {
    try {
        const safeEmail = `From: Security Team <security@organization.in>
To: finance@organization.in
Subject: Scheduled Maintenance
Date: Thu, 03 Sep 2026 18:10:00 +0530

Hello world`;

        const encodedMessage = Buffer.from(safeEmail).toString('base64');
        const detectionResult = await detectionAdapter.analyze(encodedMessage);
        let threatObject = mqlBridge.normalize(detectionResult, safeEmail);
        threatObject = await forensicEngine.analyzeHeaders(threatObject);
        threatObject = iocExtractor.extract(threatObject);
        threatObject = await infraEnricher.enrich(threatObject);
        threatObject = await campaignGraph.processThreatObject(threatObject);
        threatObject = evidenceFusion.fuse(threatObject);
        threatObject = executiveGuard.evaluateTarget(threatObject);
        threatObject = confidenceEngine.calculate(threatObject);
        const policyDecision = policyEngine.evaluate(threatObject);
        threatObject = await remediationEngine.executePolicyDecision(threatObject, policyDecision);
        console.log('SUCCESS:', threatObject.case_id);
    } catch (e) {
        console.error('STACK:', e.stack);
    }
}

test();
