/**
 * Measures where time actually goes in the analysis pipeline.
 *
 * The plan is explicit that optimisation follows measurement, so this stage
 * times each module in isolation against realistic messages rather than
 * guessing at bottlenecks. Network-dependent stages are reported separately,
 * because their cost is latency to somebody else's server, not work this
 * process is doing, and they distort a CPU profile if mixed in.
 *
 * Run: node scratch/benchmark_pipeline.js [iterations]
 */

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
const semanticCorrelation = require('../modules/semanticCorrelation');

const ITERATIONS = parseInt(process.argv[2] || '200', 10);

const PASSING_AUTH = { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarc_policy: { status: 'UNAVAILABLE', policy: null } };

function buildMessage(index, { withAttachment = false, bodyRepeat = 1 } = {}) {
    const body = ('Your outstanding remittance settlement requires immediate beneficiary authorisation. '
        + 'Please confirm the updated wire transfer instructions before the settlement deadline expires today. '
        + 'Review the invoice at http://198.51.100.20/pay and confirm your password to continue. ').repeat(bodyRepeat);

    const headers = [
        `From: "Accounts Payable" <ap${index}@supplier-billing.example>`,
        `Reply-To: collections@unrelated.example`,
        'To: finance@company.example',
        `Subject: Outstanding remittance authorisation ${index}`,
        `Message-ID: <bench-${index}@supplier-billing.example>`,
        'Date: Mon, 1 Sep 2026 10:00:00 +0000',
        'Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail'
    ];

    if (!withAttachment) {
        return `${headers.join('\r\n')}\r\nContent-Type: text/plain\r\n\r\n${body}\r\n`;
    }

    const payload = Buffer.from('inert benchmark payload '.repeat(400)).toString('base64');
    return [
        ...headers,
        'Content-Type: multipart/mixed; boundary="BM"',
        '',
        '--BM',
        'Content-Type: text/plain',
        '',
        body,
        '--BM',
        'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
        'Content-Transfer-Encoding: base64',
        'Content-Disposition: attachment; filename="invoice.pdf.exe"',
        '',
        payload,
        '--BM--'
    ].join('\r\n');
}

function percentile(sorted, p) {
    if (!sorted.length) return 0;
    const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[index];
}

function summarise(label, samples) {
    const sorted = samples.slice().sort((a, b) => a - b);
    const total = samples.reduce((s, v) => s + v, 0);
    return {
        label,
        mean: total / samples.length,
        p50: percentile(sorted, 50),
        p95: percentile(sorted, 95),
        max: sorted[sorted.length - 1]
    };
}

async function main() {
    console.log(`Benchmarking the analysis pipeline over ${ITERATIONS} messages.\n`);

    const plainMessages = Array.from({ length: ITERATIONS }, (_, i) => buildMessage(i));
    const attachmentMessage = buildMessage(0, { withAttachment: true });

    // Parsing is async, so parse up front and time the synchronous stages against
    // the parsed result. Mixing the two would hide which is actually expensive.
    const parsed = [];
    const parseTimes = [];
    for (const raw of plainMessages) {
        const start = process.hrtime.bigint();
        parsed.push(await emailParser.parse(raw));
        parseTimes.push(Number(process.hrtime.bigint() - start) / 1e6);
    }

    const stages = {
        'MIME parsing': parseTimes,
        'ThreatObject build': [],
        'Attachment analysis': [],
        'IOC extraction': [],
        'NLP analysis': [],
        'MQL rules (message stage)': [],
        'Behavioural analysis': [],
        'Threat-intel lookup (local)': [],
        'Semantic correlation': [],
        'Executive guard': [],
        'Adaptive scoring': [],
        'Evidence fusion': [],
        'Confidence scoring': []
    };

    const time = (bucket, fn) => {
        const start = process.hrtime.bigint();
        const out = fn();
        stages[bucket].push(Number(process.hrtime.bigint() - start) / 1e6);
        return out;
    };

    const endToEnd = [];

    for (let i = 0; i < ITERATIONS; i++) {
        const raw = plainMessages[i];
        const parsedEmail = parsed[i];
        const wallStart = process.hrtime.bigint();

        let threatObject = time('ThreatObject build', () => mqlBridge.normalize(parsedEmail, null, raw));
        threatObject.forensics.authentication = PASSING_AUTH;

        threatObject = await time('Attachment analysis', () => attachmentAnalyzer.analyze(threatObject, parsedEmail));
        threatObject = time('IOC extraction', () => iocExtractor.extract(threatObject, parsedEmail));
        threatObject = time('NLP analysis', () => nlpAnalyzer.analyze(threatObject, parsedEmail));
        threatObject = time('MQL rules (message stage)', () => ruleEngine.evaluate(threatObject, parsedEmail, 'message'));
        threatObject = time('Behavioural analysis', () => behavioralAnalyzer.analyze(threatObject, parsedEmail));

        time('Threat-intel lookup (local)', () => {
            (threatObject.iocs?.urls || []).forEach(u => threatIntelStore.lookupUrl(u));
            (threatObject.iocs?.domains || []).forEach(d => threatIntelStore.lookupDomain(d));
            (threatObject.iocs?.ips || []).forEach(ip => threatIntelStore.lookupIp(ip));
        });

        time('Semantic correlation', () => semanticCorrelation.findSimilarCases(threatObject, parsedEmail));
        threatObject = time('Executive guard', () => executiveGuard.evaluateTarget(threatObject, parsedEmail));
        threatObject = time('Adaptive scoring', () => adaptiveLearning.score(threatObject, parsedEmail));
        threatObject = time('Evidence fusion', () => evidenceFusion.fuse(threatObject));
        threatObject = time('Confidence scoring', () => confidenceEngine.calculate(threatObject));

        endToEnd.push(Number(process.hrtime.bigint() - wallStart) / 1e6);
    }

    const rows = Object.entries(stages)
        .map(([label, samples]) => summarise(label, samples))
        .sort((a, b) => b.mean - a.mean);

    console.log('Per-stage cost (milliseconds, local CPU work only)');
    console.log('  stage'.padEnd(34) + 'mean'.padStart(9) + 'p50'.padStart(9) + 'p95'.padStart(9) + 'max'.padStart(9));
    rows.forEach(r => {
        console.log('  ' + r.label.padEnd(32)
            + r.mean.toFixed(3).padStart(9)
            + r.p50.toFixed(3).padStart(9)
            + r.p95.toFixed(3).padStart(9)
            + r.max.toFixed(3).padStart(9));
    });

    const wall = summarise('analysis', endToEnd);
    const parseSummary = summarise('parse', parseTimes);
    const perMessage = wall.mean + parseSummary.mean;

    console.log('\nPer message');
    console.log(`  parsing + analysis mean : ${perMessage.toFixed(2)} ms`);
    console.log(`  analysis p95            : ${wall.p95.toFixed(2)} ms`);
    console.log(`  sustained throughput    : ~${Math.round(1000 / perMessage)} messages/second on one core`);

    // Attachment handling is the one input-size-sensitive stage, so it is
    // measured separately rather than averaged away by small plain messages.
    const attachmentParsed = await emailParser.parse(attachmentMessage);
    const attachmentSamples = [];
    for (let i = 0; i < 50; i++) {
        const base = mqlBridge.normalize(attachmentParsed, null, attachmentMessage);
        const start = process.hrtime.bigint();
        await attachmentAnalyzer.analyze(base, attachmentParsed);
        attachmentSamples.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    const attachmentSummary = summarise('attachment', attachmentSamples);
    console.log(`\nAttachment hashing (10KB payload): mean ${attachmentSummary.mean.toFixed(3)} ms, p95 ${attachmentSummary.p95.toFixed(3)} ms`);

    console.log('\nNetwork-dependent stages are excluded above and dominate wall-clock time in');
    console.log('production: DKIM verification, RDAP domain age, DNS PTR and geolocation each');
    console.log('wait on a remote server. They run concurrently where dependencies allow.');
}

main().catch(err => {
    console.error('Benchmark failed:', err);
    process.exit(1);
});
