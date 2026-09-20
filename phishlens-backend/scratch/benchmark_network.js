/**
 * Measures the network-dependent stages, which the CPU profile deliberately
 * excluded. Local analysis costs about a millisecond per message; if a single
 * remote lookup costs hundreds, that is where wall-clock time actually goes and
 * where concurrency matters.
 *
 * Run: node scratch/benchmark_network.js
 */

const authAnalyzer = require('../modules/authAnalyzer');
const rdapAdapter = require('../adapters/rdapAdapter');
const dnsAdapter = require('../adapters/dnsAdapter');
const emailParser = require('../modules/emailParser');
const mqlBridge = require('../modules/mqlBridge');

const SAMPLE = [
    'From: "Accounts" <ap@github.com>',
    'To: finance@company.example',
    'Subject: Remittance',
    'Message-ID: <net-bench@github.com>',
    'Date: Mon, 1 Sep 2026 10:00:00 +0000',
    'Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail',
    'Content-Type: text/plain',
    '',
    'Please review the attached remittance advice.'
].join('\r\n');

async function timed(label, fn) {
    const start = process.hrtime.bigint();
    let outcome = 'ok';
    try {
        await fn();
    } catch (e) {
        outcome = `failed: ${e.message}`;
    }
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    return { label, ms, outcome };
}

async function main() {
    console.log('Measuring network-dependent stages (single sample each; these vary with link and registry load).\n');

    const results = [];

    // Cold: nothing cached yet.
    results.push(await timed('DKIM independent verification', () => authAnalyzer.verifyDkimIndependently(SAMPLE)));
    results.push(await timed('DMARC policy lookup (DNS TXT)', () => authAnalyzer.lookupDmarcPolicy('github.com')));
    results.push(await timed('RDAP domain age (cold)', () => rdapAdapter.lookupDomainAge('wikipedia.org')));
    results.push(await timed('RDAP domain age (cached)', () => rdapAdapter.lookupDomainAge('wikipedia.org')));
    results.push(await timed('Reverse DNS PTR', () => dnsAdapter.lookupPtr('1.1.1.1')));

    console.log('  stage'.padEnd(36) + 'ms'.padStart(10) + '   outcome');
    results.forEach(r => {
        console.log('  ' + r.label.padEnd(34) + r.ms.toFixed(1).padStart(10) + '   ' + r.outcome);
    });

    // The authentication stage runs DKIM verification and the DMARC lookup one
    // after the other, although neither depends on the other's result.
    const parsedEmail = await emailParser.parse(SAMPLE);
    const threatObject = mqlBridge.normalize(parsedEmail, null, SAMPLE);

    const sequentialStart = process.hrtime.bigint();
    await authAnalyzer.verifyDkimIndependently(SAMPLE);
    await authAnalyzer.lookupDmarcPolicy('github.com');
    const sequentialMs = Number(process.hrtime.bigint() - sequentialStart) / 1e6;

    const concurrentStart = process.hrtime.bigint();
    await Promise.all([
        authAnalyzer.verifyDkimIndependently(SAMPLE),
        authAnalyzer.lookupDmarcPolicy('github.com')
    ]);
    const concurrentMs = Number(process.hrtime.bigint() - concurrentStart) / 1e6;

    console.log('\nAuthentication stage: two independent lookups');
    console.log(`  run one after the other : ${sequentialMs.toFixed(1)} ms`);
    console.log(`  run concurrently        : ${concurrentMs.toFixed(1)} ms`);
    console.log(`  saving                  : ${(sequentialMs - concurrentMs).toFixed(1)} ms per message`);

    const fullStart = process.hrtime.bigint();
    await authAnalyzer.analyze(threatObject, parsedEmail, SAMPLE);
    console.log(`\nauthAnalyzer.analyze() as currently implemented: ${(Number(process.hrtime.bigint() - fullStart) / 1e6).toFixed(1)} ms`);
}

main().catch(e => { console.error(e); process.exit(1); });
