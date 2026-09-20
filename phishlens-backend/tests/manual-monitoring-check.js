/**
 * Does the installed application actually monitor mail?
 *
 * Not "does it start", and not "does the endpoint exist" - does a message
 * arriving on a monitored channel become a case, with a verdict, visible in the
 * console. That is the question that went unasked while this feature was
 * shipped twice.
 *
 * Runs against the installed app's own backend on port 3001, using the key it
 * generated for itself.
 */

const fs = require('fs');
const path = require('path');

const KEY_FILE = path.join(process.env.APPDATA || '', 'phishlens-desktop', 'desktop-api-key');
const BASE = 'http://localhost:3001';

const stamp = Date.now();

function rawMessage(n) {
    return [
        'Return-Path: <security@micros0ft-verify.tk>',
        'Received: from mail.micros0ft-verify.tk (185.220.101.44) by mx.google.com; Sat, 20 Sep 2026 12:00:00 +0000',
        'Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=micros0ft-verify.tk; dkim=none; dmarc=fail',
        'From: "Microsoft Security" <security@micros0ft-verify.tk>',
        'To: you@example.com',
        'Subject: Unusual sign-in detected - verify within 24 hours',
        `Message-ID: <monitor-${stamp}-${n}@micros0ft-verify.tk>`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'We noticed a sign-in from an unrecognised device.',
        'Confirm your identity immediately or your account will be locked.',
        '',
        'Verify now: http://micros0ft-verify.tk/login',
        ''
    ].join('\r\n');
}

async function main() {
    const key = fs.readFileSync(KEY_FILE, 'utf8').trim();
    const auth = { 'x-api-key': key, 'Content-Type': 'application/json' };

    const before = await (await fetch(`${BASE}/api/cases`, { headers: auth })).json();
    const countBefore = before.count ?? (before.cases || []).length;
    console.log(`cases before                : ${countBefore}`);

    // --- the browser channel, as the extension would use it ---------------
    console.log('');
    console.log('--- browser channel: a message seen in webmail ---');
    const browserRes = await fetch(`${BASE}/api/ingest/browser`, {
        method: 'POST',
        headers: auth,
        body: JSON.stringify({
            source: 'mail.google.com',
            provider_message_id: `msg-${stamp}`,
            raw: rawMessage('a'),
            evidence: 'FULL_HEADERS'
        })
    });
    const browser = await browserRes.json();
    console.log(`  HTTP ${browserRes.status} -> ${browser.verdict} at ${browser.confidence} (${browser.evidence_completeness})`);
    console.log(`  case: ${browser.case_id}`);

    // --- the same message with only what a row shows -----------------------
    console.log('');
    console.log('--- browser channel: only what the message list shows ---');
    const rowRes = await fetch(`${BASE}/api/ingest/browser`, {
        method: 'POST',
        headers: auth,
        body: JSON.stringify({
            source: 'outlook.live.com',
            provider_message_id: `row-${stamp}`,
            evidence: 'BODY_ONLY',
            subject: 'Unusual sign-in detected - verify within 24 hours',
            sender: 'security@micros0ft-verify.tk',
            snippet: 'Confirm your identity immediately or your account will be locked.'
        })
    });
    const row = await rowRes.json();
    console.log(`  HTTP ${rowRes.status} -> ${row.verdict} at ${row.confidence} (${row.evidence_completeness})`);

    // --- did the cases actually land -------------------------------------
    console.log('');
    const after = await (await fetch(`${BASE}/api/cases`, { headers: auth })).json();
    const cases = after.cases || [];
    const countAfter = after.count ?? cases.length;
    console.log(`cases after                 : ${countAfter}  (+${countAfter - countBefore})`);

    const landed = cases.find(c => c.case_id === browser.case_id);
    console.log(`the browser case is in the list: ${landed ? 'yes' : 'NO'}`);
    if (landed) {
        console.log(`  subject   : ${landed.message.subject}`);
        console.log(`  sender    : ${landed.message.sender}`);
        console.log(`  source    : ${landed.message.source}`);
        console.log('  findings  :');
        (landed.evidence || []).slice(0, 6).forEach(e => console.log(`     - ${e.severity} | ${e.finding}`));
    }

    // --- does coverage now report the browser channel as live -------------
    console.log('');
    const coverage = await (await fetch(`${BASE}/api/ingestion`, { headers: auth })).json();
    const watcher = (coverage.sources || []).find(s => s.id === 'browser_watch');
    console.log('--- coverage ---');
    console.log(`  browser channel status   : ${watcher ? watcher.status : 'MISSING'}`);
    console.log(`  messages through it      : ${watcher ? watcher.messages_ingested : '-'}`);
    console.log(`  monitoring_live_mail     : ${coverage.monitoring_live_mail}`);
    console.log(`  automatic_active         : ${coverage.summary?.automatic_active}`);

    // Not "did it say HIGH_RISK". A fresh install has no correlation history, so
    // the same message that reaches 0.93 on a database with related cases
    // reaches less here - and that is the confidence engine being honest, not a
    // fault. What must be true is that the message was examined, became a case,
    // was judged dangerous enough to warn about, and that having the headers
    // produced more evidence and more certainty than not having them.
    const flagged = ['HIGH_RISK', 'SUSPICIOUS'];
    const authFindings = (landed?.evidence || []).filter(e => /SPF|DKIM|DMARC/i.test(e.finding)).length;
    const worked = browserRes.ok
        && rowRes.ok
        && !!landed
        && flagged.includes(browser.verdict)
        && flagged.includes(row.verdict)
        && row.evidence_completeness === 'BODY_ONLY'
        && authFindings > 0
        && browser.confidence > row.confidence;

    console.log('');
    console.log(`  authentication findings from the original : ${authFindings}`);
    console.log(`  confidence with headers vs without        : ${browser.confidence} vs ${row.confidence}`);
    console.log('');
    console.log(worked ? 'MONITORING WORKS' : 'SOMETHING DID NOT WORK');
    process.exit(worked ? 0 : 1);
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(2); });
