const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { NetworkObserver, STATE } = require('../modules/networkObserver');
const { ConnectionWatchlist } = require('../modules/connectionWatchlist');
const connectionEvidence = require('../modules/connectionEvidence');
const evidenceFusion = require('../modules/evidenceFusion');
const confidenceEngine = require('../modules/confidenceEngine');

/**
 * Network intelligence: the one evidence source that does not come from the
 * message.
 *
 * Everything else in PhishLens reasons about text a sender wrote, and a sender
 * can write anything. None of it can say what happened next. A packet capture
 * can, and that is the whole reason for having one in a mail tool.
 *
 * ## What these are mostly about
 *
 * Two properties, and they matter more than the detection itself.
 *
 * **A capture that was not running must never read as an all-clear.** A link
 * opened on a phone, a resolver using DNS-over-HTTPS, traffic leaving through a
 * VPN and nobody clicking at all produce identical silence. Turning that into
 * "no connection observed, therefore safe" would be the worst failure this
 * feature could have, because it would be reassuring and wrong.
 *
 * **It must not claim to identify a person.** The capture observes the machine,
 * not a browser and not an account. On a shared machine more than one person
 * uses that interface.
 */

const observations = (rows) => rows;

// ---------------------------------------------------------------------------
// The rolling observer
// ---------------------------------------------------------------------------

test('the observer is off until switched on, and says so', () => {
    const observer = new NetworkObserver();

    assert.strictEqual(observer.state, STATE.DISABLED);
    assert.strictEqual(observer.isObserving(), false);

    // Capturing packets records every destination a machine contacts. A
    // security tool that began doing that because it had been installed would
    // be doing something nobody asked for.
    assert.match(observer.status().detail, /switched off/i);
    assert.match(observer.status().detail, /not being collected/i);
});

test('the observer never stops saying that silence proves nothing', () => {
    const observer = new NetworkObserver();
    const status = observer.status();

    // On every report, not only when it fails. This is the conclusion somebody
    // will reach unprompted, and it is wrong.
    assert.match(status.limitation, /not evidence/i);
    assert.match(status.collects, /No payload/i);
});

test('a missing tool is reported as missing, not as a failure to observe', async () => {
    const observer = new NetworkObserver(
        { detect: async () => ({ available: false, reason: 'TShark is not installed.' }) }
    );

    const status = await observer.start();
    assert.strictEqual(status.state, STATE.UNAVAILABLE);
    assert.match(status.detail, /not installed/i);
    assert.strictEqual(status.observing, false);
});

test('permission and driver failures are told apart', () => {
    // They are fixed by completely different actions, and the difference is the
    // only useful part of the message. Collapsing both into "capture failed"
    // leaves somebody with nothing to do about it.
    const permission = new NetworkObserver();
    permission.readStderr('tshark: The capture session could not be initiated: permission denied');
    assert.strictEqual(permission.state, STATE.NOT_PERMITTED);
    assert.match(permission.detail, /administrator/i);

    const driver = new NetworkObserver();
    driver.readStderr('tshark: There are no interfaces on which a capture can be done (npcap not installed)');
    assert.strictEqual(driver.state, STATE.NO_CAPTURE_DRIVER);
    assert.match(driver.detail, /Npcap/);
});

test('the rolling memory is bounded by age as well as by count', () => {
    const observer = new NetworkObserver();

    const old = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const now = new Date().toISOString();

    observer.observations = [
        { at: old, host: 'ancient.example', address: '203.0.113.1' },
        { at: now, host: 'recent.example', address: '203.0.113.2' }
    ];
    observer.prune();

    // An observation older than the correlation window can never match
    // anything again, so keeping it would be storing a record of somebody's
    // browsing for no purpose at all.
    assert.strictEqual(observer.observations.length, 1);
    assert.strictEqual(observer.observations[0].host, 'recent.example');
});

test('partial lines from the capture are not parsed as whole ones', () => {
    // TShark writes to a pipe, so a chunk boundary can land mid-row. Parsing a
    // half-written line would invent an observation with a truncated hostname,
    // which could match the wrong indicator.
    const observer = new NetworkObserver();
    let parsed = [];
    observer.evidence = { parseFields: (text) => { parsed.push(text); return []; } };

    observer.ingest('1758000000.1\t203.0.113.5\t\t443\t\tevil.exa');
    assert.deepStrictEqual(parsed, [], 'nothing complete has arrived yet');

    observer.ingest('mple\t\n');
    assert.strictEqual(parsed.length, 1);
    assert.match(parsed[0], /evil\.example/, 'the line must be reassembled before parsing');
});

// ---------------------------------------------------------------------------
// What gets followed up, and what deliberately does not
// ---------------------------------------------------------------------------

test('only flagged cases are followed up', () => {
    const watchlist = new ConnectionWatchlist();

    const safe = watchlist.decide({
        detection: { verdict: 'SAFE' },
        iocs: { urls: ['https://ordinary.example/news'] }
    });

    // The difference between a security tool and surveillance. Enrolling every
    // case would mean holding every destination every message ever mentioned
    // and matching all of it against everywhere the machine goes - for no
    // benefit, since a connection to a host from a message already judged safe
    // tells nobody anything.
    assert.strictEqual(safe.watch, false);
    assert.match(safe.reason, /high-risk and suspicious/i);

    const flagged = watchlist.decide({
        detection: { verdict: 'HIGH_RISK' },
        iocs: { urls: ['https://evil.example/login'] }
    });
    assert.strictEqual(flagged.watch, true);
    assert.deepStrictEqual(flagged.indicators, ['evil.example']);
});

test('a flagged case with nothing to watch for says so rather than waiting', () => {
    const watchlist = new ConnectionWatchlist();

    const result = watchlist.decide({
        detection: { verdict: 'HIGH_RISK' },
        iocs: {}
    });

    // Otherwise the case shows a pending check that can never resolve, which
    // reads as "still looking" forever.
    assert.strictEqual(result.watch, false);
    assert.match(result.reason, /no host or address/i);
});

test('indicators are hosts, because a capture cannot see a path', () => {
    const watchlist = new ConnectionWatchlist();

    const result = watchlist.decide({
        detection: { verdict: 'SUSPICIOUS' },
        iocs: {
            urls: ['https://login.evil.example/account/verify?id=9'],
            domains: ['payload.evil.example'],
            ips: ['203.0.113.9']
        }
    });

    // What a capture yields is a DNS question and a TLS server name. A full URL
    // would never match anything, so storing one would be a watch that silently
    // never fires.
    assert.ok(result.indicators.includes('login.evil.example'));
    assert.ok(result.indicators.includes('payload.evil.example'));
    assert.ok(result.indicators.includes('203.0.113.9'));
    assert.ok(!result.indicators.some(i => i.includes('/')), 'no paths');
});

test('the watchlist states its own scope', () => {
    const watchlist = new ConnectionWatchlist();
    assert.match(watchlist.state().scope, /Nothing else is matched against/i);
});

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

test('a connection after the message matches; one before it does not', () => {
    const received = new Date('2026-09-26T10:00:00Z').toISOString();

    const after = connectionEvidence.correlate(observations([
        { at: new Date('2026-09-26T10:06:00Z').toISOString(), host: 'evil.example', address: '203.0.113.5', port: 443, protocol: 'TLS', kind: 'tls' }
    ]), ['evil.example'], { receivedAt: received });

    assert.strictEqual(after.matched, true);
    assert.strictEqual(after.matches[0].delay_seconds, 360);

    // Traffic before the message existed cannot have been caused by it. Counting
    // it would turn ordinary browsing into evidence of a click.
    const before = connectionEvidence.correlate(observations([
        { at: new Date('2026-09-26T09:50:00Z').toISOString(), host: 'evil.example', address: '203.0.113.5' }
    ]), ['evil.example'], { receivedAt: received });

    assert.strictEqual(before.matched, false);
});

test('a subdomain of a flagged host counts as the same destination', () => {
    const received = new Date('2026-09-26T10:00:00Z').toISOString();

    const result = connectionEvidence.correlate(observations([
        { at: new Date('2026-09-26T10:01:00Z').toISOString(), host: 'cdn.evil.example', address: '203.0.113.5' }
    ]), ['evil.example'], { receivedAt: received });

    // Dressing a link up in a subdomain is the usual shape, and treating it as
    // a different destination would make the check trivially avoidable.
    assert.strictEqual(result.matched, true);
});

// ---------------------------------------------------------------------------
// How it reaches the verdict
// ---------------------------------------------------------------------------

test('an observed connection is decisive and reaches high risk on its own', () => {
    // The warning was issued and the machine went there anyway. Nothing else
    // this system can know is more consequential, and there is no benign
    // reading of it - so it is not capped down to "suspicious" for want of
    // corroboration.
    let threatObject = {
        detection: {},
        connection_evidence: {
            status: 'OBSERVED',
            matches: [{
                indicator: 'evil.example',
                observed_host: 'evil.example',
                observed_address: '203.0.113.5',
                port: 443,
                protocol: 'TLS',
                kind: 'tls',
                at: new Date().toISOString(),
                delay_seconds: 240
            }]
        }
    };

    threatObject = evidenceFusion.fuse(threatObject);
    const connection = threatObject.evidence.find(e => e.evidence_type === 'CONNECTION_OBSERVED');
    assert.ok(connection, 'the observation must become evidence');
    assert.strictEqual(connection.decisive, true);

    threatObject = confidenceEngine.calculate(threatObject);
    assert.strictEqual(threatObject.detection.verdict, 'HIGH_RISK');

    const contribution = threatObject.confidence.contributions.find(c => c.family === 'CONNECTION');
    assert.ok(contribution, 'it must appear as its own family, not folded into infrastructure');
});

test('it never claims to know who made the connection', () => {
    let threatObject = {
        detection: {},
        connection_evidence: {
            status: 'OBSERVED',
            matches: [{ indicator: 'evil.example', observed_host: 'evil.example', observed_address: '203.0.113.5', at: new Date().toISOString(), delay_seconds: 10 }]
        }
    };

    threatObject = evidenceFusion.fuse(threatObject);
    const connection = threatObject.evidence.find(e => e.evidence_type === 'CONNECTION_OBSERVED');

    // The capture observes an interface. On a shared machine more than one
    // person uses it, and no packet says which application opened the socket.
    assert.match(connection.explanation, /not who reached it/i);
    assert.doesNotMatch(connection.finding, /user|clicked/i);
});

test('a window nobody watched scores nothing, and is not silence', () => {
    let threatObject = {
        detection: {},
        connection_evidence: {
            status: 'NOT_COLLECTED',
            detail: 'Network observation was not running for this window, so no connection evidence was collected.'
        }
    };

    threatObject = evidenceFusion.fuse(threatObject);

    // Recorded as a gap in the analysis, which is where a gap belongs - but at
    // LOW and 0.1, because not knowing is not a reason to raise a verdict.
    const gap = threatObject.evidence.find(e => e.evidence_type === 'ANALYSIS_LIMITATION');
    assert.ok(gap, 'an uncollected window belongs in the evidence, not only in a log');
    assert.strictEqual(gap.severity, 'LOW');

    threatObject = confidenceEngine.calculate(threatObject);
    assert.strictEqual(threatObject.detection.verdict, 'SAFE', 'not knowing must not raise a verdict');
});

test('watching and seeing nothing produces no evidence at all', () => {
    // The most important negative in this file. "We watched and saw nothing"
    // would read as exoneration, and a link opened on a phone, a DNS-over-HTTPS
    // resolver and a VPN all produce exactly that. So NOT_OBSERVED is recorded
    // on the case for a reader, and deliberately never becomes evidence.
    let threatObject = {
        detection: {},
        connection_evidence: {
            status: 'NOT_OBSERVED',
            detail: 'No traffic reached the destinations this message named in the window.'
        }
    };

    threatObject = evidenceFusion.fuse(threatObject);

    const anyConnectionEvidence = threatObject.evidence.filter(e =>
        e.evidence_type === 'CONNECTION_OBSERVED' || e.source === 'PHISHLENS_NETWORK_OBSERVER');
    assert.deepStrictEqual(anyConnectionEvidence, [],
        'an unmatched window must not become a finding in either direction');
});

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

test('the pipeline decides the watch before storing, and enrols after', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    const decideAt = source.indexOf('connectionWatchlist.decide(threatObject)');
    const saveAt = source.indexOf('caseManager.saveCase(threatObject)');
    const enrolAt = source.indexOf('connectionWatchlist.enrol(threatObject');

    assert.ok(decideAt > -1 && saveAt > -1 && enrolAt > -1, 'all three steps must be present');

    // Decided first, so the stored case carries the pending status rather than
    // being silently amended afterwards.
    assert.ok(decideAt < saveAt, 'the decision must be on the case before it is written');
    // Enrolled after, because saveCase can reassign a case id on collision and
    // an entry keyed to an id no case has would never resolve.
    assert.ok(enrolAt > saveAt, 'the watchlist must use the id that was actually stored');
});

test('a backlog scan is not followed up on the network', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    // Nothing observed on the network today bears on a message from two years
    // ago, and watching for its destinations would generate matches that mean
    // nothing.
    assert.match(source, /historical \? null : connectionWatchlist\.decide/,
        'historical cases must not be enrolled');
});

test('observation does not start unless it is switched on', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    assert.match(source, /ENABLE_NETWORK_OBSERVER/,
        'capturing needs an explicit decision, not an install');

    // But the sweep runs regardless: cases already waiting still need their
    // windows closed and marked unobserved, rather than sitting pending forever.
    const fn = source.slice(source.indexOf('async function startNetworkObservation'));
    const guardAt = fn.indexOf('ENABLE_NETWORK_OBSERVER');
    const sweepAt = fn.indexOf('connectionFollowUp.start()');
    assert.ok(sweepAt > -1 && sweepAt < guardAt,
        'the follow-up sweep must start even when observation is off');
});
