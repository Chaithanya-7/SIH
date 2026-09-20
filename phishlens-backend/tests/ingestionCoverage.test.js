const test = require('node:test');
const assert = require('node:assert');

function freshRegistry() {
    delete require.cache[require.resolve('../modules/ingestionRegistry')];
    return require('../modules/ingestionRegistry');
}

test('every supported entry path is listed, including the ones switched off', () => {
    const registry = freshRegistry();
    const coverage = registry.getCoverage();
    const ids = coverage.sources.map(s => s.id);

    ['smtp_gateway', 'imap_poller', 'gmail_api', 'rest_api', 'webhook', 'file_upload']
        .forEach(id => assert.ok(ids.includes(id), `${id} must appear in the coverage report`));

    // An operator needs to see unwatched doors, not only the ones in use.
    const unconfigured = coverage.sources.filter(s => s.status === 'NOT_CONFIGURED');
    assert.ok(unconfigured.every(s => s.enable_hint), 'an unwatched source must say how to enable it');
});

test('a deployment with no automatic source is not described as monitoring mail', () => {
    const registry = freshRegistry();
    const coverage = registry.getCoverage();

    assert.strictEqual(coverage.monitoring_live_mail, false);
    assert.ok(
        coverage.warnings.some(w => /not monitoring any mailbox or gateway/i.test(w)),
        'the report must state plainly that nothing is being monitored'
    );
});

test('an active automatic source flips the monitoring state', () => {
    const registry = freshRegistry();
    registry.setState('imap_poller', {
        configured: true, enabled: true, status: registry.STATUS.ACTIVE, detail: 'Polling'
    });

    const coverage = registry.getCoverage();
    assert.strictEqual(coverage.monitoring_live_mail, true);
    assert.strictEqual(coverage.summary.automatic_active, 1);
    assert.ok(!coverage.warnings.some(w => /not monitoring any mailbox/i.test(w)));
});

/**
 * The failure that matters most: a poller that dies quietly while the rest of
 * the system keeps reporting healthy, so mail stops being examined unnoticed.
 */
test('a source that stops reporting in is marked stalled and warned about', () => {
    const registry = freshRegistry();
    registry.setState('imap_poller', {
        configured: true, enabled: true, status: registry.STATUS.ACTIVE, detail: 'Polling'
    });

    const source = registry.sources.get('imap_poller');
    const missedIntervals = source.heartbeat_seconds * 3000 + 5000;
    source.last_heartbeat_at = new Date(Date.now() - missedIntervals).toISOString();

    const coverage = registry.getCoverage();
    const imap = coverage.sources.find(s => s.id === 'imap_poller');

    assert.strictEqual(imap.status, 'STALLED');
    assert.match(imap.detail, /may not be examined/);
    assert.ok(coverage.warnings.some(w => /stopped reporting in/i.test(w)));
    assert.strictEqual(coverage.summary.stalled, 1);
});

test('a stalled source recovers when it reports in again', () => {
    const registry = freshRegistry();
    registry.setState('imap_poller', {
        configured: true, enabled: true, status: registry.STATUS.ACTIVE, detail: 'Polling'
    });
    const source = registry.sources.get('imap_poller');
    source.last_heartbeat_at = new Date(Date.now() - (source.heartbeat_seconds * 3000 + 5000)).toISOString();

    assert.strictEqual(registry.getCoverage().sources.find(s => s.id === 'imap_poller').status, 'STALLED');

    registry.heartbeat('imap_poller');
    assert.strictEqual(registry.getCoverage().sources.find(s => s.id === 'imap_poller').status, 'ACTIVE');
});

test('a source that failed to start is reported as failed with its reason', () => {
    const registry = freshRegistry();
    registry.setState('smtp_gateway', {
        configured: false, enabled: true, status: registry.STATUS.FAILED,
        detail: 'Enabled but credentials missing'
    });
    registry.recordFailure('smtp_gateway', new Error('Missing SMTP_USERNAME or SMTP_PASSWORD'));

    const coverage = registry.getCoverage();
    const smtp = coverage.sources.find(s => s.id === 'smtp_gateway');

    assert.strictEqual(smtp.status, 'FAILED');
    assert.strictEqual(smtp.failures, 1);
    assert.match(smtp.last_error.message, /Missing SMTP_USERNAME/);
    assert.ok(coverage.warnings.some(w => /failed to start/i.test(w)));
});

test('ingested message counts and timestamps are tracked per source', () => {
    const registry = freshRegistry();
    registry.recordMessage('rest_api');
    registry.recordMessage('rest_api');
    registry.recordMessage('file_upload');

    const sources = registry.getCoverage().sources;
    assert.strictEqual(sources.find(s => s.id === 'rest_api').messages_ingested, 2);
    assert.strictEqual(sources.find(s => s.id === 'file_upload').messages_ingested, 1);
    assert.ok(sources.find(s => s.id === 'rest_api').last_message_at);
    assert.strictEqual(sources.find(s => s.id === 'webhook').messages_ingested, 0);
});

test('a source with no heartbeat expectation is never marked stalled', () => {
    const registry = freshRegistry();
    registry.setState('smtp_gateway', {
        configured: true, enabled: true, status: registry.STATUS.ACTIVE, detail: 'Listening'
    });
    const source = registry.sources.get('smtp_gateway');
    source.last_heartbeat_at = new Date(Date.now() - 86400000).toISOString();

    // An idle SMTP listener is healthy; it simply has not been sent anything.
    assert.strictEqual(registry.getCoverage().sources.find(s => s.id === 'smtp_gateway').status, 'ACTIVE');
});
