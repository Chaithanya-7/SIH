const test = require('node:test');
const assert = require('node:assert');

/**
 * A connected mailbox must show up as coverage.
 *
 * The coverage page exists to answer one question: could a message reach
 * somebody without being examined. Connecting a mailbox through the console
 * used to leave it answering "nothing is being watched", because the registry
 * takes a path's status from setState and mailConnections only ever sent a
 * heartbeat. Understating coverage is the failure that matters here - it trains
 * people to ignore the page.
 */

function fresh() {
    ['../modules/mailConnections', '../modules/ingestionRegistry', '../modules/secretStore']
        .forEach(m => delete require.cache[require.resolve(m)]);
    const registry = require('../modules/ingestionRegistry');
    const connections = require('../modules/mailConnections');
    return { registry, connections };
}

function imapPath(registry) {
    return registry.getCoverage().sources.find(s => s.id === 'imap_poller');
}

test('with nothing connected the IMAP path reports disabled, and says where to connect one', () => {
    const { registry, connections } = fresh();
    connections.connections.clear();
    connections.pollers.clear();
    connections.publishCoverage();

    const path = imapPath(registry);
    assert.strictEqual(path.status, 'DISABLED');
    assert.strictEqual(path.configured, false);

    // A hint that names something which no longer exists is worse than no hint
    // at all, and both of this one's earlier versions did: first the
    // environment variables that stopped being how this works, then the
    // Mailboxes page, which was removed when connecting an account gave way to
    // watching the channels mail actually arrives through.
    assert.doesNotMatch(path.enable_hint, /IMAP_ENABLED|IMAP_USER|IMAP_HOST/,
        'the hint must not point at the removed environment-variable path');
    assert.doesNotMatch(path.enable_hint, /Mailboxes page/,
        'the hint must not point at the removed connector page');
    assert.ok(path.enable_hint && path.enable_hint.length > 20,
        'an unwatched source must still say something useful about itself');
});

test('a mailbox being polled is reported as active coverage', () => {
    const { registry, connections } = fresh();
    connections.connections.clear();
    connections.pollers.clear();

    connections.connections.set('c1', { id: 'c1', email: 'a@example.com', folder: 'INBOX' });
    connections.pollers.set('c1', setTimeout(() => {}, 0));
    connections.publishCoverage();

    const path = imapPath(registry);
    assert.strictEqual(path.status, 'ACTIVE');
    assert.strictEqual(path.enabled, true);
    assert.match(path.detail, /1 of 1/);

    assert.strictEqual(registry.getCoverage().monitoring_live_mail, true,
        'a polled mailbox means live mail is being monitored');

    clearTimeout(connections.pollers.get('c1'));
    connections.pollers.clear();
});

test('a connected mailbox that is not being polled is reported as failing, not as absent', () => {
    const { registry, connections } = fresh();
    connections.connections.clear();
    connections.pollers.clear();

    // Stored, but no poller running: credentials went stale, or the process
    // never got as far as watching it.
    connections.connections.set('c1', { id: 'c1', email: 'a@example.com', folder: 'INBOX', last_error: 'Invalid credentials' });
    connections.publishCoverage();

    const path = imapPath(registry);
    assert.strictEqual(path.status, 'FAILED', 'a mailbox that should be watched and is not must be visible');
    assert.strictEqual(path.configured, true);
});

test('removing the last mailbox reports it as gone rather than as failing', () => {
    const { registry, connections } = fresh();
    connections.connections.clear();
    connections.pollers.clear();

    connections.connections.set('c1', { id: 'c1', email: 'a@example.com', folder: 'INBOX' });
    connections.pollers.set('c1', setTimeout(() => {}, 0));
    connections.publishCoverage();
    assert.strictEqual(imapPath(registry).status, 'ACTIVE');

    // Through remove() itself, not by sequencing the steps by hand: the defect
    // this guards against is an ordering one. stopWatching runs while the
    // connection is still in the map, so publishing only from there leaves the
    // last removed mailbox looking like a failure rather than a deliberate
    // disconnection. A test that re-enacts the steps would pass either way.
    connections.remove('c1');

    const path = imapPath(registry);
    assert.strictEqual(path.status, 'DISABLED');
    assert.strictEqual(path.configured, false);
});

test('every provider offers the spam folder, because filtered phishing never reaches the inbox', () => {
    const { connections } = fresh();
    const providers = connections.providers();

    const gmail = providers.find(p => p.id === 'gmail');
    assert.ok(gmail.folders.some(f => f.path === 'INBOX'), 'the inbox must be offered');
    assert.ok(gmail.folders.some(f => /spam/i.test(f.path)), 'Gmail must offer its spam folder');

    // A folder list of exactly one entry means the console hides the choice,
    // which is correct only where the provider genuinely has nothing else.
    providers.forEach(p => {
        assert.ok(Array.isArray(p.folders) && p.folders.length >= 1, `${p.id} must name at least one folder`);
        assert.strictEqual(p.folders[0].path, 'INBOX', `${p.id} must default to the inbox`);
    });
});

test('the coverage report says which channels watch for mail and which only receive it', () => {
    const { registry } = fresh();
    const coverage = registry.getCoverage();

    // The console groups the two apart and decides from this whether to tell
    // somebody their mail is being watched. Leaving it off the wire made three
    // always-open endpoints look like three monitored channels, and the page
    // announced monitoring while nothing was watching - a coverage report
    // overstating coverage, which is the direction that gets somebody hurt.
    coverage.sources.forEach(s => {
        assert.strictEqual(typeof s.always_available, 'boolean',
            `${s.id} must say whether it watches for mail or only receives it`);
    });

    const manual = coverage.sources.filter(s => s.always_available).map(s => s.id).sort();
    assert.deepStrictEqual(manual, ['file_upload', 'rest_api', 'webhook'],
        'only the submit-to-it endpoints are always available');

    // And the summary must agree with the flags rather than being a second
    // opinion.
    const automaticActive = coverage.sources.filter(s => !s.always_available && s.status === 'ACTIVE').length;
    assert.strictEqual(coverage.summary.automatic_active, automaticActive);
    assert.strictEqual(coverage.monitoring_live_mail, automaticActive > 0);
});

test('the browser watcher is a channel the coverage report knows about', () => {
    const { registry } = fresh();
    const browser = registry.getCoverage().sources.find(s => s.id === 'browser_watch');

    assert.ok(browser, 'watching webmail in the browser must appear as a way mail is examined');
    assert.strictEqual(browser.always_available, false, 'it watches on its own rather than waiting to be sent something');
    assert.match(browser.enable_hint, /extension/i, 'it must say that it needs the browser extension');
});
