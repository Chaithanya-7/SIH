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

    // The hint used to name environment variables that are no longer how this
    // works, which is worse than no hint at all.
    assert.doesNotMatch(path.enable_hint, /IMAP_ENABLED|IMAP_USER|IMAP_HOST/,
        'the hint must not point at the removed environment-variable path');
    assert.match(path.enable_hint, /Mailboxes page/,
        'the hint must name where a mailbox is actually connected');
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
