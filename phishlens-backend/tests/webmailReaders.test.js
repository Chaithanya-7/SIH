const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');

/**
 * The webmail readers, run against a real DOM.
 *
 * These are the assumption the whole browser channel rests on. Everything else
 * in that channel is ours and can be tested directly; this part depends on what
 * Gmail and Outlook put on the page, which is theirs and can change without
 * notice.
 *
 * There was a fixture for this in the extension folder and nothing that ran it,
 * so the checks existed only as something once done by hand. A reader that
 * quietly stops matching produces no errors at all - it finds no rows, examines
 * nothing, and looks exactly like an empty inbox.
 *
 * ## What this proves, and what it cannot
 *
 * It proves the readers do the right thing with markup shaped like Gmail's:
 * find rows, read identifiers, tell unread from read, skip a row with no
 * identifier, build the right "show original" address, and refuse a sign-in
 * page handed back in place of a message.
 *
 * It cannot prove Gmail still looks like this. Only opening real mail shows
 * that, which is why the extension now reports how many rows each sweep saw.
 */

const EXTENSION = path.join(__dirname, '..', '..', 'phishlens-extension');
const FIXTURE = path.join(EXTENSION, 'tests', 'provider-fixture.html');

/** Loads mail-providers.js the way a content script would, and hands back its exports. */
function loadProviders() {
    const source = fs.readFileSync(path.join(EXTENSION, 'mail-providers.js'), 'utf8');
    const sandbox = { window: {}, globalThis: {}, module: { exports: {} } };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox);

    return sandbox.module.exports?.forHostname
        ? sandbox.module.exports
        : (sandbox.PhishLensMailProviders || sandbox.window.PhishLensMailProviders);
}

const fixtureDocument = () => new JSDOM(fs.readFileSync(FIXTURE, 'utf8')).window.document;

test('the fixture the readers are checked against still exists', () => {
    // Windows Defender removed this file once: it is Gmail-shaped markup
    // advertising a suspended PayPal account, which is exactly what a phishing
    // page looks like. Losing it silently would take these tests with it.
    assert.ok(fs.existsSync(FIXTURE), 'the provider fixture is missing from the extension');
    assert.ok(fs.readFileSync(FIXTURE, 'utf8').includes('gmail-fixture'), 'the fixture is not the one these tests expect');
});

test('the providers module loads and resolves a host', () => {
    const providers = loadProviders();
    assert.ok(providers, 'mail-providers.js exported nothing usable');

    assert.strictEqual(providers.forHostname('mail.google.com')?.id, 'gmail');
    assert.strictEqual(providers.forHostname('outlook.live.com')?.id, 'outlook');
    assert.strictEqual(providers.forHostname('outlook.office365.com')?.id, 'outlook');
    assert.strictEqual(providers.forHostname('example.com'), null, 'an unrelated site must match no reader');
});

test('the Gmail reader finds message rows in Gmail-shaped markup', () => {
    const providers = loadProviders();
    const rows = providers.gmail.listVisible(fixtureDocument());

    assert.ok(rows.length > 0, 'no rows found - the reader no longer matches this markup');
    for (const row of rows) {
        assert.ok(row.id, 'every row must carry an identifier');
        assert.ok(row.row, 'every row must carry its element, for labelling later');
        assert.strictEqual(typeof row.unread, 'boolean');
    }
});

test('unread messages are told apart from read ones', () => {
    const providers = loadProviders();
    const rows = providers.gmail.listVisible(fixtureDocument());

    // The whole reason for watching the list rather than the open message.
    assert.ok(rows.some(r => r.unread), 'no unread row was recognised');
    assert.ok(rows.some(r => !r.unread), 'every row was called unread, so the test is not discriminating');
});

test('a row with no identifier is skipped rather than guessed at', () => {
    const providers = loadProviders();
    const rows = providers.gmail.listVisible(fixtureDocument());

    // Submitting a message with no id would be deduplicated against every other
    // id-less message, so one would stand in for all of them.
    assert.ok(rows.every(r => r.id && r.id.length > 0));
});

test('the show-original address is built only when the session key is known', () => {
    const providers = loadProviders();
    const location = { origin: 'https://mail.google.com', pathname: '/mail/u/0/' };

    assert.strictEqual(providers.gmail.rawUrl('18f3a1b2c3d4e5f6', location, null), null,
        'without the session key there is no address to fetch, and guessing one returns a sign-in page');

    const url = providers.gmail.rawUrl('18f3a1b2c3d4e5f6', location, 'abc123');
    assert.match(url, /view=om/, 'it must ask for the original message');
    assert.match(url, /ik=abc123/, 'it must carry the session key');
    assert.match(url, /permmsgid=msg-f:18f3a1b2c3d4e5f6/, 'it must name the message');
});

test('the session key is read out of the page', () => {
    const providers = loadProviders();
    const key = providers.gmail.inboxKey(fixtureDocument());
    assert.ok(key, 'no session key found, so no raw message could ever be fetched');
});

test('a sign-in page is refused in place of a message', () => {
    const providers = loadProviders();

    // The endpoint answers with a login page once the session lapses. Parsed as
    // a message it has no headers at all, so it would be analysed as mail that
    // failed every authentication check - a false alarm manufactured by us.
    assert.strictEqual(providers.gmail.looksLikeRawMessage('<!doctype html><html><body>Sign in</body></html>'), false);
    assert.strictEqual(providers.gmail.looksLikeRawMessage(''), false);
    assert.strictEqual(providers.gmail.looksLikeRawMessage(null), false);

    const real = ['Delivered-To: someone@example.com', 'From: a@b.example', 'Subject: Hello', '', 'Body'].join('\r\n');
    assert.strictEqual(providers.gmail.looksLikeRawMessage(real), true, 'a real message must be accepted');
});

test('the fallback reads something usable when the raw message cannot be fetched', () => {
    const providers = loadProviders();
    const rows = providers.gmail.listVisible(fixtureDocument());
    const fallback = providers.gmail.fallback(rows[0]);

    // Not as good as the real message, and it is labelled BODY_ONLY where it is
    // used, so nothing downstream treats it as a full header analysis.
    assert.ok(typeof fallback.subject === 'string');
    assert.ok(typeof fallback.sender === 'string');
    assert.ok(fallback.subject || fallback.sender || fallback.snippet, 'the fallback read nothing at all');
});
