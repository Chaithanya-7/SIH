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

test('a row whose id sits on a child element is still identified', () => {
    const providers = loadProviders();

    // This is the shape real Gmail uses, and it is what broke: the reader looked
    // only at the row element, found every row, and dropped all of them for
    // having no id. A full inbox reported as an empty list.
    const dom = new JSDOM(`
        <table><tbody>
            <tr class="zA zE">
                <td><span data-legacy-thread-id="18f3a1b2c3d4e5f6" data-thread-id="#thread-f:18f3a1b2c3d4e5f6"></span></td>
                <td><span class="bog">Your account will be suspended</span></td>
            </tr>
        </tbody></table>
    `);

    const rows = providers.gmail.listVisible(dom.window.document);
    assert.strictEqual(rows.length, 1, 'the row was dropped because its id is on a child, not on itself');
    assert.strictEqual(rows[0].id, '18f3a1b2c3d4e5f6', 'the thread-f: prefix must be stripped');
    assert.strictEqual(rows[0].unread, true);
});

test('rows on the page are counted even when none can be identified', () => {
    const providers = loadProviders();

    // "No rows at all" and "rows I cannot identify" are different faults and
    // used to produce identical output. countRows reports the first number so
    // the popup can tell them apart.
    const dom = new JSDOM('<table><tbody><tr class="zA"><td>no identifier anywhere</td></tr></tbody></table>');

    assert.strictEqual(providers.gmail.countRows(dom.window.document), 1, 'the row is on the page');
    assert.strictEqual(providers.gmail.listVisible(dom.window.document).length, 0, 'and cannot be identified');
});

test('a row Gmail publishes no id for is still examined, under a derived one', () => {
    const providers = loadProviders();

    // Dropping such rows is what silently reported a full inbox as empty. The
    // derived id only has to be the same across sweeps and different between
    // messages; the backend deduplicates properly on the raw message after.
    const markup = `
        <table><tbody>
            <tr class="zA zE">
                <td><span email="billing@supplier.example">Billing</span></td>
                <td><span class="bog">Your account will be suspended</span></td>
                <td class="xW"><span title="Mon, 22 Sep 2026 09:14">09:14</span></td>
            </tr>
        </tbody></table>`;

    const rows = providers.gmail.listVisible(new JSDOM(markup).window.document);
    assert.strictEqual(rows.length, 1, 'the row must not be dropped for lacking a published id');
    assert.match(rows[0].id, /^derived-/, "a derived id must be marked as derived, never passed off as one Gmail published");

    // Stable: the same row read twice gives the same id, or every sweep would
    // submit the same message again as though it were new.
    const again = providers.gmail.listVisible(new JSDOM(markup).window.document);
    assert.strictEqual(again[0].id, rows[0].id, 'the derived id must be stable across sweeps');

    // And different for a different message.
    const other = providers.gmail.listVisible(new JSDOM(
        markup.replace('Your account will be suspended', 'Lunch on Thursday')
    ).window.document);
    assert.notStrictEqual(other[0].id, rows[0].id, 'two different messages must not share an id');
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

test('rows are found when the class name has changed underneath us', () => {
    const providers = loadProviders();

    // The fault the user hit: a 2,267-message inbox reported as "found no
    // messages in the list", which reads as an empty inbox rather than as a
    // broken reader.
    //
    // The reader searched for `tr.zA`, a class Gmail had used for years and is
    // free to change in any release. This markup carries identifiers exactly
    // as Gmail does and uses none of the class names the old selector knew.
    const dom = new JSDOM(`
        <div role="main">
          <div role="list">
            <div role="listitem" class="XyZ9q">
              <span data-legacy-message-id="18f3a1b2c3d4e5f6"></span>
              <span class="bog">Funds/Securities Balance</span>
            </div>
            <div role="listitem" class="XyZ9q">
              <span data-legacy-thread-id="18f3a1b2c3d4e5f7"></span>
              <span class="bog">Quick check</span>
            </div>
          </div>
        </div>
    `);

    const rows = providers.gmail.listVisible(dom.window.document);
    assert.strictEqual(rows.length, 2, 'the rows must be found without any known class name');
    assert.strictEqual(rows[0].id, '18f3a1b2c3d4e5f6');
    assert.strictEqual(providers.gmail.countRows(dom.window.document), 2,
        'and the count must agree, or the popup reports an empty inbox');
});

test('one identifier carried on several nested elements yields one row', () => {
    const providers = loadProviders();

    // Climbing from every carrier to its row would otherwise submit the same
    // message once per nested element that mentions it.
    const dom = new JSDOM(`
        <div role="main"><div role="list">
          <div role="listitem">
            <span data-legacy-message-id="18aaa"></span>
            <div><span data-thread-id="#thread-f:18aaa"></span></div>
            <span class="bog">Only one message here</span>
          </div>
        </div></div>
    `);

    assert.strictEqual(providers.gmail.findRows(dom.window.document).length, 1);
    assert.strictEqual(providers.gmail.listVisible(dom.window.document).length, 1);
});

test('an identifier outside the list is not read as a row', () => {
    const providers = loadProviders();

    // The open message in the reading pane carries the same attributes. Treating
    // it as a list row would examine whatever is on screen over and over.
    const dom = new JSDOM(`
        <div role="main">
          <div role="list">
            <div role="listitem"><span data-legacy-message-id="18real"></span></div>
          </div>
        </div>
        <aside><div data-legacy-message-id="18inpane">open message</div></aside>
    `);

    // Spread into an array of this realm before comparing. The providers module
    // is evaluated in a vm context, so the array it returns carries that
    // context's Array prototype - and deepStrictEqual compares prototypes, so
    // two arrays with identical contents fail against each other.
    const ids = [...providers.gmail.listVisible(dom.window.document).map(r => r.id)];
    assert.deepStrictEqual(ids, ['18real']);
});

test('the reader can say what it sees when it sees nothing', () => {
    const providers = loadProviders();

    // "Found no messages in the list" is unactionable and describes the failure
    // that most needs acting on. The census is what makes it fixable without
    // having the page in front of you.
    const dom = new JSDOM(`
        <div role="main"><div role="list">
          <div role="listitem" data-something-else="1">a row this reader does not understand</div>
        </div></div>
    `);

    const described = providers.gmail.describeReader(dom.window.document);

    assert.strictEqual(described.matched_by, 'nothing');
    assert.strictEqual(described.rows_found, 0);
    assert.strictEqual(described.identifier_carriers, 0);
    assert.ok(described.row_like_elements > 0, 'it must report that row-like elements do exist');
    assert.ok(described.data_attributes_seen.some(a => a.startsWith('data-something-else')),
        'and name the attributes the page actually carries, which is what widens the reader');
});

test('the class selector is still preferred when it matches', () => {
    const providers = loadProviders();

    // Exact and cheap when it works; the census only earns its cost when it
    // does not.
    const described = providers.gmail.describeReader(fixtureDocument());
    assert.strictEqual(described.matched_by, 'class selector');
    assert.ok(described.rows_by_class > 0);
});
