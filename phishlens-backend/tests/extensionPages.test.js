const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

/**
 * The extension's own pages, actually run.
 *
 * These exist because of a bug that reached the user's browser: the popup
 * called showWatchState() and the function was never defined. An edit script
 * failed part-way, the call landed, the definition did not, and `node --check`
 * reported the file as fine - because an undefined function is not a syntax
 * error. It is a ReferenceError at the moment the line runs, and the only thing
 * that catches it is running the line.
 *
 * So the pages are loaded here the way a browser loads them: the real HTML,
 * every script it references, in order, with the extension APIs stubbed. If a
 * page throws while opening, these fail.
 *
 * This is not a UI test. Nothing is asserted about what is rendered - only that
 * the page runs without throwing, which is the failure that actually shipped.
 */

const EXTENSION = path.join(__dirname, '..', '..', 'phishlens-extension');

/** Built from character codes: a literal newline here has been eaten twice by editing layers. */
const SEPARATOR = String.fromCharCode(10) + ';' + String.fromCharCode(10);

/** A chrome/browser API surface wide enough for these pages to start. */
function extensionApiStub() {
    const noop = () => {};
    return {
        runtime: {
            lastError: null,
            // Answers nothing. A page must cope with a worker that never
            // replies, which is the normal case for a sleeping MV3 worker.
            sendMessage: (message, callback) => { if (typeof callback === 'function') callback(undefined); },
            openOptionsPage: noop,
            getURL: p => p
        },
        storage: {
            local: {
                get: (defaults, callback) => { if (typeof callback === 'function') callback({}); },
                set: (values, callback) => { if (typeof callback === 'function') callback(); }
            }
        },
        tabs: { create: noop },
        action: { setBadgeText: noop, setBadgeBackgroundColor: noop },
        alarms: { create: noop, onAlarm: { addListener: noop } }
    };
}

/**
 * Loads one of the extension's HTML pages with its scripts, and returns
 * anything that went wrong while it started.
 */
async function runPage(pageName) {
    const html = fs.readFileSync(path.join(EXTENSION, pageName), 'utf8');
    const errors = [];

    const dom = new JSDOM(html, {
        runScripts: 'outside-only',
        pretendToBeVisual: true,
        url: 'chrome-extension://phishlens-test/' + pageName
    });

    const { window } = dom;
    window.chrome = extensionApiStub();
    window.browser = undefined;
    window.fetch = () => Promise.reject(new Error('network disabled in this test'));
    window.onerror = (message) => { errors.push(String(message)); };
    window.addEventListener('error', e => errors.push(String(e.message || e)));
    window.addEventListener('unhandledrejection', e => errors.push(String(e.reason && e.reason.message || e.reason)));

    // The scripts the page references, in the order it references them.
    const sources = [...html.matchAll(/<script[^>]*src="([^"]+)"/g)].map(m => m[1]);
    assert.ok(sources.length, `${pageName} references no scripts, which cannot be right`);

    // Concatenated and evaluated once, because separate <script> tags share one
    // global lexical scope and separate eval() calls do not: a top-level const
    // in one eval is invisible to the next, so config.js would appear undefined
    // to popup.js purely as an artefact of how this test ran it.
    const combined = [];
    for (const src of sources) {
        const file = path.join(EXTENSION, src);
        assert.ok(fs.existsSync(file), `${pageName} references ${src}, which does not exist`);
        combined.push(`//# ${src}
` + fs.readFileSync(file, 'utf8'));
    }

    try {
        window.eval(combined.join(SEPARATOR));
    } catch (e) {
        errors.push(e.message);
    }

    // The pages do their work on DOMContentLoaded, so nothing above has run yet.
    try {
        window.document.dispatchEvent(new window.Event('DOMContentLoaded', { bubbles: true }));
    } catch (e) {
        errors.push(`DOMContentLoaded: ${e.message}`);
    }

    // Let anything asynchronous that was started settle.
    await new Promise(resolve => setTimeout(resolve, 50));

    dom.window.close();
    return errors;
}

test('the popup opens without throwing', async () => {
    const errors = await runPage('popup.html');

    // The exact shape of the bug that shipped: a call with no definition.
    assert.deepStrictEqual(errors, [],
        'the popup threw while opening, which is what leaves it stuck on "Connecting…"');
});

test('the options page opens without throwing', async () => {
    const errors = await runPage('options.html');
    assert.deepStrictEqual(errors, []);
});

test('every element the popup looks up exists in its HTML', () => {
    const html = fs.readFileSync(path.join(EXTENSION, 'popup.html'), 'utf8');
    const script = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');

    const present = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
    const wanted = [...script.matchAll(/getElementById\('([^']+)'\)/g)].map(m => m[1]);

    // A missing element is not an error anywhere - getElementById returns null,
    // and the failure surfaces later as a property access on null.
    const missing = wanted.filter(id => !present.has(id));
    assert.deepStrictEqual(missing, [], 'popup.js looks up elements that popup.html does not contain');
});

test('the popup keeps the list behind a drawer, and the counts can be pressed', () => {
    const html = fs.readFileSync(path.join(EXTENSION, 'popup.html'), 'utf8');
    const script = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');

    // The list and the two buttons sit inside a details element, so the popup
    // opens short and grows only when asked.
    assert.match(html, /<details[^>]*id="details-drawer"/, 'the drawer must exist');
    const drawer = html.slice(html.indexOf('id="details-drawer"'), html.indexOf('</details>'));
    assert.match(drawer, /id="recent-list"/, 'the recent list belongs inside the drawer');
    assert.match(drawer, /id="btn-more-info"/, 'the buttons belong inside the drawer too');
    assert.doesNotMatch(html, /<details[^>]*open/, 'the drawer must start closed');

    // The counts are buttons, not text that merely looks pressable.
    for (const verdict of ['high', 'suspicious', 'safe']) {
        assert.match(html, new RegExp(`<button[^>]*id="filter-${verdict}"`),
            `the ${verdict} count must be a button`);
    }

    // And pressing one has to actually filter, rather than only look pressed.
    assert.match(script, /filterVerdict/, 'the popup must track what it is filtered to');
    assert.match(script, /renderRecent\(\)/, 'pressing a count must re-render the list');
});

test('the refresh button reaches the watcher, not only the popup', () => {
    const html = fs.readFileSync(path.join(EXTENSION, 'popup.html'), 'utf8');
    const popup = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    assert.match(html, /id="btn-refresh"/, 'the button must exist');

    // The whole chain has to be there. A button that only re-reads the summary
    // would look like it worked and change nothing, because the summary only
    // moves after a sweep has actually examined something.
    assert.match(popup, /phishlens:sweep-now/, 'the popup must ask the worker to sweep');
    assert.match(worker, /phishlens:sweep-now/, 'the worker must handle the request');
    assert.match(content, /phishlens:sweep-now/, 'the watcher must sweep when asked');

    // Pressing it must also clear any backoff, or an earlier failure makes the
    // button do nothing for up to a minute.
    const listener = content.slice(content.indexOf("request?.type !== 'phishlens:sweep-now'"));
    assert.match(listener.slice(0, 400), /quietUntil = 0/, 'a request must not wait out a backoff');

    // And it must start a watcher in tabs that have none, which is the case the
    // button most often exists for.
    assert.match(worker, /watchAlreadyOpenTabs\('asked from the popup'\)/,
        'the request must also inject into mail tabs with no watcher');
});

test('the popup says which reason applies when nothing is watched', () => {
    const popup = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    // "The page watcher has not reported yet" is true and useless: it does not
    // distinguish no mail tab, a mail tab with no watcher, and a missing
    // permission - which need three different things done about them.
    assert.match(popup, /phishlens:diagnose/, 'the popup must ask why');
    assert.match(worker, /phishlens:diagnose/, 'the worker must answer');
    assert.match(content, /phishlens:ping/, 'a watcher must be able to say it is there');

    for (const reason of [
        /missing the permission/i,
        /No Gmail or Outlook Web tab is open/i,
        /open but not being watched/i
    ]) {
        assert.match(popup, reason, `the popup must name the case: ${reason}`);
    }
});

test('the manifest carries nothing the target browser rejects', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(EXTENSION, 'manifest.json'), 'utf8'));

    assert.strictEqual(manifest.manifest_version, 3);

    // background.scripts is a Manifest V2 key. Chrome lists it on the
    // extension's error page, where somebody reasonably reads a red "Errors"
    // badge on a security tool as the tool being broken.
    assert.ok(!manifest.background?.scripts,
        'background.scripts is MV2 and Chrome reports it as an error under MV3');
    assert.ok(manifest.background?.service_worker, 'MV3 needs a service worker');

    // Every file the manifest names must exist, or the extension fails to load.
    const referenced = [
        manifest.background.service_worker,
        manifest.action?.default_popup,
        manifest.options_ui?.page,
        ...(manifest.content_scripts || []).flatMap(cs => cs.js || [])
    ].filter(Boolean);

    const missing = referenced.filter(f => !fs.existsSync(path.join(EXTENSION, f)));
    assert.deepStrictEqual(missing, [], 'the manifest names files that are not there');
});

test('a rejected key recovers instead of dead-ending', () => {
    // The fault the user hit: the popup said "Not authorized — the configured
    // API key was rejected", and there was no way out of it.
    //
    // A key saved on the options page outranks the provisioned one, and should:
    // somebody who typed a value must not be overruled by a default. But that
    // precedence had no way back. When the desktop application's key changed,
    // the saved key kept winning, every request came back 401, and the only
    // remedy was knowing to go and clear a field nobody had been told about.
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');

    assert.match(worker, /function authedFetch/, 'requests must go through something that can retry');
    assert.match(worker, /provisionedApiKey/, 'the key that lost the precedence must still be carried');

    // One retry, never a loop: a backend refusing both keys is a different
    // fault, and hammering it turns a clear failure into a slow one.
    const fn = worker.slice(worker.indexOf('async function authedFetch'), worker.indexOf('async function diagnoseKey'));
    assert.match(fn, /401 && .*403|401.*\|\|.*403|status !== 401 && .*status !== 403/,
        'it must retry on refusal specifically, not on every error');
    assert.strictEqual((fn.match(/await attempt\(/g) || []).length, 2,
        'exactly two attempts: the chosen key, then the provisioned one');

    // And the requests that matter actually use it.
    assert.match(worker, /authedFetch\('\/api\/ingest\/browser'/, 'the sweep must recover');
    assert.match(worker, /authedFetch\('\/api\/summary'/, 'so must the badge');
});

test('the three reasons a key is refused are told apart', () => {
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');
    const popup = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');

    // These need three different things done about them and produced one
    // identical sentence. The health route needs no credential, which makes it
    // the only thing still reachable when everything else is a 401.
    assert.match(worker, /api_key_fingerprint/, 'the backend states which key it expects');
    assert.match(worker, /BACKEND_HAS_NO_KEY/, 'a backend with no key refuses even a correct one');
    assert.match(worker, /WRONG_KEY/, 'a different key is a different problem');
    assert.match(worker, /REJECTED_DESPITE_MATCH/, 'and a matching key still refused is a third');

    // A fingerprint, never the key: it identifies which key without carrying it.
    assert.match(worker, /crypto\.subtle\.digest\('SHA-256'/, 'compared by digest');
    assert.match(worker, /slice\(0, 12\)/, 'truncated, so it identifies without revealing');

    assert.match(popup, /phishlens:key-diagnosis/, 'the popup must ask why');
    assert.match(popup, /diagnosis\?\.diagnosis\?\.detail/, 'and show the reason rather than the generic line');
});

test('the fix is offered where the fault is reported', () => {
    const popup = fs.readFileSync(path.join(EXTENSION, 'popup.js'), 'utf8');
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');

    // Describing a remedy on a page somebody has to go and find is how the
    // original fault stayed unfixed.
    assert.match(popup, /offerProvisionedKey/);
    assert.match(popup, /phishlens:use-provisioned-key/);
    assert.match(worker, /phishlens:use-provisioned-key/, 'and the worker must carry it out');

    // It clears the saved key rather than overwriting it with another value,
    // so the precedence resolves naturally to the provisioned one.
    const handler = worker.slice(worker.indexOf("phishlens:use-provisioned-key"));
    assert.match(handler.slice(0, 400), /apiKey: ''/);
});

test('the backlog scan waits for the list instead of assuming it is there', () => {
    const worker = fs.readFileSync(path.join(EXTENSION, 'background.js'), 'utf8');
    const content = fs.readFileSync(path.join(EXTENSION, 'content-gmail.js'), 'utf8');

    // What this replaces: a fixed six-second wait, in a tab the browser
    // throttles, for a large application - and then reporting success
    // regardless. The scan read an empty document, concluded the mailbox was
    // empty and stopped, while the popup said "Scan started" and the backend
    // received nothing. Zero examined *and* zero failures, which is what
    // "nothing was even attempted" looks like.
    assert.match(content, /phishlens:reader-status/, 'the tab must be able to say whether it can see mail');
    assert.match(worker, /async function waitForReader/, 'and the worker must ask before starting');
    assert.match(worker, /BACKLOG_READY_TIMEOUT_MS/);

    // It must not claim to have started when the reader never saw anything.
    const start = worker.slice(worker.indexOf('async function startBacklogScan'));
    assert.match(start.slice(0, 2500), /if \(!ready\.ok\)/, 'a reader that never became ready must stop the scan');
    assert.match(start.slice(0, 2500), /tabs\.remove/, 'and the tab it opened must not be left behind');

    // A tab that never answers and one that answers seeing nothing are
    // different faults needing different things done about them.
    const waiter = worker.slice(worker.indexOf('async function waitForReader'), worker.indexOf('async function startBacklogScan'));
    assert.match(waiter, /never reported back/, 'no answer means the script is not running there');
    assert.match(waiter, /no message list appeared/, 'an answer with no rows is the other case');
    assert.match(waiter, /reader: last\.reader/, 'and it must carry the census, so the reader can be widened');
});
