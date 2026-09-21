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
