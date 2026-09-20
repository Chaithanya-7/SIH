const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

/**
 * Regressions for a class of defect that never fails a request.
 *
 * Nothing here crashes, logs, or returns a wrong answer. A leaked timer, an
 * unbounded body, a loop with no deadline and a retry with no backoff all
 * behave perfectly until the system is under load or something upstream is
 * slow - and then they degrade in ways that look like anything but their own
 * cause. Each was found by reading for it rather than by seeing it fail.
 */

const backend = (name) => fs.readFileSync(path.join(__dirname, '..', 'modules', name), 'utf8');
const serverSource = () => fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const extension = (name) => fs.readFileSync(path.join(__dirname, '..', '..', 'phishlens-extension', name), 'utf8');

function stripComments(text) {
    return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

test('a timeout raced against work is cancelled when the work wins', () => {
    const source = stripComments(backend('dnsblReputation.js'));

    assert.match(source, /Promise\.race/, 'the lookup still races a deadline');
    // Promise.race settles on the first outcome and cancels nothing. A six
    // second timer survived every fast lookup - three per message, every
    // message - each holding the event loop awake to reject a promise nobody
    // was waiting on any more.
    assert.match(source, /clearTimeout/,
        'the losing timer must be cleared, or every fast lookup leaks one');
    assert.match(source, /finally\s*\{[^}]*clearTimeout/,
        'clearing it must happen on both paths, which is what finally is for');
});

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

test('every ingestion route states its own size limit', () => {
    const source = serverSource();

    // The global JSON parser allows 50MB. A route that accepts a message and
    // says nothing inherits that, so one submission could put fifty megabytes
    // through MIME parsing, QR decoding and language analysis.
    const routes = [
        { path: '/api/ingest/browser', pattern: /app\.post\('\/api\/ingest\/browser',\s*express\.json\(\s*\{\s*limit:/ },
        { path: '/api/ingest/file', pattern: /app\.post\('\/api\/ingest\/file',\s*express\.text\(\s*\{[^}]*limit:/ }
    ];

    routes.forEach(route => {
        assert.match(source, route.pattern,
            `${route.path} must bound its own body rather than inheriting the global limit`);
    });
});

// ---------------------------------------------------------------------------
// The browser watcher
// ---------------------------------------------------------------------------

test('a sweep cannot start while the previous one is still running', () => {
    const source = stripComments(extension('content-gmail.js'));

    // A sweep examines up to twenty-five messages, each a network round trip,
    // so it routinely outlasts the four second interval that starts the next.
    assert.match(source, /sweeping\s*=\s*false/, 'there must be a flag for a sweep in progress');
    // Written to tolerate other conditions in the same guard. An earlier
    // version used [^)]*, which cannot cross the ")" inside Date.now() and so
    // failed against perfectly correct code.
    assert.match(source, /if\s*\([\s\S]{0,120}?sweeping[\s\S]{0,120}?\)\s*return/,
        'a sweep already running must stop the next one from starting');
    assert.match(source, /finally\s*\{\s*sweeping\s*=\s*false/,
        'the flag must clear even when the sweep throws, or sweeping stops forever');
});

test('the fetch for an original message cannot hang indefinitely', () => {
    const source = stripComments(extension('content-gmail.js'));

    // This fetch is awaited inside a sequential loop. Without a deadline, one
    // unanswered request stops that sweep permanently and every message behind
    // it goes unexamined - silently, with the extension still appearing to run.
    assert.match(source, /AbortController/, 'the request must be abortable');
    assert.match(source, /signal:\s*controller\.signal/, 'the signal must actually be passed to fetch');
    assert.match(source, /setTimeout\(\(\)\s*=>\s*controller\.abort\(\)/, 'something must trigger the abort');
    assert.match(source, /finally\s*\{\s*clearTimeout/, 'and the deadline must be cleared when it is not needed');
});

test('a message larger than any provider will send is refused before it is read', () => {
    const source = stripComments(extension('content-gmail.js'));

    assert.match(source, /MAX_MESSAGE_BYTES/, 'there must be a ceiling on message size');
    assert.match(source, /content-length/i,
        'the declared length should be checked before the body is read into memory');
});

test('the watcher backs off instead of hammering a backend that is not there', () => {
    const source = stripComments(extension('content-gmail.js'));

    // A failed submission un-remembers its message so it is retried, which is
    // right for one hiccup and wrong for a backend that is switched off:
    // twenty-five messages every four seconds is six requests a second against
    // nothing, plus a re-fetch of each original from the mail provider.
    assert.match(source, /consecutiveFailures/, 'repeated failures must be counted');
    assert.match(source, /quietUntil/, 'and must push the next attempt further out');
    assert.match(source, /Math\.min\([\s\S]{0,120}?MAX_BACKOFF_MS/,
        'the widening gap needs a ceiling so it cannot grow without bound');
    assert.match(source, /consecutiveFailures\s*=\s*0/,
        'a success must reset it, or the watcher never recovers its pace');
});

test('the watcher never sends anything to an address it was not configured with', () => {
    const source = stripComments(extension('content-gmail.js'));

    // The content script runs inside a mail page. It holds no API key and
    // addresses no backend directly: it hands the payload to the service
    // worker, which owns both. Anything else would put the key into a script
    // injected into a page somebody else's code also runs in.
    assert.doesNotMatch(source, /fetch\(\s*[`'"]https?:\/\/localhost/,
        'the content script must not call the backend directly');
    assert.doesNotMatch(source, /apiKey|api_key/i,
        'the content script must never hold the API key');
    assert.match(source, /runtime\.sendMessage/, 'it submits through the service worker');
});
