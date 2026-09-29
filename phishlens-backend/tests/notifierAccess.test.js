const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

/**
 * Can the desktop notifier actually read verdicts?
 *
 * This exists because of a fault found by installing the build and poking it,
 * which no test in this repository would have caught. The desktop notifier polls
 * `/api/cases` with the machine API key. Against the running install that came
 * back **401**, which would have meant the notification feature shipped
 * incapable of raising a single notification - failing silently, once, into a log
 * nobody reads.
 *
 * Reasoning about it was not enough. The supervisor hands the same `apiKey`
 * field to the backend's environment and to the notifier, so on paper they
 * cannot differ; the live 401 said otherwise. This starts a real backend with a
 * known key and asks it, which is the only thing that settles it.
 *
 * ## The second trap, which reasoning did find
 *
 * `requireAuth` accepts the service key by giving the request a synthetic user:
 * `{ role: 'ADMIN', organization_id: 'org_dev' }`. `/api/cases` then filters by
 * that organisation. A case belonging to a real organisation would be filtered
 * *out* - so the notifier could authenticate perfectly and still be handed an
 * empty list forever. Authentication succeeding and data arriving are two
 * different things, and both are checked here.
 */

const SERVER = path.join(__dirname, '..', 'server.js');
const KEY = 'test-key-' + 'a'.repeat(40);
const PORT = 3457;

/** Asks the backend a question exactly the way the notifier does. */
function ask(routePath, key) {
    return new Promise((resolve, reject) => {
        const req = http.get({
            hostname: '127.0.0.1',
            port: PORT,
            path: routePath,
            headers: { 'x-api-key': key },
            timeout: 8000
        }, res => {
            let body = '';
            res.on('data', c => { body += c; });
            res.on('end', () => {
                let parsed = null;
                try { parsed = JSON.parse(body); } catch (e) { /* not JSON */ }
                resolve({ status: res.statusCode, body: parsed });
            });
        });
        req.on('timeout', () => req.destroy(new Error('timed out')));
        req.on('error', reject);
    });
}

async function waitForHealth(deadlineMs = 45000) {
    const until = Date.now() + deadlineMs;
    while (Date.now() < until) {
        try {
            const answer = await ask('/api/health', KEY);
            if (answer.status === 200) return true;
        } catch (e) {
            // Not listening yet.
        }
        await new Promise(r => setTimeout(r, 500));
    }
    return false;
}

test('the notifier can authenticate with the machine key and receive cases', async (t) => {
    // Its own data directory. A test that read the real one would see the
    // person's mail, and a test that wrote to it would put fixtures in their
    // case list - which has happened on this project before.
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-notifier-'));

    const child = spawn(process.execPath, [SERVER], {
        env: {
            ...process.env,
            PORT: String(PORT),
            PHISHLENS_API_KEY: KEY,
            PHISHLENS_DATA_DIR: dataDir,
            NODE_ENV: 'test',
            // Nothing in this test should reach the network or start a capture.
            ENABLE_NETWORK_OBSERVER: 'false'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let output = '';
    child.stdout.on('data', c => { output += c; });
    child.stderr.on('data', c => { output += c; });

    t.after(() => {
        child.kill();
        try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
    });

    const up = await waitForHealth();
    assert.ok(up, `the backend did not start:\n${output.slice(-2000)}`);

    // The call the notifier actually makes, with the key the supervisor holds.
    const cases = await ask('/api/cases', KEY);

    assert.strictEqual(cases.status, 200,
        'the machine API key must authenticate /api/cases, or the notifier polls a 401 forever and never raises anything');
    assert.ok(Array.isArray(cases.body?.cases), 'and it must come back with a case list, even an empty one');

    // A wrong key must still be refused - this is an authentication check, not
    // an open endpoint.
    const refused = await ask('/api/cases', 'not-the-key');
    assert.strictEqual(refused.status, 401, 'an incorrect key must be rejected');
});

test('the service key is not filtered out of its own results by organisation', async (t) => {
    // The trap: requireAuth gives a service-key request the synthetic identity
    // { role: 'ADMIN', organization_id: 'org_dev' }, and /api/cases filters by
    // organisation. A case belonging to a real organisation is then filtered out,
    // so the notifier authenticates and is handed nothing, forever.
    const source = fs.readFileSync(SERVER, 'utf8');
    const block = source.slice(source.indexOf("app.get('/api/cases'"), source.indexOf("app.get('/api/summary'"));

    const filtersByOrg = /organization_id/.test(block);
    if (!filtersByOrg) return; // Nothing to guard.

    // If it does filter, the filter has to let a case with no organisation
    // through - which is what a single-user desktop install produces.
    assert.match(block, /!c\.organization_id \|\|/,
        'a case with no organisation must pass the filter, or a desktop install sees an empty list');
});

test('two sweeps reaching the same message is not a server error', async (t) => {
    /**
     * The fault that stopped a live scan dead.
     *
     * The live watcher sweeps every four seconds while a backlog scan walks the
     * same page, so both submit the same rows. The second submission collided
     * with the first inside the deduplication store and the pipeline threw,
     * which the endpoint reported as a 500. Five of those in a row stopped the
     * scan - on a mailbox where nothing was wrong with any single message.
     *
     * Reproduced directly before it was fixed: first 200, second 500.
     */
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-race-'));
    const port = PORT + 7;

    const child = spawn(process.execPath, [SERVER], {
        env: { ...process.env, PORT: String(port), PHISHLENS_API_KEY: KEY, PHISHLENS_DATA_DIR: dataDir, NODE_ENV: 'test', ENABLE_NETWORK_OBSERVER: 'false' },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    child.stdout.on('data', c => { output += c; });
    child.stderr.on('data', c => { output += c; });
    t.after(() => { child.kill(); try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (e) {} });

    const send = body => new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const req = http.request({
            hostname: '127.0.0.1', port, path: '/api/ingest/browser', method: 'POST',
            headers: { 'x-api-key': KEY, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
            timeout: 60000
        }, res => {
            let text = '';
            res.on('data', d => { text += d; });
            res.on('end', () => { let parsed = null; try { parsed = JSON.parse(text); } catch (e) {} resolve({ status: res.statusCode, body: parsed }); });
        });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timed out')));
        req.write(payload); req.end();
    });

    const until = Date.now() + 45000;
    let up = false;
    while (Date.now() < until && !up) {
        try {
            await new Promise((res, rej) => {
                const r = http.get({ hostname: '127.0.0.1', port, path: '/api/health' }, x => { x.resume(); x.statusCode === 200 ? res() : rej(new Error('not ready')); });
                r.on('error', rej); r.setTimeout(2000, () => r.destroy(new Error('t')));
            });
            up = true;
        } catch (e) { await new Promise(r => setTimeout(r, 500)); }
    }
    assert.ok(up, `the backend did not start:\n${output.slice(-1500)}`);

    const CRLF = String.fromCharCode(13, 10);
    const raw = [
        'From: "Sender" <a@example.com>', 'To: me@gmail.com', 'Subject: Submitted twice at once',
        'Message-ID: <race-test-1@example.com>', 'Date: Sat, 27 Sep 2026 10:00:00 +0000',
        'Content-Type: text/plain; charset=utf-8'
    ].join(CRLF) + CRLF + CRLF + 'identical body';

    const payload = { source: 'mail.google.com', provider_message_id: 'race-test-1', raw, evidence: 'FULL_HEADERS' };
    const [first, second] = await Promise.all([send(payload), send(payload)]);

    const statuses = [first.status, second.status].sort();
    assert.deepStrictEqual(statuses, [200, 409],
        `one submission should succeed and the other be told it is already in hand, got ${statuses.join(' and ')}`);

    const collided = [first, second].find(r => r.status === 409);
    assert.strictEqual(collided.body.already_in_progress, true,
        'the caller must be able to tell this apart from a real failure');
    assert.match(collided.body.error, /Nothing is wrong/i);

    // And it must never be a 500, which is what made a healthy scan look broken.
    assert.ok(!statuses.includes(500), 'a concurrent duplicate must never be reported as a server error');
});
