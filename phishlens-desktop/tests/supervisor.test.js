const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const Module = require('module');

/**
 * Tests the supervisor's decision-making without launching Electron.
 *
 * `electron` is stubbed because these behaviours - attaching rather than
 * duplicating, giving up on a restart loop, only stopping what it owns - are
 * the ones that damage data or hide failures when they go wrong, and they
 * should be verifiable without a windowing system.
 */

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-supervisor-'));

const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
    if (request === 'electron') return 'electron-stub';
    return originalResolve.call(this, request, ...rest);
};
require.cache['electron-stub'] = {
    id: 'electron-stub',
    filename: 'electron-stub',
    loaded: true,
    exports: {
        app: {
            isPackaged: false,
            getPath: () => userDataDir,
            getVersion: () => '1.0.0'
        }
    }
};

const BackendSupervisor = require('../backendSupervisor');

/** A stand-in backend that answers the health probe the way the real one does. */
function startStubBackend(port) {
    return new Promise(resolve => {
        const server = http.createServer((req, res) => {
            if (req.url === '/api/health') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ status: 'OPERATIONAL' }));
            }
            res.writeHead(404);
            res.end();
        });
        server.listen(port, '127.0.0.1', () => resolve(server));
    });
}

function freePort() {
    return 3400 + Math.floor(Math.random() * 500);
}

test('a key is generated on first run and reused afterwards', () => {
    const port = freePort();
    const first = new BackendSupervisor({ port });
    assert.ok(first.apiKey && first.apiKey.length >= 32, 'a usable key must be generated');

    const second = new BackendSupervisor({ port });
    assert.strictEqual(second.apiKey, first.apiKey, 'the same installation must keep the same key across restarts');
    assert.ok(fs.existsSync(first.keyFile()), 'the key must be persisted');
});

/**
 * Two backends over one data directory would corrupt the case store and sever
 * the audit chain, so attaching is not an optimisation, it is a safety rule.
 */
test('it attaches to a backend that is already running instead of starting another', async () => {
    const port = freePort();
    const server = await startStubBackend(port);
    const supervisor = new BackendSupervisor({ port });

    try {
        const started = await supervisor.start();
        assert.strictEqual(started, true);
        assert.strictEqual(supervisor.status, 'READY');
        assert.strictEqual(supervisor.attachedToExisting, true, 'it must report that it attached');
        assert.strictEqual(supervisor.child, null, 'it must not have spawned a process');
    } finally {
        server.close();
    }
});

test('a backend it merely attached to is left running when the app stops', async () => {
    const port = freePort();
    const server = await startStubBackend(port);
    const supervisor = new BackendSupervisor({ port });

    try {
        await supervisor.start();
        supervisor.stop();

        const stillUp = await supervisor.checkHealth();
        assert.strictEqual(stillUp, true, 'a backend owned by someone else must not be killed');
    } finally {
        server.close();
    }
});

test('the health probe rejects something that answers but is not PhishLens', async () => {
    const port = freePort();
    const decoy = http.createServer((_req, res) => { res.writeHead(404); res.end('not phishlens'); });
    await new Promise(r => decoy.listen(port, '127.0.0.1', r));
    const supervisor = new BackendSupervisor({ port });

    try {
        assert.strictEqual(await supervisor.checkHealth(), false,
            'an occupied port is not the same as a working backend');
    } finally {
        decoy.close();
    }
});

test('the health probe reports false when nothing is listening', async () => {
    const supervisor = new BackendSupervisor({ port: freePort() });
    assert.strictEqual(await supervisor.checkHealth(300), false);
});

/**
 * Restarting forever would hide a real fault - a missing dependency, a busy
 * port - behind an app that looks like it is merely slow to start.
 */
test('it stops restarting after repeated immediate failures and says why', () => {
    const supervisor = new BackendSupervisor({ port: freePort() });
    const statuses = [];
    supervisor.on('status', s => statuses.push(s.status));

    supervisor.restarts = 3;
    supervisor.startedAt = Date.now();
    supervisor.handleUnexpectedExit('/nonexistent');

    assert.strictEqual(supervisor.status, 'FAILED');
    assert.match(supervisor.detail, /without staying up/);
    assert.ok(!statuses.includes('RESTARTING'), 'it must not schedule another restart past the limit');
});

test('a backend that ran normally before exiting gets a fresh restart budget', () => {
    const supervisor = new BackendSupervisor({ port: freePort() });
    supervisor.restarts = 2;
    // Exited after running well past the healthy-runtime threshold.
    supervisor.startedAt = Date.now() - 120000;
    supervisor.stopping = true; // prevents the scheduled respawn during the test

    supervisor.handleUnexpectedExit('/nonexistent');
    assert.strictEqual(supervisor.restarts, 1, 'the counter resets, then counts this exit as the first');
    assert.strictEqual(supervisor.status, 'RESTARTING');
});

test('reported state describes whether the backend is managed or borrowed', async () => {
    const port = freePort();
    const server = await startStubBackend(port);
    const supervisor = new BackendSupervisor({ port });

    try {
        await supervisor.start();
        const state = supervisor.state();

        assert.strictEqual(state.status, 'READY');
        assert.strictEqual(state.attached_to_existing, true);
        assert.strictEqual(state.managed_by_app, false);
        assert.strictEqual(state.backend_url, `http://127.0.0.1:${port}`);
        assert.ok(Array.isArray(state.logs));
    } finally {
        server.close();
    }
});

test('it reports a clear failure when the backend cannot be located', async () => {
    const supervisor = new BackendSupervisor({ port: freePort() });
    supervisor.backendPath = () => null;

    const started = await supervisor.start();
    assert.strictEqual(started, false);
    assert.strictEqual(supervisor.status, 'FAILED');
    assert.match(supervisor.detail, /could not be found/);
});

test.after(() => {
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
});

/**
 * Channel settings, read from the person's own data folder.
 *
 * The monitoring channels are switched on by environment variables, and for an
 * installed application the only way to set those was the Windows user
 * environment - which puts a password in the registry for every process that
 * user runs. These are read from a file beside the application's own data
 * instead.
 */
test('channels are off when there is no settings file', () => {
    const supervisor = new BackendSupervisor();
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-channels-'));

    assert.deepStrictEqual(supervisor.channelEnvironment(empty), {},
        'no file means no channels, not half-configured ones');
});

test('a malformed settings file leaves every channel off', () => {
    const supervisor = new BackendSupervisor();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-channels-'));
    fs.writeFileSync(path.join(dir, 'channels.json'), '{ not json');

    // A monitoring channel that cannot read its own settings must not come up
    // and report itself as watching.
    assert.deepStrictEqual(supervisor.channelEnvironment(dir), {});
});

test('SMTP is only switched on when it has a credential to enforce', () => {
    const supervisor = new BackendSupervisor();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-channels-'));

    // Enabled but with nothing to authenticate against would be an open relay.
    fs.writeFileSync(path.join(dir, 'channels.json'), JSON.stringify({ smtp: { enabled: true } }));
    assert.deepStrictEqual(supervisor.channelEnvironment(dir), {});

    fs.writeFileSync(path.join(dir, 'channels.json'), JSON.stringify({
        smtp: { enabled: true, username: 'u', password: 'p' }
    }));
    const env = supervisor.channelEnvironment(dir);
    assert.strictEqual(env.ENABLE_SMTP_INGESTION, 'true');
    assert.strictEqual(env.SMTP_BIND_HOST, '127.0.0.1', 'it must bind to loopback unless deliberately changed');
    assert.strictEqual(env.SMTP_LISTEN_PORT, '2525');
});

test('a channel marked disabled stays disabled even with credentials present', () => {
    const supervisor = new BackendSupervisor();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-channels-'));
    fs.writeFileSync(path.join(dir, 'channels.json'), JSON.stringify({
        imap: { enabled: false, user: 'someone@example.com', password: 'secret', host: 'imap.example.com' }
    }));

    assert.deepStrictEqual(supervisor.channelEnvironment(dir), {},
        'leaving credentials in the file must not switch the channel on');
});

test('channel settings cannot override the port, the key or the data directory', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'backendSupervisor.js'), 'utf8');

    const spread = source.indexOf('...this.channelEnvironment(');
    assert.ok(spread > 0, 'the channel settings must be spread into the backend environment');

    for (const setting of ['PORT: String(this.port)', 'PHISHLENS_API_KEY: this.apiKey', 'PHISHLENS_DATA_DIR:']) {
        assert.ok(source.indexOf(setting) > spread,
            `${setting} must come after the channel settings, so a file cannot move it`);
    }
});
