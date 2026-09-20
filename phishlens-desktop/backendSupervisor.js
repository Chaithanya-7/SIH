const { spawn } = require('child_process');
const { app } = require('electron');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { EventEmitter } = require('events');

/**
 * Runs and watches the PhishLens backend so one installation is one thing to
 * launch.
 *
 * Behaviour worth being explicit about:
 *
 *   It attaches rather than duplicates. If a backend is already listening and
 *   healthy - because the operator ran start-all.bat, or a previous window is
 *   still open - the app uses it instead of starting a second one. Two backends
 *   sharing one data directory would corrupt the case store and the audit chain.
 *
 *   It owns a key, not a password. A desktop install has no operator to invent
 *   a secret, so one is generated on first run and kept in the per-user
 *   application data directory. It is passed to the backend it starts and to
 *   the console it loads, which is what makes the app work without setup.
 *
 *   It restarts a crash, but gives up on a loop. Repeated immediate failures
 *   mean something is actually wrong - a missing dependency, a busy port - and
 *   silently restarting forever would hide that. After a few attempts it stops
 *   and surfaces the captured output.
 *
 *   It never leaves the backend running. The child is killed on quit, including
 *   the abrupt paths, because an orphaned server holding the port would stop
 *   the app starting next time.
 */

const HEALTH_TIMEOUT_MS = 1500;
const STARTUP_TIMEOUT_MS = 45000;
const MAX_RESTARTS = 3;
/** A process that survives this long is considered to have started properly. */
const HEALTHY_RUNTIME_MS = 20000;
const LOG_LINES_KEPT = 300;

class BackendSupervisor extends EventEmitter {
    constructor({ port = 3001, host = '127.0.0.1' } = {}) {
        super();
        this.port = port;
        this.host = host;
        this.baseUrl = `http://${host}:${port}`;
        this.child = null;
        this.status = 'STOPPED';
        this.detail = 'Not started.';
        this.logs = [];
        this.restarts = 0;
        this.startedAt = null;
        this.attachedToExisting = false;
        this.stopping = false;
        this.apiKey = this.loadOrCreateApiKey();
    }

    // ---------- credentials ----------

    keyFile() {
        return path.join(app.getPath('userData'), 'desktop-api-key');
    }

    loadOrCreateApiKey() {
        const file = this.keyFile();
        try {
            if (fs.existsSync(file)) {
                const existing = fs.readFileSync(file, 'utf8').trim();
                if (existing.length >= 32) return existing;
            }
            const generated = crypto.randomBytes(32).toString('hex');
            fs.mkdirSync(path.dirname(file), { recursive: true });
            // Written owner-only where the platform honours it, since this key
            // authenticates every request the console makes.
            fs.writeFileSync(file, generated, { mode: 0o600 });
            return generated;
        } catch (e) {
            this.record(`Could not persist the local API key (${e.message}). Using a session-only key.`);
            return crypto.randomBytes(32).toString('hex');
        }
    }

    // ---------- process location ----------

    /** The backend directory: bundled beside the app when packaged, the repo when not. */
    backendPath() {
        const packaged = path.join(process.resourcesPath || '', 'backend');
        if (fs.existsSync(path.join(packaged, 'server.js'))) return packaged;

        const local = path.join(__dirname, '..', 'phishlens-backend');
        if (fs.existsSync(path.join(local, 'server.js'))) return local;

        return null;
    }

    /**
     * Which runtime to spawn.
     *
     * Electron's own Node, always, so the app works on a machine with no Node
     * installed - which is the point of shipping an installer.
     *
     * An earlier version of this preferred a system Node, on the grounds that
     * the backend's sqlite3 binding was compiled for a specific ABI and would
     * not load under Electron. That was wrong: sqlite3 6.x is a Node-API addon
     * (`napi_versions: [3, 6]`, and the binary exports napi_* symbols), and
     * Node-API is ABI-stable across runtimes. Verified by opening a database,
     * writing, reading it back and closing under both - system Node at ABI 137
     * and Electron's Node at ABI 149, with the same binary.
     *
     * The branch that used to distinguish packaged from unpackaged returned the
     * same value on both sides, so it decided nothing and is gone.
     *
     * PHISHLENS_BACKEND_NODE remains for running the backend under a Node of
     * your choosing; it is not needed to work around anything.
     */
    runtime() {
        if (process.env.PHISHLENS_BACKEND_NODE) {
            return { command: process.env.PHISHLENS_BACKEND_NODE, env: {}, label: 'configured Node' };
        }
        return { command: process.execPath, env: { ELECTRON_RUN_AS_NODE: '1' }, label: 'Electron Node' };
    }

    // ---------- health ----------

    checkHealth(timeoutMs = HEALTH_TIMEOUT_MS) {
        return new Promise(resolve => {
            const request = http.get(`${this.baseUrl}/api/health`, { timeout: timeoutMs }, response => {
                response.resume();
                resolve(response.statusCode === 200);
            });
            request.on('timeout', () => { request.destroy(); resolve(false); });
            request.on('error', () => resolve(false));
        });
    }

    async waitUntilHealthy(deadlineMs) {
        const deadline = Date.now() + deadlineMs;
        while (Date.now() < deadline) {
            if (this.stopping) return false;
            if (await this.checkHealth()) return true;
            await new Promise(r => setTimeout(r, 600));
        }
        return false;
    }

    // ---------- lifecycle ----------

    setStatus(status, detail) {
        this.status = status;
        this.detail = detail;
        this.emit('status', this.state());
    }

    record(line) {
        const text = String(line).trimEnd();
        if (!text) return;
        this.logs.push(`[${new Date().toISOString()}] ${text}`);
        if (this.logs.length > LOG_LINES_KEPT) this.logs.shift();
        this.emit('log', text);
    }

    async start() {
        this.stopping = false;

        // Attaching rather than duplicating: two backends over one data
        // directory would corrupt the case store and break the audit chain.
        this.setStatus('STARTING', 'Checking whether a PhishLens backend is already running…');
        if (await this.checkHealth()) {
            this.attachedToExisting = true;
            this.record(`A backend is already running on ${this.baseUrl}; attaching to it instead of starting another.`);
            this.setStatus('READY', `Attached to the PhishLens backend already running on ${this.baseUrl}.`);
            return true;
        }

        const backendDir = this.backendPath();
        if (!backendDir) {
            this.setStatus('FAILED', 'The PhishLens backend could not be found next to the application or in the repository.');
            return false;
        }

        return this.spawnBackend(backendDir);
    }

    async spawnBackend(backendDir) {
        const { command, env, label } = this.runtime();
        this.setStatus('STARTING', `Starting the PhishLens backend with ${label}…`);
        this.record(`Starting backend from ${backendDir}`);

        this.child = spawn(command, [path.join(backendDir, 'server.js')], {
            cwd: backendDir,
            env: {
                ...process.env,
                ...env,
                PORT: String(this.port),
                PHISHLENS_API_KEY: this.apiKey,
                // Cases, tokens and the audit ledger belong with the user, not
                // inside the installation. A packaged app's own directory is
                // read-only on Windows and macOS, so a backend writing there
                // would start and then fail at the first thing it tried to
                // remember - and on an upgrade or uninstall that history would
                // be sitting in a directory the installer replaces.
                PHISHLENS_DATA_DIR: process.env.PHISHLENS_DATA_DIR || path.join(app.getPath('userData'), 'data'),
                // The console is loaded from a file:// page or the dev server,
                // so browser-origin CORS is not what authenticates it; the key is.
                ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS || 'http://localhost:3005',
                NODE_ENV: process.env.NODE_ENV || 'production'
            },
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true
        });

        this.startedAt = Date.now();
        this.child.stdout.on('data', chunk => String(chunk).split(/\r?\n/).forEach(l => this.record(l)));
        this.child.stderr.on('data', chunk => String(chunk).split(/\r?\n/).forEach(l => this.record(l)));

        this.child.on('error', err => {
            this.record(`Backend process error: ${err.message}`);
            this.setStatus('FAILED', `The backend could not be started: ${err.message}`);
        });

        this.child.on('exit', (code, signal) => {
            this.child = null;
            if (this.stopping) return;
            this.record(`Backend exited with code ${code}${signal ? ` (signal ${signal})` : ''}.`);
            this.handleUnexpectedExit(backendDir);
        });

        const healthy = await this.waitUntilHealthy(STARTUP_TIMEOUT_MS);
        if (healthy) {
            this.restarts = 0;
            this.setStatus('READY', `PhishLens backend running on ${this.baseUrl}.`);
            return true;
        }

        if (!this.stopping) {
            this.setStatus('FAILED', `The backend did not become ready within ${STARTUP_TIMEOUT_MS / 1000}s. The log below shows what it reported.`);
        }
        return false;
    }

    handleUnexpectedExit(backendDir) {
        const ranLongEnough = this.startedAt && (Date.now() - this.startedAt) > HEALTHY_RUNTIME_MS;
        if (ranLongEnough) this.restarts = 0;

        if (this.restarts >= MAX_RESTARTS) {
            this.setStatus('FAILED',
                `The backend stopped ${this.restarts + 1} times without staying up. Something is preventing it from running, so it will not be restarted again automatically.`);
            return;
        }

        this.restarts += 1;
        const delay = Math.min(8000, 1000 * this.restarts);
        this.setStatus('RESTARTING', `The backend stopped unexpectedly. Restarting (attempt ${this.restarts} of ${MAX_RESTARTS})…`);
        setTimeout(() => { if (!this.stopping) this.spawnBackend(backendDir); }, delay);
    }

    /**
     * Stops a backend this process started. A backend it merely attached to is
     * left alone: it belongs to whoever started it.
     */
    stop() {
        this.stopping = true;
        if (!this.child) return;

        this.record('Stopping the backend.');
        const child = this.child;
        this.child = null;

        try {
            if (process.platform === 'win32') {
                // SIGTERM does not reliably terminate a Windows process tree.
                spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true });
            } else {
                child.kill('SIGTERM');
                setTimeout(() => { try { child.kill('SIGKILL'); } catch (e) { /* already gone */ } }, 4000);
            }
        } catch (e) {
            this.record(`Could not stop the backend cleanly: ${e.message}`);
        }
    }

    state() {
        return {
            status: this.status,
            detail: this.detail,
            backend_url: this.baseUrl,
            attached_to_existing: this.attachedToExisting,
            managed_by_app: !this.attachedToExisting && !!this.child,
            restarts: this.restarts,
            logs: this.logs.slice(-60)
        };
    }
}

module.exports = BackendSupervisor;
