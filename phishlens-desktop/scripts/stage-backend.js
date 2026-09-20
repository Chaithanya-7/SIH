#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

/**
 * Builds a production-only copy of the backend's dependencies for packaging.
 *
 * The installer copies the backend's `node_modules` wholesale, which means
 * whatever is installed for development travels to every user: nodemon, a PDF
 * parser used only by tests, a QR *generator* used only to make test fixtures.
 * None of it is reachable at runtime. It is weight in the download and surface
 * in the install, for no benefit.
 *
 * Resolving that by listing exclusions would be fragile - it means tracking
 * every transitive dependency of every dev tool by hand, and getting it wrong
 * either ships the tool anyway or deletes something the backend needs. Letting
 * npm resolve the production tree from the lockfile is the only version that
 * stays correct as dependencies change.
 *
 * The staging directory is built beside the desktop app rather than inside the
 * backend, so a packaging run never disturbs the working tree the developer is
 * using.
 */

const backend = path.join(__dirname, '..', '..', 'phishlens-backend');
const staging = path.join(__dirname, '..', 'build-staging', 'backend-deps');

function log(message) {
    console.log(`[stage-backend] ${message}`);
}

if (!fs.existsSync(path.join(backend, 'package.json'))) {
    console.error('[stage-backend] Cannot find the backend beside this application.');
    process.exit(1);
}

fs.rmSync(staging, { recursive: true, force: true });
fs.mkdirSync(staging, { recursive: true });

for (const file of ['package.json', 'package-lock.json']) {
    const source = path.join(backend, file);
    if (fs.existsSync(source)) fs.copyFileSync(source, path.join(staging, file));
}

const useLockfile = fs.existsSync(path.join(staging, 'package-lock.json'));
log(`Installing production dependencies only (${useLockfile ? 'npm ci' : 'npm install'})...`);

try {
    // shell: true on Windows because npm is a .cmd, and since the fix for
    // CVE-2024-27980 Node refuses to spawn a batch file without one - the
    // failure is an opaque EINVAL that says nothing about the cause. Every
    // argument here is a literal, so the shell has nothing to interpolate.
    execFileSync(
        process.platform === 'win32' ? 'npm.cmd' : 'npm',
        [useLockfile ? 'ci' : 'install', '--omit=dev', '--no-audit', '--no-fund'],
        { cwd: staging, stdio: 'inherit', shell: process.platform === 'win32' }
    );
} catch (e) {
    // The message matters: the first version of this script passed an invalid
    // flag, npm rejected it, and the failure was reported as a bare "install
    // failed" with nothing to act on.
    console.error(`[stage-backend] Production dependency install failed: ${e.message}`);
    process.exit(1);
}

const installed = fs.readdirSync(path.join(staging, 'node_modules')).filter(n => !n.startsWith('.'));
log(`Staged ${installed.length} production package(s) at ${staging}`);

// The compiled sqlite3 binding has to survive the staged install, or the
// packaged backend gets a dependency tree with a hole in the one place it
// cannot recover from.
const binding = path.join(staging, 'node_modules', 'sqlite3', 'build', 'Release', 'node_sqlite3.node');
if (!fs.existsSync(binding)) {
    console.error('[stage-backend] The sqlite3 native binding is missing from the staged tree; the packaged backend would fail when the campaign graph opens its database.');
    process.exit(1);
}
log('sqlite3 native binding present.');
