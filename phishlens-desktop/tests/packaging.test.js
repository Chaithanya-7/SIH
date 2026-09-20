const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

/**
 * Checks what the installer actually contains.
 *
 * The first packaged build looked completely successful - electron-builder
 * exited 0 and produced a 111 MB installer - and shipped a backend with no
 * `node_modules` at all. It would have installed cleanly and then failed on
 * `require('express')`, on the user's machine, with nothing in the build log to
 * suggest anything was wrong. electron-builder omits `node_modules` from an
 * `extraResources` set and no filter pattern overrides it.
 *
 * A green build is not evidence that the thing built works, so these assertions
 * run against the packaged output rather than the source tree.
 *
 * Skipped when there is no build to inspect, so `npm test` stays useful without
 * one.
 */

const PACKAGED = path.join(__dirname, '..', 'dist', 'win-unpacked', 'resources');
const built = fs.existsSync(PACKAGED);
const skip = built ? false : 'no packaged build in dist/win-unpacked - run `npm run build` first';

test('the packaged app contains the backend and the console', { skip }, () => {
    assert.ok(fs.existsSync(path.join(PACKAGED, 'backend', 'server.js')), 'the backend must be bundled');
    assert.ok(fs.existsSync(path.join(PACKAGED, 'dashboard', 'index.html')), 'the built console must be bundled');
});

/**
 * The defect this exists for. Every declared dependency must resolve from the
 * packaged backend's own location - not from the repository it was copied out
 * of, which is why the check runs with that directory as the resolution root.
 */
test('every backend dependency resolves from the packaged location', { skip }, () => {
    const backend = path.join(PACKAGED, 'backend');
    const manifest = JSON.parse(fs.readFileSync(path.join(backend, 'package.json'), 'utf8'));
    const deps = Object.keys(manifest.dependencies || {});
    assert.ok(deps.length > 0, 'the backend declares dependencies');

    const script = deps.map(d => `try{require.resolve(${JSON.stringify(d)})}catch(e){console.log(${JSON.stringify(d)})}`).join(';');
    const unresolved = execFileSync(process.execPath, ['-e', script], { cwd: backend, encoding: 'utf8' })
        .split('\n').map(s => s.trim()).filter(Boolean);

    assert.deepStrictEqual(unresolved, [],
        'these cannot be required from the installed app, so it would fail at startup on a user machine');
});

/** sqlite3 is the one compiled dependency, so its binary has to be there. */
test('the native sqlite3 binary is present in the package', { skip }, () => {
    const binary = path.join(PACKAGED, 'backend', 'node_modules', 'sqlite3', 'build', 'Release', 'node_sqlite3.node');
    assert.ok(fs.existsSync(binary), 'without this the campaign graph cannot open its database');
});

/**
 * The backend runs under Electron's Node in a packaged app. sqlite3 6.x is a
 * Node-API addon so this works without a rebuild - asserted rather than assumed,
 * because an earlier version of the README claimed the opposite.
 */
test('sqlite3 loads under the runtime the app will actually use', { skip }, () => {
    const electron = path.join(__dirname, '..', 'node_modules', 'electron', 'dist', 'electron.exe');
    if (!fs.existsSync(electron)) return; // no Electron binary to test against

    const backend = path.join(PACKAGED, 'backend');
    const out = execFileSync(electron, ['-e', 'try{require("sqlite3");console.log("loaded")}catch(e){console.log("failed: "+e.message)}'], {
        cwd: backend,
        encoding: 'utf8',
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }
    });
    assert.match(out, /loaded/, 'sqlite3 must load under Electron Node without being rebuilt');
});

/** Nothing from the development machine should travel inside an installer. */
test('no local state or secrets are bundled', { skip }, () => {
    const backend = path.join(PACKAGED, 'backend');
    const forbidden = ['.env', 'data', 'tests', 'scratch', 'test.json'];
    const leaked = forbidden.filter(f => fs.existsSync(path.join(backend, f)));

    assert.deepStrictEqual(leaked, [],
        'these belong to the development machine and must not ship to anyone else');
});

test('the app is not carrying the backend\'s own case history', { skip }, () => {
    const dataDir = path.join(PACKAGED, 'backend', 'data');
    assert.strictEqual(fs.existsSync(dataDir), false,
        'cases, tokens and the audit ledger are per-user state, written to the user profile at runtime');
});

/**
 * Development tooling must not travel inside an installer.
 *
 * The packaging copies the backend's dependency tree wholesale, so before the
 * staging step it shipped whatever happened to be installed for development -
 * a file watcher, a PDF parser used only by tests, a QR *generator* used only
 * to build test fixtures. None of it is reachable at runtime; all of it was
 * weight in the download and surface in the install.
 */
test('no development-only dependency is bundled', { skip }, () => {
    const backend = path.join(PACKAGED, 'backend');
    const manifest = JSON.parse(fs.readFileSync(path.join(backend, 'package.json'), 'utf8'));
    const devDeps = Object.keys(manifest.devDependencies || {});
    assert.ok(devDeps.length > 0, 'the backend declares dev dependencies, so this check is meaningful');

    const shipped = devDeps.filter(d => fs.existsSync(path.join(backend, 'node_modules', d)));
    assert.deepStrictEqual(shipped, [], 'these are development tools and have no reason to be in an installer');
});

/** The runtime dependencies still have to be there - pruning must not overreach. */
test('pruning dev dependencies did not remove a runtime one', { skip }, () => {
    const backend = path.join(PACKAGED, 'backend');
    const manifest = JSON.parse(fs.readFileSync(path.join(backend, 'package.json'), 'utf8'));
    const missing = Object.keys(manifest.dependencies || {})
        .filter(d => !fs.existsSync(path.join(backend, 'node_modules', d)));

    assert.deepStrictEqual(missing, [], 'a runtime dependency was pruned away with the dev tooling');
});

/** The QR decoder is a runtime dependency; the QR generator is not. */
test('the QR decoder ships and the QR generator does not', { skip }, () => {
    const modules = path.join(PACKAGED, 'backend', 'node_modules');
    ['jsqr', 'jpeg-js', 'pngjs'].forEach(d =>
        assert.ok(fs.existsSync(path.join(modules, d)), `${d} decodes QR codes at runtime and must ship`));
    assert.ok(!fs.existsSync(path.join(modules, 'qrcode')),
        'qrcode only generates fixtures for the test suite');
});
