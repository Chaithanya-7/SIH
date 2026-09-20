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

/**
 * Reference data the backend cannot work correctly without.
 *
 * The Public Suffix List is not a dependency npm knows about - it is a data
 * file in the backend tree - so nothing in the packaging would notice it going
 * missing. Without it, registrable-domain extraction falls back to the last two
 * labels, which is wrong for every multi-label suffix and for every free
 * hosting platform: a phishing page on a fresh github.io subdomain would report
 * GitHub's own registration date and look like an established domain. The
 * failure is silent, which is exactly why it is asserted here.
 */
test('the Public Suffix List ships with the backend', { skip }, () => {
    const list = path.join(PACKAGED, 'backend', 'reference', 'public_suffix_list.dat');
    assert.ok(fs.existsSync(list), 'without it every domain-age and lookalike decision degrades silently');

    const content = fs.readFileSync(list, 'utf8');
    assert.match(content, /===BEGIN ICANN DOMAINS===/, 'it must be the real list, not a truncated download');

    // The platforms that motivated adding it in the first place.
    ['github.io', 'pages.dev', 'workers.dev', 'blogspot.com'].forEach(suffix =>
        assert.ok(new RegExp(`^${suffix.replace('.', '\.')}$`, 'm').test(content),
            `${suffix} must be present or subdomains of it resolve to the platform itself`));
});

test('the QR decoder and its image libraries are all present', { skip }, () => {
    const modules = path.join(PACKAGED, 'backend', 'node_modules');
    ['jsqr', 'jpeg-js', 'pngjs'].forEach(dependency =>
        assert.ok(fs.existsSync(path.join(modules, dependency)),
            `${dependency} is needed to read a QR code out of an attachment at runtime`));
});

/**
 * The console must reference its assets relatively.
 *
 * Vite's default base is '/', which emits <script src="/assets/index-xxx.js">.
 * Over HTTP that is correct. Loaded as a file:// URL - which is exactly how the
 * packaged app opens the console - a leading slash resolves to the root of the
 * filesystem and every asset 404s. The HTML itself still loads, so the window
 * title is right and the body background applies, and the user gets a
 * correctly-titled black window with nothing in it.
 *
 * This shipped, and it survived every earlier check because those confirmed the
 * backend answered and that loadFile() resolved. Neither says anything about
 * whether the page rendered. Measured with a headless Electron window: 0
 * rendered characters before, 508 after.
 */
test('the packaged console references its assets relatively', { skip }, () => {
    const indexPath = path.join(PACKAGED, 'dashboard', 'index.html');
    const html = fs.readFileSync(indexPath, 'utf8');

    const absolute = [...html.matchAll(/(?:src|href)="(\/[^"]*)"/g)].map(m => m[1]);
    assert.deepStrictEqual(absolute, [],
        'an absolute asset path resolves to the filesystem root under file:// and renders a blank window');

    const referenced = [...html.matchAll(/(?:src|href)="(\.\/[^"]+)"/g)].map(m => m[1]);
    assert.ok(referenced.length >= 2, 'the console should reference at least a script and a stylesheet');

    // The referenced files must actually be there, not merely correctly spelt.
    referenced.forEach(rel => {
        const resolved = path.join(path.dirname(indexPath), rel.replace(/^\.\//, ''));
        assert.ok(fs.existsSync(resolved), `${rel} is referenced but missing from the package`);
    });
});

/**
 * `files` is an allow-list, and a module left off it fails only on launch.
 *
 * Adding a module beside main.js and requiring it produces a build that
 * succeeds, an installer that installs, and an application that dies at startup
 * with "Cannot find module" - the one failure a user can neither work around
 * nor diagnose. That shipped.
 *
 * Worse, the check meant to catch it grepped app.asar for the module's name and
 * found the *require statement*, and concluded the module was present.
 * Confirming a reference exists is not confirming its target does. These run
 * against the source, so they fail before a build rather than after an install.
 */
function localRequires(file) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    const found = new Set();
    for (const match of source.matchAll(/require\(['"]\.\/([^'"]+)['"]\)/g)) {
        found.add(match[1].endsWith('.js') ? match[1] : `${match[1]}.js`);
    }
    return [...found];
}

function desktopManifest() {
    let raw = fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8');
    if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
    return JSON.parse(raw);
}

test('every module the app requires at runtime is in the packaged file list', () => {
    const packaged = new Set(desktopManifest().build.files);

    const needed = new Set();
    ['main.js', 'preload.js'].forEach(entry => localRequires(entry).forEach(name => needed.add(name)));
    assert.ok(needed.size > 0, 'the entry points require something, so this check is meaningful');

    const missing = [...needed].filter(name => !packaged.has(name));
    assert.deepStrictEqual(missing, [],
        `required at runtime but absent from build.files, so the app dies on launch: ${missing.join(', ')}`);
});

test('every file listed for packaging exists on disk', () => {
    // The same failure from the other side: a name listed but misspelt copies
    // nothing, and again only shows once installed.
    const absent = desktopManifest().build.files
        .filter(name => !name.includes('*') && !name.startsWith('!'))
        .filter(name => !fs.existsSync(path.join(__dirname, '..', name)));

    assert.deepStrictEqual(absent, [], `listed for packaging but not present: ${absent.join(', ')}`);
});

test('the browser extension is shipped, and carries the file the app writes into', () => {
    const resources = desktopManifest().build.extraResources || [];
    assert.ok(resources.some(entry => entry.to === 'phishlens-extension'),
        'the console prints a folder to load; without this it names a path only a source checkout has');

    // provisioned.js is written by the application at startup and carries this
    // machine's API key. It must not travel inside an installer: an installer
    // carrying a key hands every person who runs it the same credential, and
    // that credential belongs to whoever built it.
    const ext = resources.find(entry => entry.to === 'phishlens-extension');
    assert.ok((ext.filter || []).includes('!provisioned.js'),
        'the packaged extension must exclude the file that holds a build key');
});

test('a build key cannot travel inside an installer', { skip }, () => {
    const shipped = path.join(PACKAGED, 'phishlens-extension', 'provisioned.js');
    assert.strictEqual(fs.existsSync(shipped), false,
        'this file holds a live credential and is written per install, not bundled');
});

test('the provisioned settings are untracked, so a key cannot be committed', () => {
    // Ignoring a file git already follows changes nothing, so this checks the
    // index rather than .gitignore.
    const tracked = execFileSync('git', ['ls-files', 'phishlens-extension/provisioned.js'], {
        cwd: path.join(__dirname, '..', '..'),
        encoding: 'utf8'
    }).trim();

    assert.strictEqual(tracked, '',
        'provisioned.js is tracked - the application writes a real key into it, one git add from being published');
});

test('the extension source can be pointed at a checkout, and a bad pointer is ignored', () => {
    // A packaged install ships its own extension and cannot know a source
    // checkout exists, so edits to the source only reached the browser after a
    // rebuild and reinstall. A pointer file beside the application data
    // redirects it - but only when it names something that is really an
    // extension, so a folder that has since moved falls back rather than
    // leaving the console printing a path that is not there.
    const source = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');

    assert.match(source, /extension-source\.txt/, 'there must be a pointer file');
    assert.match(source, /manifest\.json/,
        'a pointer is only honoured when it names a real extension');
    assert.match(source, /app\.isPackaged/,
        'and it still falls back to the bundled copy');

    // Not an environment variable: it has to survive a restart and belong to
    // this install rather than to the shell that launched it.
    assert.doesNotMatch(source, /process\.env\.PHISHLENS_EXTENSION/,
        'the source folder is not taken from the environment');
});
