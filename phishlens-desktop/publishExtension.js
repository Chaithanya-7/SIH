const fs = require('fs');
const path = require('path');

/**
 * Puts this install's address and key into the extension, ready to load.
 *
 * Loading an unpacked extension is already four steps in a corner of the
 * browser people do not normally visit, and the step they get stuck on is
 * pasting a 64-character key that is generated per install and kept in an
 * application data folder. That key is not a secret from the machine that
 * generated it, so making somebody carry it by hand bought nothing but a place
 * to give up.
 *
 * ## Where it writes, and why that depends
 *
 * Where the extension folder can be written to - a source checkout - the
 * settings go straight into it. One folder, the one already being edited, and
 * nothing is copied anywhere.
 *
 * A packaged install cannot do that: its resources directory is read-only on
 * Windows and macOS, which is the same constraint that moved the data store out
 * of the installation folder. There the extension is copied beside the
 * application's own data first, and the settings written into the copy.
 *
 * Either way the console is told which folder it ended up in, so the path it
 * prints is one that exists on the machine reading it.
 *
 * The written file carries a live credential, so it is git-ignored: a key in a
 * repository is a key belonging to everyone who clones it.
 */

const PROVISIONED_FILE = 'provisioned.js';

/** Can this directory be written to, without leaving anything behind? */
function isWritable(dir) {
    const probe = path.join(dir, '.phishlens-write-probe');
    try {
        fs.writeFileSync(probe, '');
        fs.unlinkSync(probe);
        return true;
    } catch (e) {
        return false;
    }
}

function publishExtension({ sourceDir, targetDir, apiBaseUrl, apiKey, log = () => {} }) {
    // Absolute, because the console prints this for somebody to paste into a
    // file dialog. A relative path is correct and useless there.
    const source = path.resolve(sourceDir);
    const fallback = path.resolve(targetDir);

    if (!fs.existsSync(path.join(source, 'manifest.json'))) {
        throw new Error(`No extension found at ${source}.`);
    }

    // In place where that is possible, which keeps a source checkout to one
    // folder rather than two that can drift apart.
    if (isWritable(source)) {
        writeProvisioned(source, apiBaseUrl, apiKey);
        log(`[Extension] Configured in place at ${source}`);
        return source;
    }

    // Replaced rather than merged. A stale file from an older version would
    // otherwise linger in a folder the browser loads wholesale, and a manifest
    // that no longer matches its scripts fails in ways that are hard to read.
    fs.rmSync(fallback, { recursive: true, force: true });
    fs.mkdirSync(fallback, { recursive: true });
    fs.cpSync(source, fallback, { recursive: true });

    // Tests belong to the source tree, not to something a browser will load.
    fs.rmSync(path.join(fallback, 'tests'), { recursive: true, force: true });

    writeProvisioned(fallback, apiBaseUrl, apiKey);
    log(`[Extension] Published a configured copy to ${fallback}`);
    return fallback;
}

function writeProvisioned(dir, apiBaseUrl, apiKey) {
    const contents = [
        '// Written by the PhishLens desktop application. Do not edit: this file',
        '// is replaced every time the application starts.',
        '//',
        '// It carries this machine\'s API key and is deliberately git-ignored.',
        '//',
        '// Anything saved on the extension\'s own options page takes precedence',
        '// over these values, so a deliberate change is never overwritten.',
        'globalThis.PHISHLENS_PROVISIONED = {',
        `    apiBaseUrl: ${JSON.stringify(apiBaseUrl)},`,
        `    apiKey: ${JSON.stringify(apiKey)},`,
        `    provisionedAt: ${JSON.stringify(new Date().toISOString())}`,
        '};',
        ''
    ].join('\n');

    fs.writeFileSync(path.join(dir, PROVISIONED_FILE), contents, { encoding: 'utf8', mode: 0o600 });
}

module.exports = publishExtension;
