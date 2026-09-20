const fs = require('fs');
const path = require('path');

/**
 * Publishes a ready-to-load copy of the browser extension.
 *
 * Loading an unpacked extension is four steps in a corner of the browser people
 * do not normally visit, and the step they get stuck on is pasting a
 * 64-character key that is generated per install and kept in an application
 * data folder. That key is not a secret from the machine that generated it, so
 * making somebody carry it by hand bought nothing but a place to give up.
 *
 * This copies the bundled extension into the application's own writable data
 * directory and writes the address and key into it on the way, so loading that
 * copy needs no configuration at all.
 *
 * It cannot be done in place: in a packaged install the resources directory is
 * read-only on Windows and macOS, which is the same constraint that moved the
 * data store out of the installation folder.
 */

const PROVISIONED_FILE = 'provisioned.js';

function publishExtension({ sourceDir, targetDir, apiBaseUrl, apiKey, log = () => {} }) {
    if (!fs.existsSync(path.join(sourceDir, 'manifest.json'))) {
        throw new Error(`No extension found at ${sourceDir}.`);
    }

    // Replaced rather than merged. A stale file from an older version would
    // otherwise linger in a folder the browser loads wholesale, and a manifest
    // that no longer matches its scripts fails in ways that are hard to read.
    fs.rmSync(targetDir, { recursive: true, force: true });
    fs.mkdirSync(targetDir, { recursive: true });
    fs.cpSync(sourceDir, targetDir, { recursive: true });

    // Tests belong to the source tree, not to something a browser will load.
    fs.rmSync(path.join(targetDir, 'tests'), { recursive: true, force: true });

    const provisioned = [
        '// Written by the PhishLens desktop application. Do not edit: this file',
        '// is replaced every time the application starts.',
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

    fs.writeFileSync(path.join(targetDir, PROVISIONED_FILE), provisioned, { encoding: 'utf8', mode: 0o600 });

    log(`[Extension] Published a configured copy to ${targetDir}`);
    return targetDir;
}

module.exports = publishExtension;
