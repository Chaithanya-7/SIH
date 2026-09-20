const fs = require('fs');
const path = require('path');

/**
 * Where PhishLens keeps everything it remembers.
 *
 * This was previously hard-coded to a `data` folder inside the installation,
 * which is wrong in two ways that both surfaced at once.
 *
 * On a packaged desktop install the application directory is read-only on
 * Windows and macOS, so a backend started from it could not write a case, a
 * token or an audit entry - the install would run and then fail at the first
 * thing it tried to remember.
 *
 * And in the test suite, every module resolved to the same fixed folder, so a
 * test that isolated its own state by moving those files aside did it to every
 * other test file running concurrently as well. That is not a hypothetical: it
 * is how it was found.
 *
 * PHISHLENS_DATA_DIR overrides it. Unset, the behaviour is exactly as before.
 */
function dataDir() {
    const configured = process.env.PHISHLENS_DATA_DIR;
    return configured && configured.trim()
        ? path.resolve(configured.trim())
        : path.join(__dirname, '..', 'data');
}

/**
 * The full path to one stored file, with its directory created.
 *
 * Resolved on each call rather than cached, because a module is constructed
 * once at require time and the directory may be set after that - which is
 * exactly what a test, or a desktop app deciding where its user data lives,
 * needs to be able to do.
 */
function dataFile(name) {
    const dir = dataDir();
    try {
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch (e) {
        console.error(`[DataPaths] Could not create the data directory at ${dir}: ${e.message}`);
    }
    return path.join(dir, name);
}

module.exports = { dataDir, dataFile };
