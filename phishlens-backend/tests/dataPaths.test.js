const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Where PhishLens writes is not a detail. A packaged desktop install runs from
 * a read-only directory, so a backend that insists on storing cases beside its
 * own source starts and then fails the first time it tries to remember
 * anything.
 */

function fresh() {
    delete require.cache[require.resolve('../modules/dataPaths')];
    return require('../modules/dataPaths');
}

test('with nothing configured it keeps the historical location', () => {
    const previous = process.env.PHISHLENS_DATA_DIR;
    delete process.env.PHISHLENS_DATA_DIR;
    try {
        const { dataDir } = fresh();
        assert.strictEqual(path.basename(dataDir()), 'data');
        assert.ok(dataDir().includes('phishlens-backend'), 'the default must stay where existing installs already keep their data');
    } finally {
        if (previous !== undefined) process.env.PHISHLENS_DATA_DIR = previous;
    }
});

test('a configured directory is used instead, and created if absent', () => {
    const previous = process.env.PHISHLENS_DATA_DIR;
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-paths-'));
    const target = path.join(base, 'nested', 'store');
    process.env.PHISHLENS_DATA_DIR = target;
    try {
        const { dataFile } = fresh();
        const file = dataFile('cases.json');

        assert.strictEqual(path.dirname(file), target);
        assert.ok(fs.existsSync(target), 'the directory must be created rather than failing on first write');
    } finally {
        if (previous === undefined) delete process.env.PHISHLENS_DATA_DIR;
        else process.env.PHISHLENS_DATA_DIR = previous;
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * Resolved per call, not cached at require time: a module is constructed once
 * when it is first required, which is often before anything has decided where
 * data should live.
 */
test('a directory set after the module loaded is still honoured', () => {
    const previous = process.env.PHISHLENS_DATA_DIR;
    const first = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-paths-a-'));
    const second = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-paths-b-'));
    process.env.PHISHLENS_DATA_DIR = first;
    try {
        const { dataFile } = fresh();
        assert.strictEqual(path.dirname(dataFile('x.json')), first);

        process.env.PHISHLENS_DATA_DIR = second;
        assert.strictEqual(path.dirname(dataFile('x.json')), second);
    } finally {
        if (previous === undefined) delete process.env.PHISHLENS_DATA_DIR;
        else process.env.PHISHLENS_DATA_DIR = previous;
        [first, second].forEach(d => fs.rmSync(d, { recursive: true, force: true }));
    }
});

/** Every module that persists anything has to go through it, or the override is a half-truth. */
test('no module still hard-codes a path beside its own source', () => {
    const root = path.join(__dirname, '..');
    const offenders = [];
    ['modules', 'adapters'].forEach(dir => {
        fs.readdirSync(path.join(root, dir))
            .filter(f => f.endsWith('.js'))
            .forEach(f => {
                const content = fs.readFileSync(path.join(root, dir, f), 'utf8');
                if (/__dirname,\s*['"]\.\.\/data/.test(content)) offenders.push(`${dir}/${f}`);
            });
    });
    assert.deepStrictEqual(offenders, [], 'these still write beside their own source, so PHISHLENS_DATA_DIR would not move them');
});
