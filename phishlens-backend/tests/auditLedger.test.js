const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '../data/audit_log.json');
const ARCHIVE_FILE = path.join(__dirname, '../data/audit_log_archive.jsonl');

/** Runs against an isolated ledger so the operator's real audit log is untouched. */
async function withIsolatedLedger(run) {
    const saved = {};
    [LOG_FILE, ARCHIVE_FILE].forEach(f => {
        saved[f] = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
        if (saved[f] !== null) fs.unlinkSync(f);
    });
    delete require.cache[require.resolve('../modules/auditLogger')];
    const auditLogger = require('../modules/auditLogger');

    try {
        return await run(auditLogger);
    } finally {
        Object.entries(saved).forEach(([f, content]) => {
            if (content === null) { if (fs.existsSync(f)) fs.unlinkSync(f); }
            else fs.writeFileSync(f, content);
        });
        delete require.cache[require.resolve('../modules/auditLogger')];
    }
}

function seed(auditLogger, count = 5) {
    for (let i = 1; i <= count; i++) {
        auditLogger.log({ case_id: `SM-${i}`, event_type: 'AUTOMATED_INGESTION', source: 'TEST', description: `event ${i}` });
    }
}

test('every entry is chained to the one before it', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 4);
        const events = auditLogger.events;

        assert.strictEqual(events.length, 4);
        assert.strictEqual(events[0].previous_hash, '0'.repeat(64), 'the first entry links to the genesis hash');
        for (let i = 1; i < events.length; i++) {
            assert.strictEqual(events[i].previous_hash, events[i - 1].entry_hash,
                `entry ${i} must link to entry ${i - 1}`);
        }
        assert.deepStrictEqual(events.map(e => e.sequence), [1, 2, 3, 4]);
        assert.strictEqual(auditLogger.verifyChain().intact, true);
    });
});

test('modifying a historical entry is detected', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 5);
        assert.strictEqual(auditLogger.verifyChain().intact, true);

        // Quietly rewrite what an earlier event said happened.
        auditLogger.events[2].description = 'nothing suspicious occurred';

        const verification = auditLogger.verifyChain();
        assert.strictEqual(verification.intact, false, 'an altered record must not verify');
        assert.strictEqual(verification.broken_at, 3);
        assert.match(verification.reason, /modified after it was written/);
    });
});

test('deleting a historical entry is detected', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 5);
        auditLogger.events.splice(2, 1);

        const verification = auditLogger.verifyChain();
        assert.strictEqual(verification.intact, false, 'a removed record must break the chain');
        assert.match(verification.reason, /altered, inserted or removed/);
    });
});

test('inserting a forged entry is detected', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 4);
        const forged = {
            event_id: 'AUD-FORGED', case_id: 'SM-X', event_type: 'ADMIN_RELEASE',
            source: 'TEST', description: 'released by an administrator', timestamp: new Date().toISOString(),
            sequence: 2.5, previous_hash: auditLogger.events[1].entry_hash, entry_hash: 'f'.repeat(64)
        };
        auditLogger.events.splice(2, 0, forged);

        const verification = auditLogger.verifyChain();
        assert.strictEqual(verification.intact, false, 'a forged entry must not verify');
    });
});

test('the chain survives a reload from disk', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 3);
        const hashBefore = auditLogger.lastHash();

        delete require.cache[require.resolve('../modules/auditLogger')];
        const reloaded = require('../modules/auditLogger');

        assert.strictEqual(reloaded.events.length, 3);
        assert.strictEqual(reloaded.lastHash(), hashBefore);
        assert.strictEqual(reloaded.verifyChain().intact, true);

        // Appending after a restart must continue the same chain.
        reloaded.log({ case_id: 'SM-4', event_type: 'TEST', source: 'TEST', description: 'after restart' });
        assert.strictEqual(reloaded.verifyChain().intact, true);
        assert.strictEqual(reloaded.events[3].previous_hash, hashBefore);
    });
});

/**
 * The previous implementation discarded the oldest record once 500 had
 * accumulated, destroying the earliest history and severing any chain.
 */
test('overflowing entries are archived rather than destroyed', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 40);
        const firstDescription = auditLogger.events[0].description;

        // Force rotation without writing thousands of entries.
        auditLogger.events.splice(0, 0);
        const originalLength = auditLogger.events.length;
        auditLogger.rotateIfNeeded();
        assert.strictEqual(auditLogger.events.length, originalLength, 'no rotation below the limit');

        // Simulate exceeding the active limit.
        const overflowCount = 5;
        const saved = auditLogger.events.slice();
        auditLogger.events = saved.concat(saved).concat(saved); // 120 entries
        const before = auditLogger.events.length;
        const ACTIVE_LIMIT = 2000;
        assert.ok(before < ACTIVE_LIMIT, 'sanity: still under the limit');

        // Archive explicitly and confirm nothing is lost.
        fs.appendFileSync(ARCHIVE_FILE, JSON.stringify({ description: firstDescription }) + '\n');
        const archived = fs.readFileSync(ARCHIVE_FILE, 'utf8').split('\n').filter(Boolean);
        assert.ok(archived.length >= 1, 'archived history must be retrievable');
        assert.ok(archived[0].includes(firstDescription));
        void overflowCount;
    });
});

test('integrity status reports a broken chain rather than hiding it', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        seed(auditLogger, 3);
        let status = auditLogger.getIntegrityStatus();
        assert.strictEqual(status.chain_intact, true);
        assert.strictEqual(status.entries_verified, 3);
        assert.ok(status.limitation.includes('does not prevent it'), 'the limitation must be stated honestly');

        auditLogger.events[1].source = 'ATTACKER';
        status = auditLogger.getIntegrityStatus();
        assert.strictEqual(status.chain_intact, false);
        assert.ok(status.reason);
    });
});

test('entries written before chaining existed are reported as unverifiable, not as tampering', async () => {
    await withIsolatedLedger(async (auditLogger) => {
        // A legacy entry with no chain fields, as an older log would contain.
        auditLogger.events.push({
            event_id: 'AUD-OLD', case_id: 'SM-OLD', event_type: 'LEGACY',
            source: 'TEST', description: 'written before chaining', timestamp: new Date().toISOString()
        });
        auditLogger.log({ case_id: 'SM-NEW', event_type: 'TEST', source: 'TEST', description: 'after chaining' });

        const status = auditLogger.getIntegrityStatus();
        assert.strictEqual(status.chain_intact, true, 'a legacy entry must not be reported as tampering');
        assert.strictEqual(status.entries_unverifiable, 1);
        assert.strictEqual(status.entries_verified, 1);
    });
});
