const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const os = require('os');

/**
 * Runs against its own data directory.
 *
 * The previous version moved the shared executive-directory file aside and put
 * it back afterwards. `node --test` runs test files concurrently in separate
 * processes, so that relocated the file for every other test file at the same
 * time - and this one writes organisation domains, which the domain-posture
 * tests read. The result was a test that failed only when the two happened to
 * overlap, which is the worst kind to debug.
 */
async function withIsolatedDirectory(run) {
    const previous = process.env.PHISHLENS_DATA_DIR;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-execguard-'));
    process.env.PHISHLENS_DATA_DIR = dir;
    delete require.cache[require.resolve('../modules/executiveGuard')];
    const guard = require('../modules/executiveGuard');

    try {
        return await run(guard);
    } finally {
        if (previous === undefined) delete process.env.PHISHLENS_DATA_DIR;
        else process.env.PHISHLENS_DATA_DIR = previous;
        delete require.cache[require.resolve('../modules/executiveGuard')];
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
    }
}

function caseFor({ senderName, senderAddress, replyTo, recipient, caseId = 'SM-TEST' }) {
    return {
        threatObject: {
            case_id: caseId,
            message: { sender: `${senderName} <${senderAddress}>`, recipient, subject: 'Request' }
        },
        parsedEmail: {
            from: { name: senderName, address: senderAddress },
            replyTo: replyTo || null
        }
    };
}

function seedDirectory(guard) {
    guard.setOrganizationDomains(['company.example']);
    guard.addPerson({ name: 'Anita Desai', title: 'Chief Financial Officer', email: 'anita.desai@company.example', aliases: ['A. Desai'] });
    guard.addPerson({ name: 'Ravi Kumar', title: 'Chief Executive Officer', email: 'ravi.kumar@company.example' });
}

test('with no directory configured it says so instead of pretending to protect', async () => {
    await withIsolatedDirectory(async (guard) => {
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Anita Desai', senderAddress: 'attacker@evil.example', recipient: 'finance@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);

        assert.strictEqual(result.executive_context.status, 'NO_DIRECTORY_CONFIGURED');
        assert.strictEqual(result.executive_context.findings.length, 0);
        assert.match(result.executive_context.limitation, /No protected people have been configured/);
    });
});

test('a protected person impersonated from another address is detected', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Anita Desai', senderAddress: 'a.desai@company-finance.example', recipient: 'accounts@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);
        const finding = result.executive_context.findings.find(f => f.type === 'EXECUTIVE_DISPLAY_NAME_IMPERSONATION');

        assert.ok(finding, 'impersonation of a protected person must be detected');
        assert.strictEqual(finding.severity, 'CRITICAL');
        assert.strictEqual(result.executive_context.is_impersonated, true);
        assert.ok(finding.explanation.includes('anita.desai@company.example'), 'it must name the real address');
    });
});

test('the genuine person sending from their own address is not flagged', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Anita Desai', senderAddress: 'anita.desai@company.example', recipient: 'accounts@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);

        assert.strictEqual(result.executive_context.is_impersonated, false);
        assert.strictEqual(result.executive_context.findings.filter(f => f.type === 'EXECUTIVE_DISPLAY_NAME_IMPERSONATION').length, 0);
    });
});

test('a known alias of a protected person still resolves to them', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Desai, Anita', senderAddress: 'billing@unrelated.example', recipient: 'accounts@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);
        assert.strictEqual(result.executive_context.is_impersonated, true, 'a reordered name denotes the same person');
    });
});

/**
 * The previous implementation matched with substring tests, so a job title
 * anywhere in an address or name counted as an executive. That produced false
 * accusations against ordinary correspondence.
 */
test('unrelated people whose titles or names merely contain a keyword are not flagged', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);

        const cases = [
            { senderName: 'Marketing Director', senderAddress: 'marketing-director@partner.example', recipient: 'team@company.example' },
            { senderName: 'Sandeep Kumar', senderAddress: 'sandeep.kumar@partner.example', recipient: 'team@company.example' },
            { senderName: 'CEO Digest Newsletter', senderAddress: 'news@digest.example', recipient: 'team@company.example' }
        ];

        for (const spec of cases) {
            const { threatObject, parsedEmail } = caseFor(spec);
            const result = guard.evaluateTarget(threatObject, parsedEmail);
            assert.strictEqual(result.executive_context.is_impersonated, false,
                `"${spec.senderName}" must not be treated as impersonating a protected person`);
        }
    });
});

test('a single shared surname does not identify a protected person', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Priya Desai', senderAddress: 'priya@partner.example', recipient: 'team@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);
        assert.strictEqual(result.executive_context.is_impersonated, false,
            'sharing one common surname is not impersonation');
    });
});

test('a lookalike organisation domain is detected, the real one is not', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);

        const spoof = caseFor({ senderName: 'Accounts', senderAddress: 'billing@cornpany.example', recipient: 'team@company.example' });
        const spoofResult = guard.evaluateTarget(spoof.threatObject, spoof.parsedEmail);
        const finding = spoofResult.executive_context.findings.find(f => f.type === 'LOOKALIKE_ORGANIZATION_DOMAIN');
        assert.ok(finding, 'a near-identical domain must be flagged');
        assert.ok(finding.explanation.includes('company.example'));

        const genuine = caseFor({ senderName: 'Accounts', senderAddress: 'billing@company.example', recipient: 'team@company.example' });
        const genuineResult = guard.evaluateTarget(genuine.threatObject, genuine.parsedEmail);
        assert.strictEqual(genuineResult.executive_context.findings.filter(f => f.type === 'LOOKALIKE_ORGANIZATION_DOMAIN').length, 0,
            'the organisation\'s own domain must never be flagged as a lookalike');

        const unrelated = caseFor({ senderName: 'Accounts', senderAddress: 'billing@entirely-different.example', recipient: 'team@company.example' });
        const unrelatedResult = guard.evaluateTarget(unrelated.threatObject, unrelated.parsedEmail);
        assert.strictEqual(unrelatedResult.executive_context.findings.filter(f => f.type === 'LOOKALIKE_ORGANIZATION_DOMAIN').length, 0,
            'a clearly different domain is not a lookalike');
    });
});

test('reply redirection while impersonating an executive is called out', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);
        const { threatObject, parsedEmail } = caseFor({
            senderName: 'Ravi Kumar', senderAddress: 'ravi@lookalike.example',
            replyTo: 'collector@drop.example', recipient: 'finance@company.example'
        });
        const result = guard.evaluateTarget(threatObject, parsedEmail);
        const finding = result.executive_context.findings.find(f => f.type === 'EXECUTIVE_REPLY_REDIRECTION');

        assert.ok(finding, 'reply redirection during impersonation must be reported');
        assert.ok(finding.explanation.includes('collector@drop.example'));
    });
});

test('targeting a protected person is context, and repeat targeting escalates it', async () => {
    await withIsolatedDirectory(async (guard) => {
        seedDirectory(guard);

        const first = caseFor({ senderName: 'Someone', senderAddress: 'x@external.example', recipient: 'anita.desai@company.example', caseId: 'SM-1' });
        const firstResult = guard.evaluateTarget(first.threatObject, first.parsedEmail);
        const firstFinding = firstResult.executive_context.findings.find(f => f.type === 'PROTECTED_PERSON_TARGETED');
        assert.ok(firstFinding);
        assert.strictEqual(firstFinding.severity, 'MEDIUM', 'a single message to an executive is not itself an attack');
        assert.strictEqual(firstResult.executive_context.is_targeted, true);

        ['SM-2', 'SM-3', 'SM-4'].forEach(id => {
            const next = caseFor({ senderName: 'Someone', senderAddress: 'x@external.example', recipient: 'anita.desai@company.example', caseId: id });
            guard.evaluateTarget(next.threatObject, next.parsedEmail);
        });

        const later = caseFor({ senderName: 'Someone', senderAddress: 'x@external.example', recipient: 'anita.desai@company.example', caseId: 'SM-5' });
        const laterResult = guard.evaluateTarget(later.threatObject, later.parsedEmail);
        const laterFinding = laterResult.executive_context.findings.find(f => f.type === 'PROTECTED_PERSON_TARGETED');

        assert.strictEqual(laterFinding.severity, 'HIGH', 'sustained targeting should escalate');
        assert.match(laterFinding.explanation, /previous flagged message/);
    });
});

test('the directory validates entries and persists them', async () => {
    await withIsolatedDirectory(async (guard) => {
        assert.strictEqual(guard.addPerson({ name: 'X', email: 'not-an-email' }).ok, false);
        assert.strictEqual(guard.addPerson({ name: '', email: 'a@b.example' }).ok, false);

        const added = guard.addPerson({ name: 'Anita Desai', title: 'CFO', email: 'anita@company.example' });
        assert.strictEqual(added.ok, true);
        assert.strictEqual(guard.addPerson({ name: 'Duplicate', email: 'anita@company.example' }).ok, false,
            'the same address must not be protected twice');

        // Path read off the guard so it follows the isolated data directory.
        assert.ok(fs.existsSync(guard.configFile), 'the directory must persist');
        assert.strictEqual(guard.removePerson(added.person.id).ok, true);
        assert.strictEqual(guard.getDirectory().protected_people.length, 0);
    });
});
