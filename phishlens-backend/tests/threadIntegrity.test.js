const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Thread hijacking is the case where reading the message cannot help.
 *
 * The prose is genuinely flawless - it is a real conversation, quoted
 * underneath, with real names and real history. No language model finds fault
 * with it and no urgency heuristic applies. What is wrong is who replied.
 *
 * These tests run against a private thread index, because the module builds
 * history as it goes and one test's conversation must not leak into another's.
 */

function isolated(run) {
    const previous = process.env.PHISHLENS_DATA_DIR;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-thread-'));
    process.env.PHISHLENS_DATA_DIR = dir;
    ['../modules/threadIntegrity', '../modules/ruleEngine'].forEach(m => delete require.cache[require.resolve(m)]);

    const threadIntegrity = require('../modules/threadIntegrity');
    const ruleEngine = require('../modules/ruleEngine');

    try {
        return run({ threadIntegrity, ruleEngine });
    } finally {
        if (previous === undefined) delete process.env.PHISHLENS_DATA_DIR;
        else process.env.PHISHLENS_DATA_DIR = previous;
        ['../modules/threadIntegrity', '../modules/ruleEngine'].forEach(m => delete require.cache[require.resolve(m)]);
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
    }
}

function message(id, from, inReplyTo, references, subject) {
    return {
        messageId: `<${id}>`,
        from: { address: from, name: '' },
        subject,
        inReplyTo: inReplyTo ? `<${inReplyTo}>` : null,
        references: (references || []).map(r => `<${r}>`),
        textBody: 'Thanks, that works for me.',
        attachments: []
    };
}

/** Runs one message through analysis and the rules, then indexes it. */
function ingest({ threadIntegrity, ruleEngine }, parsed, { auth = 'pass', verdict = 'SAFE' } = {}) {
    let threatObject = {
        detection: { verdict },
        message: { subject: parsed.subject },
        iocs: { urls: [] },
        qr: { codes: [], not_scanned: [] },
        forensics: { authentication: { dmarc: auth } }
    };
    threatObject = threadIntegrity.analyze(threatObject, parsed);
    const evaluated = ruleEngine.evaluate(threatObject, parsed);
    threadIntegrity.record(threatObject, parsed);
    return evaluated.detection.matched_rules.filter(r => r.id.startsWith('MQL-THREAD')).map(r => r.id);
}

/** A three-message conversation between two people plus a colleague. */
function establishConversation(ctx) {
    ingest(ctx, message('root@corp.example', 'jane@corp.example', null, [], 'Q3 budget'));
    ingest(ctx, message('m2@supplier.example', 'sam@supplier.example', 'root@corp.example', ['root@corp.example'], 'Re: Q3 budget'));
    ingest(ctx, message('m3@corp.example', 'jane@corp.example', 'm2@supplier.example', ['root@corp.example', 'm2@supplier.example'], 'Re: Q3 budget'));
}

// ---------------------------------------------------------------------------
// It must not accuse ordinary correspondence
// ---------------------------------------------------------------------------

/**
 * The first version of this check flagged exactly this message. In any
 * two-party exchange the second message is from somebody new, so "a participant
 * not seen before" on its own accuses every supplier who ever answered an
 * email.
 */
test('a supplier replying for the first time is not flagged', () => {
    isolated(ctx => {
        ingest(ctx, message('root@corp.example', 'jane@corp.example', null, [], 'Q3 budget'));
        const hits = ingest(ctx, message('m2@supplier.example', 'sam@supplier.example', 'root@corp.example', ['root@corp.example'], 'Re: Q3 budget'));
        assert.deepStrictEqual(hits, [], 'a first reply is a conversation, not an intrusion');
    });
});

test('a participant replying again is not flagged', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx, message('m4@supplier.example', 'sam@supplier.example', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'));
        assert.deepStrictEqual(hits, []);
    });
});

test('a new message that starts its own thread is not flagged', () => {
    isolated(ctx => {
        const hits = ingest(ctx, message('fresh@corp.example', 'newperson@corp.example', null, [], 'Introductions'));
        assert.deepStrictEqual(hits, []);
    });
});

/** People are added to threads constantly, so this is context, not an accusation. */
test('a colleague added to an established thread raises only the weak signal', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx, message('m4@corp.example', 'priya@corp.example', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'));

        assert.deepStrictEqual(hits, ['MQL-THREAD-104'],
            'weak and alone - not the strong lookalike rule');
    });
});

// ---------------------------------------------------------------------------
// The hijack shapes
// ---------------------------------------------------------------------------

/**
 * Compared on the registrable label, not the whole domain. As full domains
 * `supplier.example` and `supplier-invoices.test` are eleven edits apart - the
 * entire suffix differs - and an earlier version of this check missed the most
 * obvious hijack there is.
 */
test('a reply from a domain built around a participant name is caught', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx,
            message('e1@x.test', 'sam@supplier-invoices.test', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'),
            { auth: 'fail', verdict: 'HIGH_RISK' });

        assert.ok(hits.includes('MQL-THREAD-101'), 'supplier-invoices.test impersonates supplier.example');
    });
});

test('a single-character substitution in the domain is caught', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx,
            message('e2@x.test', 'sam@suppiier.example', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'),
            { auth: 'fail', verdict: 'HIGH_RISK' });

        assert.ok(hits.includes('MQL-THREAD-101'));
    });
});

test('the same name on a different suffix is caught', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx,
            message('e3@x.test', 'sam@supplier.test', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'),
            { auth: 'fail', verdict: 'HIGH_RISK' });

        assert.ok(hits.includes('MQL-THREAD-101'));
    });
});

/**
 * The earlier messages are what make this meaningful: they establish what this
 * correspondent's mail normally looks like.
 */
test('a participant whose mail suddenly stops authenticating is caught', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hits = ingest(ctx,
            message('e4@x.test', 'sam@supplier.example', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget'),
            { auth: 'fail', verdict: 'HIGH_RISK' });

        assert.ok(hits.includes('MQL-THREAD-102'));
    });
});

test('a subject claiming to be a reply with no thread headers is caught', () => {
    isolated(ctx => {
        const hits = ingest(ctx, {
            messageId: '<e5@x.test>',
            from: { address: 'sam@supplier.example' },
            subject: 'Re: Q3 budget',
            inReplyTo: null,
            references: [],
            textBody: 'As discussed, please update the payment details.',
            attachments: []
        }, { auth: 'fail', verdict: 'HIGH_RISK' });

        assert.ok(hits.includes('MQL-THREAD-103'));
    });
});

// ---------------------------------------------------------------------------
// The index itself
// ---------------------------------------------------------------------------

/**
 * Indexing a hijacker as a legitimate participant would make the *next*
 * message in that thread look entirely normal - the attack would teach the
 * system to accept it.
 */
test('a high-risk message is never recorded as a thread participant', () => {
    isolated(ctx => {
        establishConversation(ctx);
        const hijack = message('e6@x.test', 'attacker@supplier-invoices.test', 'm3@corp.example', ['root@corp.example', 'm3@corp.example'], 'Re: Q3 budget');
        ingest(ctx, hijack, { auth: 'fail', verdict: 'HIGH_RISK' });

        const root = ctx.threadIntegrity.threadRoot(hijack);
        const thread = ctx.threadIntegrity.threads.get(root);
        assert.ok(!thread.participants.has('attacker@supplier-invoices.test'),
            'the attack must not teach the index to accept the attacker');
    });
});

test('thread state reports its own limitation', () => {
    isolated(ctx => {
        let threatObject = ctx.threadIntegrity.analyze({ message: {} },
            message('x@corp.example', 'a@corp.example', 'unknown-root@elsewhere', ['unknown-root@elsewhere'], 'Re: something'));

        assert.strictEqual(threatObject.thread.thread_known, false);
        assert.match(threatObject.thread.limitation, /only what this installation has observed/);
        assert.ok(threatObject.thread.findings.some(f => f.type === 'THREAD_NOT_PREVIOUSLY_SEEN'));
    });
});

test('thread headers survive parsing', async () => {
    const emailParser = require('../modules/emailParser');
    const raw = [
        'From: a@corp.example', 'To: b@corp.example', 'Subject: Re: Q3 budget',
        'Message-ID: <child@corp.example>', 'In-Reply-To: <parent@corp.example>',
        'References: <root@corp.example> <parent@corp.example>', '', 'reply body'
    ].join('\r\n');

    const parsed = await emailParser.parse(raw);
    assert.strictEqual(parsed.inReplyTo, '<parent@corp.example>');
    assert.deepStrictEqual(parsed.references, ['<root@corp.example>', '<parent@corp.example>']);
});
