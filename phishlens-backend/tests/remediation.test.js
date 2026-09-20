const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

/**
 * The remediation layer is the only part of PhishLens that changes something
 * outside itself, and it was the only part with no tests at all. What is
 * checked here is deliberately weighted towards the ways it could quietly do
 * the wrong thing to somebody's mail, or claim to have done something it did
 * not do.
 */

const os = require('os');

const MODULES = [
    '../modules/remediationEngine',
    '../modules/remediationGateway',
    '../modules/containmentGuard',
    '../modules/caseManager',
    '../modules/auditLogger'
];

/**
 * Each test runs against its own data directory.
 *
 * The first version of this helper moved the real data files aside and put them
 * back afterwards. That is not isolation: `node --test` runs test files
 * concurrently in separate processes, so moving a shared file aside does it to
 * every other test file at the same time - which is how it was caught, by the
 * end-to-end test losing its own case mid-run. Pointing the modules somewhere
 * private is the only version that actually isolates anything.
 */
async function isolated(run) {
    const previous = process.env.PHISHLENS_DATA_DIR;
    const savedMode = process.env.REMEDIATION_MODE;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-remediation-'));
    process.env.PHISHLENS_DATA_DIR = dir;
    MODULES.forEach(m => delete require.cache[require.resolve(m)]);

    const mods = {
        engine: require('../modules/remediationEngine'),
        gateway: require('../modules/remediationGateway'),
        guard: require('../modules/containmentGuard'),
        cases: require('../modules/caseManager')
    };

    try {
        return await run(mods);
    } finally {
        if (savedMode === undefined) delete process.env.REMEDIATION_MODE;
        else process.env.REMEDIATION_MODE = savedMode;
        if (previous === undefined) delete process.env.PHISHLENS_DATA_DIR;
        else process.env.PHISHLENS_DATA_DIR = previous;
        MODULES.forEach(m => delete require.cache[require.resolve(m)]);
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* best effort */ }
    }
}

/** A provider that records what it was asked to do instead of doing it. */
function recordingProvider(verified = true) {
    const calls = [];
    return {
        calls,
        label: 'Test provider',
        quarantine: async (target) => { calls.push({ op: 'quarantine', target }); return { verified, labelId: 'LBL-1', error: verified ? null : 'read-back mismatch' }; },
        release: async (target) => { calls.push({ op: 'release', target }); return { verified, error: verified ? null : 'read-back mismatch' }; },
        warn: async (target) => { calls.push({ op: 'warn', target }); return { verified, labelId: 'LBL-S', error: verified ? null : 'read-back mismatch' }; }
    };
}

/**
 * A high-risk case that every guard would otherwise pass, so a test can change
 * exactly one thing and see which control reacts.
 */
function caseFor(overrides = {}) {
    const ThreatObject = require('../models/ThreatObject');
    const base = new ThreatObject({
        case_id: overrides.case_id || `TEST-${Math.random().toString(36).slice(2, 8)}`,
        detection: { verdict: 'HIGH_RISK' },
        message: {
            sender: 'attacker@evil.example',
            recipient: 'victim@corp.example',
            subject: 'Urgent wire transfer',
            message_id: '<abc@evil.example>'
        }
    });
    base.confidence = {
        threat: 0.92,
        contributions: [
            { family: 'AUTHENTICATION', contribution: 0.3 },
            { family: 'BEC_COMPOSITE', contribution: 0.35 },
            { family: 'THREAT_INTEL', contribution: 0.27 }
        ]
    };
    base.evidence = [
        { evidence_type: 'AUTHENTICATION_ANOMALY', finding: 'SPF failed for the sending host', signal_strength: 0.9 },
        { evidence_type: 'BEC_KEYWORD', finding: 'Requests an urgent payment change', signal_strength: 0.7 }
    ];
    base.mailbox_provenance = {
        organization_id: null,
        mailbox_connection_id: 'conn-1',
        provider_account: 'victim@corp.example',
        provider: 'GMAIL',
        provider_message_id: 'gmail-msg-1'
    };
    Object.assign(base, overrides.assign || {});
    return base;
}

const AUTO_POLICY = { policy_id: 'TEST_AUTO', action_type: 'QUARANTINE_MESSAGE', authorization_mode: 'AUTO_EXECUTE', reason: 'test policy' };
const ADMIN = { id: 'u1', email: 'admin@corp.example', role: 'ADMIN', organization_id: null };

// ---------------------------------------------------------------------------
// The mode switch has to mean something
// ---------------------------------------------------------------------------

/**
 * The defect this exists to prevent: REMEDIATION_MODE was read by an adapter
 * nothing called, while the engine reached Gmail directly. The setting was
 * reported at boot and by /api/summary, and decided nothing.
 */
test('simulation mode does not reach the provider at all', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const result = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);

        assert.strictEqual(provider.calls.length, 0, 'simulation must not call the provider');
        assert.strictEqual(result.remediation.status, 'SIMULATED_QUARANTINE');
        assert.strictEqual(result.remediation.simulated, true);
    });
});

test('a simulated decision is never reported as containment', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        gateway.providers.GMAIL = recordingProvider();

        const result = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);

        assert.strictEqual(result.mailbox.status, 'INBOX',
            'the message has not moved, so the mailbox state must say so');
        assert.notStrictEqual(result.remediation.status, 'QUARANTINED');
        assert.strictEqual(result.provider_action.status, 'NOT_REQUESTED');
    });
});

/**
 * A count of quarantined mail reads mailbox.status. If simulation wrote
 * QUARANTINED there, every dashboard total would overstate what is contained.
 */
test('simulated cases do not appear in a count of quarantined mail', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        gateway.providers.GMAIL = recordingProvider();

        const results = [];
        for (let i = 0; i < 3; i++) {
            results.push(await engine.executePolicyDecision(caseFor({ case_id: `SIM-${i}` }), AUTO_POLICY));
        }
        const quarantined = results.filter(c => c.mailbox.status === 'QUARANTINED').length;
        assert.strictEqual(quarantined, 0);
    });
});

test('live mode reaches the provider and reports containment only on read-back', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider(true);
        gateway.providers.GMAIL = provider;

        const result = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);

        assert.strictEqual(provider.calls.length, 1);
        assert.strictEqual(provider.calls[0].op, 'quarantine');
        assert.strictEqual(result.mailbox.status, 'QUARANTINED');
        assert.strictEqual(result.remediation.status, 'QUARANTINED');
        assert.strictEqual(result.provider_action.status, 'PROVIDER_CONFIRMED');
    });
});

/** An accepted API call is not evidence that a message moved. */
test('a provider that does not confirm the change is a failure, not a containment', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        gateway.providers.GMAIL = recordingProvider(false);

        const result = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);

        assert.strictEqual(result.remediation.status, 'FAILED');
        assert.strictEqual(result.mailbox.status, 'ACTION_FAILED');
    });
});

// ---------------------------------------------------------------------------
// Actionability
// ---------------------------------------------------------------------------

/**
 * The regression this pins: with no provenance recorded, containment could not
 * resolve a target, and every high-risk case was written ACTION_FAILED. The
 * console showed a wall of failures for messages that were never actionable,
 * and a real provider failure was indistinguishable from them.
 */
test('a message that never came from a mailbox is not actionable, not failed', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const uploaded = caseFor();
        uploaded.mailbox_provenance = { provider: 'NONE', provider_message_id: null, provider_account: 'victim@corp.example' };

        const result = await engine.executePolicyDecision(uploaded, AUTO_POLICY);

        assert.strictEqual(result.remediation.status, 'NOT_ACTIONABLE');
        assert.strictEqual(result.mailbox.status, 'INBOX');
        assert.strictEqual(result.provider_action.status, 'NOT_APPLICABLE');
        assert.strictEqual(provider.calls.length, 0);
        assert.match(result.remediation.detail, /not read from a connected mailbox/);
    });
});

test('the provider is chosen from where the message came from', async () => {
    await isolated(async ({ gateway }) => {
        const imapCase = caseFor();
        imapCase.mailbox_provenance = {
            provider: 'IMAP', provider_account: 'ops@corp.example',
            provider_message_id: '4471', uid: 4471, folder: 'INBOX'
        };
        const target = gateway.resolveTarget(imapCase);

        assert.strictEqual(target.actionable, true);
        assert.strictEqual(target.provider, 'IMAP');
        assert.strictEqual(target.uid, 4471);
        assert.strictEqual(target.rfc_message_id, '<abc@evil.example>',
            'IMAP release needs the Message-ID, because a moved message gets a new UID');
    });
});

test('a provider with no action adapter is reported as such rather than attempted', async () => {
    await isolated(async ({ gateway }) => {
        const exchange = caseFor();
        exchange.mailbox_provenance = { provider: 'EXCHANGE', provider_account: 'x@corp.example', provider_message_id: 'AAMk' };
        const target = gateway.resolveTarget(exchange);

        assert.strictEqual(target.actionable, false);
        assert.strictEqual(target.reason, 'NO_ADAPTER_FOR_PROVIDER');
    });
});

// ---------------------------------------------------------------------------
// The guards, which replace one that could never fire
// ---------------------------------------------------------------------------

test('a verdict below the confidence floor is queued for review, not contained', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const weak = caseFor();
        weak.confidence.threat = 0.72;

        const result = await engine.executePolicyDecision(weak, AUTO_POLICY);

        assert.strictEqual(result.remediation.status, 'BLOCKED_BY_GUARD');
        assert.strictEqual(result.remediation.blocked_by, 'CONFIDENCE_FLOOR');
        assert.strictEqual(result.review.status, 'PENDING_ADMIN');
        assert.strictEqual(provider.calls.length, 0);
    });
});

/** One signal is not enough to move somebody's mail without being asked. */
test('a single evidence family is not enough for automatic containment', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const thin = caseFor();
        thin.confidence.contributions = [{ family: 'LANGUAGE', contribution: 0.25 }];

        const result = await engine.executePolicyDecision(thin, AUTO_POLICY);

        assert.strictEqual(result.remediation.blocked_by, 'CORROBORATION');
        assert.strictEqual(provider.calls.length, 0);
    });
});

test('a decisive finding satisfies corroboration on its own', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const decisive = caseFor();
        decisive.confidence.contributions = [{ family: 'THREAT_INTEL', contribution: 0.35 }];
        decisive.evidence = [{ evidence_type: 'THREAT_INTEL', finding: 'URL is on a malicious-URL feed', decisive: true, signal_strength: 0.95 }];

        const result = await engine.executePolicyDecision(decisive, AUTO_POLICY);

        assert.strictEqual(result.remediation.status, 'QUARANTINED');
        assert.strictEqual(provider.calls.length, 1);
    });
});

/**
 * What the never-contain list is really for: mail whose delay costs more than
 * the phishing it might occasionally carry.
 */
test('a sender on the never-contain list is raised for review instead', async () => {
    await isolated(async ({ engine, gateway, guard }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;
        guard.addNeverContain('payroll.example');

        const payroll = caseFor();
        payroll.message.sender = 'noreply@payroll.example';

        const result = await engine.executePolicyDecision(payroll, AUTO_POLICY);

        assert.strictEqual(result.remediation.blocked_by, 'NEVER_CONTAIN_LIST');
        assert.strictEqual(provider.calls.length, 0);
    });
});

test('an exact address can be excluded without excluding its whole domain', async () => {
    await isolated(async ({ guard }) => {
        guard.addNeverContain('ceo@corp.example');
        assert.strictEqual(guard.isNeverContain('ceo@corp.example'), true);
        assert.strictEqual(guard.isNeverContain('someone-else@corp.example'), false);
    });
});

/** A misfiring rule must not be able to empty an inbox before anyone notices. */
test('automatic containment stops after the configured burst limit', async () => {
    await isolated(async ({ engine, gateway, guard }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;
        guard.config.burstLimit = 3;

        const outcomes = [];
        for (let i = 0; i < 5; i++) {
            const r = await engine.executePolicyDecision(caseFor({ case_id: `BURST-${i}` }), AUTO_POLICY);
            outcomes.push(r.remediation.status);
        }

        assert.strictEqual(outcomes.filter(o => o === 'QUARANTINED').length, 3);
        assert.strictEqual(outcomes.filter(o => o === 'BLOCKED_BY_GUARD').length, 2);
        assert.strictEqual(provider.calls.length, 3, 'the provider must not be called past the limit');
    });
});

/**
 * The guard being replaced keyed off detection.is_dev_fallback and a
 * verification_status containing "DEVELOPMENT". Both are now assigned fixed
 * values by the pipeline, so the condition could never be true. This pins that
 * the replacement reacts to conditions that actually occur.
 */
test('the guard refuses on grounds that can really happen', async () => {
    await isolated(async ({ guard }) => {
        const safeVerdict = caseFor();
        safeVerdict.detection.verdict = 'SUSPICIOUS';
        assert.strictEqual(guard.evaluate(safeVerdict).control, 'VERDICT_FLOOR');

        const passing = guard.evaluate(caseFor());
        assert.strictEqual(passing.allowed, true);
        assert.match(passing.reason, /independent evidence famil/);
    });
});

// ---------------------------------------------------------------------------
// Human-in-the-loop
// ---------------------------------------------------------------------------

/**
 * REQUIRE_APPROVAL previously fell through to "leave it in the inbox" and
 * /api/remediate/approve called a method that did not exist, so an
 * approval-gated policy could never be acted on at all.
 */
test('a policy needing approval raises something an analyst can approve', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const result = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'TEST_APPROVAL', action_type: 'QUARANTINE_MESSAGE',
            authorization_mode: 'REQUIRE_APPROVAL', reason: 'campaign correlated'
        });

        assert.strictEqual(result.remediation.status, 'PENDING_APPROVAL');
        assert.strictEqual(provider.calls.length, 0, 'nothing may move before a person approves it');

        const pending = engine.getPendingApprovals();
        assert.strictEqual(pending.length, 1);
        assert.strictEqual(pending[0].case_id, result.case_id);
    });
});

test('approving a pending action carries it out and records who approved it', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const raised = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'TEST_APPROVAL', action_type: 'QUARANTINE_MESSAGE',
            authorization_mode: 'REQUIRE_APPROVAL', reason: 'campaign correlated'
        });
        cases.saveCase(raised);

        const action = await engine.approveAction(engine.getPendingApprovals()[0].action_id, ADMIN, 'reviewed and agreed');

        assert.strictEqual(action.status, 'COMPLETED');
        assert.strictEqual(action.authorization.authorized_by, 'admin@corp.example');
        assert.strictEqual(provider.calls.length, 1);
    });
});

test('a non-admin cannot approve a containment', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'live';
        gateway.providers.GMAIL = recordingProvider();

        const raised = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'TEST_APPROVAL', action_type: 'QUARANTINE_MESSAGE',
            authorization_mode: 'REQUIRE_APPROVAL', reason: 'campaign correlated'
        });
        cases.saveCase(raised);

        await assert.rejects(
            () => engine.approveAction(engine.getPendingApprovals()[0].action_id, { id: 'u2', email: 'analyst@corp.example', role: 'ANALYST' }),
            /Admin role required/
        );
    });
});

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

test('a real containment can be rolled back and the message restored', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider(true);
        gateway.providers.GMAIL = provider;

        const contained = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);
        cases.saveCase(contained);
        const actionId = engine.getAllActions().find(a => a.case_id === contained.case_id).action_id;

        const rolled = await engine.rollbackAction(actionId, ADMIN, 'false positive on review');

        assert.strictEqual(rolled.rollback.status, 'REVERSED');
        assert.strictEqual(rolled.rollback.reversed_by, 'admin@corp.example');
        assert.strictEqual(provider.calls.filter(c => c.op === 'release').length, 1);
    });
});

/** Undoing something that never happened should say so, not report success. */
test('a simulated action cannot be rolled back, and says why', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        gateway.providers.GMAIL = recordingProvider();

        const simulated = await engine.executePolicyDecision(caseFor(), AUTO_POLICY);
        cases.saveCase(simulated);
        const actionId = engine.getAllActions().find(a => a.case_id === simulated.case_id).action_id;

        await assert.rejects(
            () => engine.rollbackAction(actionId, ADMIN),
            /simulated, so no mailbox was changed/
        );
    });
});

// ---------------------------------------------------------------------------
// Recipient warnings
// ---------------------------------------------------------------------------

test('a warning leaves the message delivered and marks it where the recipient looks', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider(true);
        gateway.providers.GMAIL = provider;

        const result = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'SUSPICIOUS_USER_WARNING', action_type: 'ALERT_RECIPIENT',
            authorization_mode: 'AUTO_EXECUTE', reason: 'moderate anomaly'
        });

        assert.strictEqual(result.remediation.status, 'RECIPIENT_WARNED');
        assert.strictEqual(result.mailbox.status, 'INBOX', 'a warning must not move the message');
        assert.strictEqual(provider.calls[0].op, 'warn');
        assert.strictEqual(result.remediation.warning.recipient_visible, true);
    });
});

/**
 * If nobody was actually warned, the case must not say somebody was. An
 * operator reading "recipient warned" will assume a person saw something.
 */
test('in simulation the warning is recorded but not claimed to be visible', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const result = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'SUSPICIOUS_USER_WARNING', action_type: 'ALERT_RECIPIENT',
            authorization_mode: 'AUTO_EXECUTE', reason: 'moderate anomaly'
        });

        assert.strictEqual(result.remediation.warning.recipient_visible, false);
        assert.strictEqual(provider.calls.length, 0);
    });
});

test('the warning text tells the recipient what was noticed and what to do', async () => {
    await isolated(async ({ engine, gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        gateway.providers.GMAIL = recordingProvider();

        const result = await engine.executePolicyDecision(caseFor(), {
            policy_id: 'SUSPICIOUS_USER_WARNING', action_type: 'ALERT_RECIPIENT',
            authorization_mode: 'AUTO_EXECUTE', reason: 'moderate anomaly'
        });

        const text = result.remediation.warning.detail;
        assert.match(text, /SPF failed/, 'it should name the strongest finding');
        assert.match(text, /channel you already trust/, 'and give the recipient something to do');
        assert.doesNotMatch(text, /0\.\d\d/, 'without quoting a score at a non-specialist');
    });
});

// ---------------------------------------------------------------------------
// Administrator override
// ---------------------------------------------------------------------------

test('an administrator can contain a case the automatic guards refused', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'live';
        const provider = recordingProvider(true);
        gateway.providers.GMAIL = provider;

        const weak = caseFor();
        weak.confidence.threat = 0.72;
        const blocked = await engine.executePolicyDecision(weak, AUTO_POLICY);
        assert.strictEqual(blocked.remediation.status, 'BLOCKED_BY_GUARD');
        cases.saveCase(blocked);

        const result = await engine.adminOverride(blocked.case_id, 'QUARANTINE', ADMIN);

        assert.strictEqual(result.outcome, 'CONTAINED',
            'the guards constrain the machine acting unasked, not a person who looked at the case');
        assert.strictEqual(provider.calls.length, 1);
    });
});

test('an override still obeys simulation mode, which is not a judgement call', async () => {
    await isolated(async ({ engine, gateway, cases }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const stored = cases.saveCase(caseFor());
        const result = await engine.adminOverride(stored.case_id, 'QUARANTINE', ADMIN);

        assert.strictEqual(result.outcome, 'SIMULATED');
        assert.strictEqual(provider.calls.length, 0);
    });
});

test('an unsupported override action is refused rather than guessed at', async () => {
    await isolated(async ({ engine, cases }) => {
        const stored = cases.saveCase(caseFor());
        await assert.rejects(() => engine.adminOverride(stored.case_id, 'DELETE', ADMIN), /Unsupported override action/);
    });
});

// ---------------------------------------------------------------------------
// What the operator is told
// ---------------------------------------------------------------------------

test('the stated capability matches what the installation will actually do', async () => {
    await isolated(async ({ gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        const simulating = gateway.capability();
        assert.strictEqual(simulating.can_act_on_mail, false);
        assert.match(simulating.statement, /does not change any mailbox/);

        process.env.REMEDIATION_MODE = 'live';
        const living = gateway.capability();
        assert.strictEqual(living.can_act_on_mail, true);
        assert.match(living.statement, /read back and confirmed/);
    });
});

test('a preview says what would happen without anything happening', async () => {
    await isolated(async ({ gateway }) => {
        process.env.REMEDIATION_MODE = 'simulation';
        const provider = recordingProvider();
        gateway.providers.GMAIL = provider;

        const preview = gateway.preview(caseFor());

        assert.strictEqual(preview.would_execute, false);
        assert.match(preview.explanation, /REMEDIATION_MODE=live/);
        assert.strictEqual(provider.calls.length, 0);
    });
});

/** An analyst's judgement is the valuable part and must survive a mailbox that could not be changed. */
test('a release records the analyst decision even when no mailbox could be touched', async () => {
    await isolated(async ({ engine, cases }) => {
        process.env.REMEDIATION_MODE = 'simulation';

        const uploaded = caseFor();
        uploaded.mailbox_provenance = { provider: 'NONE', provider_message_id: null, provider_account: 'victim@corp.example' };
        const stored = cases.saveCase(uploaded);

        const result = await engine.releaseCase(stored.case_id, ADMIN, 'FALSE_POSITIVE', 'known vendor');

        assert.strictEqual(result.case.review.status, 'RELEASED_BY_ADMIN');
        assert.strictEqual(result.case.containment_context.decision_reason, 'FALSE_POSITIVE');
        assert.strictEqual(result.mailbox_outcome, 'NOT_ACTIONABLE');
    });
});

test('a confirmed threat is retained as evidence and never deleted', async () => {
    await isolated(async ({ engine, cases }) => {
        const stored = cases.saveCase(caseFor());
        const result = await engine.confirmThreat(stored.case_id, ADMIN, 'MALICIOUS_PHISH');

        assert.strictEqual(result.case.review.status, 'CONFIRMED_THREAT');
        assert.strictEqual(result.action.reversible, false);
        assert.notStrictEqual(result.case.mailbox.status, 'DELETED');
    });
});

test('a case cannot be both released and confirmed', async () => {
    await isolated(async ({ engine, cases }) => {
        const stored = cases.saveCase(caseFor());
        await engine.confirmThreat(stored.case_id, ADMIN, 'MALICIOUS_PHISH');
        await assert.rejects(() => engine.releaseCase(stored.case_id, ADMIN), /confirmed as a threat/);
    });
});

// ---------------------------------------------------------------------------
// Policy coverage
// ---------------------------------------------------------------------------

/**
 * The hole this closes: every quarantine policy carried its own extra
 * condition - executive context, a Return-Path mismatch, campaign correlation -
 * so a message scoring 0.95 with a HIGH_RISK verdict that matched none of them
 * fell through to DEFAULT_ALLOW. Detection reached the right conclusion and
 * absolutely nothing happened to the message.
 */
test('no verdict falls through the policy set without a response', async () => {
    const policyEngine = require('../modules/policyEngine');
    const build = (conf) => ({
        confidence: { threat: conf, campaign_association: 0 },
        detection: { verdict: conf >= 0.70 ? 'HIGH_RISK' : conf >= 0.35 ? 'SUSPICIOUS' : 'SAFE' },
        evidence: [{ evidence_type: 'AUTHENTICATION_ANOMALY', finding: 'SPF failed' }],
        executive_context: {}, forensics: {}, remediation: {}
    });

    for (let conf = 0.35; conf <= 0.99; conf += 0.01) {
        const threatObject = build(Number(conf.toFixed(2)));
        const decision = policyEngine.evaluate(threatObject);
        assert.notStrictEqual(decision.action_type, 'NO_ACTION',
            `a ${threatObject.detection.verdict} verdict at confidence ${conf.toFixed(2)} produced no response at all`);
    }
});

test('every high-risk verdict asks for containment, whatever else the message looks like', async () => {
    const policyEngine = require('../modules/policyEngine');
    const plain = {
        confidence: { threat: 0.95, campaign_association: 0 },
        detection: { verdict: 'HIGH_RISK' },
        evidence: [{ evidence_type: 'URL_RISK', finding: 'Link points to a newly registered domain' }],
        executive_context: {}, forensics: {}, remediation: {}
    };
    const decision = policyEngine.evaluate(plain);

    assert.strictEqual(decision.action_type, 'QUARANTINE_MESSAGE');
    assert.strictEqual(decision.policy_id, 'HIGH_RISK_CONTAINMENT');
});

/** The more specific policies still win, because they explain themselves better. */
test('a specific policy takes precedence over the catch-all', async () => {
    const policyEngine = require('../modules/policyEngine');
    const vip = {
        confidence: { threat: 0.90, campaign_association: 0 },
        detection: { verdict: 'HIGH_RISK' },
        evidence: [{ evidence_type: 'BEC_KEYWORD', finding: 'Requests an urgent payment change' }],
        executive_context: { is_impersonated: true }, forensics: {}, remediation: {}
    };
    assert.strictEqual(policyEngine.evaluate(vip).policy_id, 'CRITICAL_BEC_VIP');
});

/** A safe verdict must still mean no action; full coverage is not the same as acting on everything. */
test('a safe verdict is still left alone', async () => {
    const policyEngine = require('../modules/policyEngine');
    const safe = {
        confidence: { threat: 0.10, campaign_association: 0 },
        detection: { verdict: 'SAFE' }, evidence: [],
        executive_context: {}, forensics: {}, remediation: {}
    };
    assert.strictEqual(policyEngine.evaluate(safe).action_type, 'NO_ACTION');
});
