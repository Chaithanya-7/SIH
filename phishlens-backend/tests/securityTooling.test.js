const test = require('node:test');
const assert = require('node:assert');
const zlib = require('zlib');

const { SecurityTools, TOOLS } = require('../modules/securityTools');
const { AttachmentInspector } = require('../modules/attachmentInspector');
const { ConnectionEvidence } = require('../modules/connectionEvidence');

/**
 * These tests exist because the integrations they cover are optional, and an
 * optional integration fails in a particular way: it goes quiet. A tool that is
 * not installed produces no findings, which looks exactly like a tool that ran
 * and found nothing. Most of what is asserted here is that those two never
 * render as the same thing.
 */

// ---------------------------------------------------------------------------
// Building fixtures, so no test depends on a file or a tool being present.
// ---------------------------------------------------------------------------

/**
 * A minimal ZIP, assembled by hand.
 *
 * Entries are stored rather than deflated and the CRC is left at zero, because
 * the inspector walks the directory and never verifies either - so a real one
 * would test the fixture builder rather than the code under test.
 */
function buildZip(files) {
    const chunks = [];
    const central = [];
    let offset = 0;

    for (const [name, content] of Object.entries(files)) {
        const nameBytes = Buffer.from(name, 'utf8');
        const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(0, 8);           // stored
        local.writeUInt32LE(0, 14);          // crc, unchecked by the inspector
        local.writeUInt32LE(data.length, 18);
        local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(nameBytes.length, 26);

        chunks.push(local, nameBytes, data);

        const entry = Buffer.alloc(46);
        entry.writeUInt32LE(0x02014b50, 0);
        entry.writeUInt16LE(20, 6);
        entry.writeUInt16LE(0, 10);
        entry.writeUInt32LE(0, 16);
        entry.writeUInt32LE(data.length, 20);
        entry.writeUInt32LE(data.length, 24);
        entry.writeUInt16LE(nameBytes.length, 28);
        entry.writeUInt32LE(offset, 42);
        central.push(entry, nameBytes);

        offset += local.length + nameBytes.length + data.length;
    }

    const directory = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(Object.keys(files).length, 8);
    end.writeUInt16LE(Object.keys(files).length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);

    return Buffer.concat([...chunks, directory, end]);
}

/** A detector that reports whatever a test needs, without touching the machine. */
function toolsReporting(report) {
    return {
        detect: async () => report,
        run: async () => ({ ok: false, output: '', error: 'not called' })
    };
}

const codes = inspection => inspection.findings.map(f => f.code);

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

test('an unavailable tool always carries the reason it is unavailable', async () => {
    const tools = new SecurityTools();
    const result = await tools.detect('clamscan');

    if (result.available) return; // Installed on this machine; nothing to assert.

    assert.ok(result.reason, 'an unavailable tool must say why');
    assert.ok(result.detail, 'an unavailable tool must explain itself in words');
    assert.ok(result.install_hint, 'an unavailable tool must say how to obtain it');
    assert.ok(result.purpose, 'an unavailable tool must say what it would have added');
});

test('every tool declares a licence, because the promise is that all of this is free', () => {
    for (const [key, spec] of Object.entries(TOOLS)) {
        assert.ok(spec.license, `${key} must state its licence`);
        assert.ok(spec.capability, `${key} must say which capability it provides`);
        assert.ok(spec.limitation, `${key} must state what it cannot do`);
    }
});

test('tshark is looked for where its installer puts it, not only on PATH', () => {
    // The Wireshark installer does not modify PATH on Windows, so a PATH-only
    // check reports a machine that has Wireshark as a machine that does not.
    const paths = TOOLS.tshark.knownPaths.join(' ');
    assert.match(paths, /Program Files\\Wireshark/, 'the Windows install location must be searched');
});

test('an unknown tool is refused rather than quietly reported as missing', async () => {
    const tools = new SecurityTools();
    await assert.rejects(() => tools.detect('nmap'), /No such tool/);
});

// ---------------------------------------------------------------------------
// Attachments: what can be found with nothing installed
// ---------------------------------------------------------------------------

test('a document carrying macros is identified without any tool installed', async () => {
    const inspector = new AttachmentInspector(toolsReporting({
        available: false, reason: 'NOT_INSTALLED', detail: 'not installed', install_hint: 'pip install oletools', purpose: 'reads macro code'
    }));

    const docm = buildZip({
        '[Content_Types].xml': '<Types/>',
        'word/document.xml': '<w:document/>',
        'word/vbaProject.bin': Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    });

    const result = await inspector.inspect(docm, { fileName: 'invoice.docm' });
    assert.ok(codes(result).includes('OFFICE_MACROS_PRESENT'));
});

test('an ordinary document produces no findings at all', async () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false, reason: 'NOT_INSTALLED', detail: '', install_hint: '', purpose: '' }));

    const docx = buildZip({
        '[Content_Types].xml': '<Types/>',
        'word/document.xml': '<w:document><w:body>Hello</w:body></w:document>'
    });

    const result = await inspector.inspect(docx, { fileName: 'notes.docx' });
    assert.deepStrictEqual(result.findings, [], 'a clean document must not be described as suspicious');
    assert.strictEqual(result.macro_analysis, null, 'a document without macros has no macro analysis to report');
});

test('a document that fetches its template over the network is caught, though it carries no macros', async () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false, reason: 'NOT_INSTALLED', detail: '', install_hint: '', purpose: '' }));

    const docx = buildZip({
        '[Content_Types].xml': '<Types/>',
        'word/_rels/settings.xml.rels':
            '<Relationships><Relationship Id="rId1" ' +
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" ' +
            'Target="http://198.51.100.20/payload.dotm" TargetMode="External"/></Relationships>'
    });

    const result = await inspector.inspect(docx, { fileName: 'agreement.docx' });
    assert.ok(codes(result).includes('REMOTE_TEMPLATE_REFERENCE'));

    const finding = result.findings.find(f => f.code === 'REMOTE_TEMPLATE_REFERENCE');
    assert.match(finding.url, /198\.51\.100\.20/);
});

test('a program named to look like a document is reported for each thing that is wrong with it', async () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false, reason: 'NOT_INSTALLED', detail: '', install_hint: '', purpose: '' }));

    const executable = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200)]);
    const result = await inspector.inspect(executable, {
        fileName: 'invoice.pdf.exe',
        declaredMimeType: 'application/pdf'
    });

    const found = codes(result);
    assert.ok(found.includes('DOUBLE_EXTENSION'), 'the hidden second extension');
    assert.ok(found.includes('EXECUTABLE_ATTACHMENT'), 'that it is run rather than opened');
    assert.ok(found.includes('EXECUTABLE_DECLARED_AS_DOCUMENT'), 'that the message misdescribed it');
});

test('a filename that reverses how it is displayed is reported', async () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false, reason: 'NOT_INSTALLED', detail: '', install_hint: '', purpose: '' }));

    // U+202E makes what follows render right-to-left, so this is shown as a .doc.
    const result = await inspector.inspect(Buffer.from('MZ'), { fileName: 'report‮cod.exe' });
    assert.ok(codes(result).includes('BIDI_FILENAME'));
});

test('the same PDF fact is not reported twice under two spellings', async () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false, reason: 'NOT_INSTALLED', detail: '', install_hint: '', purpose: '' }));

    // /JavaScript and /JS are the same construct; both appear in the same object.
    const pdf = Buffer.from('%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript/JS(x)>>>>endobj\n%%EOF');
    const result = await inspector.inspect(pdf, { fileName: 'statement.pdf' });

    const javascriptFindings = codes(result).filter(c => /JAVASCRIPT|PDF_JS/.test(c));
    assert.strictEqual(javascriptFindings.length, 1, 'one construct, one finding');
    assert.ok(codes(result).includes('PDF_OPEN_ACTION'));
});

// ---------------------------------------------------------------------------
// The honesty invariant
// ---------------------------------------------------------------------------

test('when macros are present but unreadable, the result says so rather than going quiet', async () => {
    const inspector = new AttachmentInspector(toolsReporting({
        available: false,
        reason: 'NOT_INSTALLED',
        detail: 'Python is present but the oletools module is not installed.',
        install_hint: 'pip install oletools',
        purpose: 'Extracts the macro code inside an Office attachment.'
    }));

    const docm = buildZip({ 'word/vbaProject.bin': Buffer.from([0xd0, 0xcf, 0x11, 0xe0]) });
    const result = await inspector.inspect(docm, { fileName: 'invoice.docm' });

    assert.strictEqual(result.macro_analysis.status, 'UNAVAILABLE');
    assert.match(result.macro_analysis.detail, /was not read/, 'it must say the code went unread');
    assert.ok(result.macro_analysis.remedy, 'it must say how to make it readable');

    // The wording is load-bearing: this must not be mistakable for a clean result.
    assert.doesNotMatch(result.macro_analysis.detail, /\b(clean|safe|no macros found)\b/i);
});

test('a macro project the reader cannot parse becomes a finding, not a pass', async () => {
    const inspector = new AttachmentInspector({
        detect: async () => ({ available: true, name: 'olevba', version: '0.60.2', invocation: { command: 'x', prefix: [] } }),
        // Stands in for olevba falling over on a malformed project.
        run: async () => ({ ok: false, output: 'Unhandled exception in main', error: 'exit 1' })
    });

    const docm = buildZip({ 'word/vbaProject.bin': Buffer.from('not really a vba project') });
    const result = await inspector.inspect(docm, { fileName: 'invoice.docm' });

    assert.strictEqual(result.macro_analysis.status, 'FAILED');
    assert.match(result.macro_analysis.detail, /not a clean result/);
    assert.ok(codes(result).includes('MACRO_ANALYSIS_FAILED'));
});

test('olevba output is matched by shape, since the record is named after the container', () => {
    const inspector = new AttachmentInspector(toolsReporting({ available: false }));
    const inspection = { findings: [] };

    // olevba labels this record OLE, OpenXML or Text depending on what it opened,
    // so there is no single type value to match on. This is real output.
    const records = [
        { type: 'MetaInformation', script_name: 'olevba', version: '0.60.2' },
        {
            type: 'Text',
            file: 'sample.vba',
            macros: [{}],
            analysis: [
                { type: 'AutoExec', keyword: 'AutoOpen', description: 'Runs when the Word document is opened' },
                { type: 'Suspicious', keyword: 'Shell', description: 'May run an executable file or a system command' },
                { type: 'Suspicious', keyword: 'powershell', description: 'May run PowerShell commands' },
                { type: 'IOC', keyword: 'http://198.51.100.7/x', description: 'URL' }
            ]
        }
    ];

    const summary = inspector.summariseMacroFindings(inspection, records, { name: 'olevba', version: '0.60.2' });

    assert.strictEqual(summary.status, 'ANALYSED');
    assert.deepStrictEqual(summary.auto_execute_triggers, ['AutoOpen']);
    assert.ok(summary.suspicious_keywords.includes('powershell'));
    assert.ok(inspection.findings.some(f => f.code === 'MACRO_RUNS_AUTOMATICALLY'));
    assert.ok(inspection.findings.some(f => f.code === 'MACRO_NETWORK_INDICATORS'));
});

// ---------------------------------------------------------------------------
// Connection evidence
// ---------------------------------------------------------------------------

test('TShark field output becomes destinations, whether named by TLS or by DNS', () => {
    const evidence = new ConnectionEvidence();

    // Tab-separated, in the field order the module asks for.
    const output = [
        '1758441600.123\t203.0.113.7\t\t443\t\tlogin-verify.example.tk\t',
        '1758441500.000\t\t\t\t53\t\tmail.example.com',
        '',
        'malformed line with no fields'
    ].join('\n');

    const observations = evidence.parseFields(output);

    // Two: the blank line and the line carrying neither a host nor an address are
    // both dropped, because there is no destination in them to report.
    assert.strictEqual(observations.length, 2);
    assert.strictEqual(observations[0].host, 'login-verify.example.tk');
    assert.strictEqual(observations[0].kind, 'TLS_CONNECTION');
    assert.strictEqual(observations[0].port, 443);
    assert.strictEqual(observations[1].kind, 'DNS_QUERY');
});

test('a connection only counts when it happened after the email, and soon enough', () => {
    const evidence = new ConnectionEvidence();
    const receivedAt = '2026-09-21T10:00:00.000Z';

    const result = evidence.correlate([
        { at: '2026-09-21T10:04:00.000Z', host: 'login-verify.example.tk', address: '203.0.113.7', port: 443, protocol: 'TCP', kind: 'TLS_CONNECTION' },
        { at: '2026-09-21T09:30:00.000Z', host: 'login-verify.example.tk', address: null, port: 443, protocol: 'TCP', kind: 'TLS_CONNECTION' },
        { at: '2026-09-21T14:00:00.000Z', host: 'login-verify.example.tk', address: null, port: 443, protocol: 'TCP', kind: 'TLS_CONNECTION' }
    ], ['login-verify.example.tk'], { receivedAt });

    assert.strictEqual(result.attempts, 1, 'before the email and hours later are both somebody browsing');
    assert.strictEqual(result.matches[0].delay_seconds, 240);
});

test('a subdomain of a flagged host is the same destination', () => {
    const evidence = new ConnectionEvidence();

    const result = evidence.correlate(
        [{ at: '2026-09-21T10:01:00.000Z', host: 'secure.login-verify.example.tk', address: null, port: 443, protocol: 'TCP', kind: 'TLS_CONNECTION' }],
        ['login-verify.example.tk'],
        { receivedAt: '2026-09-21T10:00:00.000Z' }
    );

    assert.ok(result.matched);
    assert.strictEqual(result.matches[0].indicator, 'login-verify.example.tk');
});

test('a host that merely ends in similar text is not a match', () => {
    const evidence = new ConnectionEvidence();

    const result = evidence.correlate(
        [{ at: '2026-09-21T10:01:00.000Z', host: 'notexample.tk', address: null, port: 443, protocol: 'TCP', kind: 'TLS_CONNECTION' }],
        ['example.tk'],
        { receivedAt: '2026-09-21T10:00:00.000Z' }
    );

    assert.strictEqual(result.matched, false, 'matching must be on a label boundary, not on text');
});

test('finding nothing is never reported as evidence that nothing happened', () => {
    const evidence = new ConnectionEvidence();
    const result = evidence.correlate([], ['login-verify.example.tk'], { receivedAt: '2026-09-21T10:00:00.000Z' });

    assert.strictEqual(result.matched, false);
    assert.match(result.interpretation, /not evidence that none happened/i);
});

test('capture fields carry addressing only, never message content', () => {
    const { FIELDS } = require('../modules/connectionEvidence');

    // A capture taken for this purpose must not be able to become a recording of
    // somebody's correspondence.
    for (const field of FIELDS) {
        assert.doesNotMatch(field, /payload|data\.data|text|body|http\.file/i, `${field} would capture content`);
    }
});

test('when TShark is absent, the gap it leaves is stated in words', async () => {
    const evidence = new ConnectionEvidence(toolsReporting({
        available: false,
        reason: 'NOT_INSTALLED',
        detail: 'TShark was not found.',
        install_hint: 'Install Wireshark.',
        purpose: 'Reports whether this machine connected to a host an email pointed at.'
    }));

    const availability = await evidence.availability();
    assert.strictEqual(availability.available, false);
    assert.match(availability.caveat, /whether anybody followed it/);
});
