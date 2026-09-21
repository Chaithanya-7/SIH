const crypto = require('crypto');
const zlib = require('zlib');
const yaraRules = require('./yaraRules');

/**
 * Looks inside an attachment, rather than only at its name and size.
 *
 * Until now attachments were hashed and described - name, type, length, SHA-256
 * - and never opened. That is safe and nearly useless: the file that carries the
 * attack looks exactly like the file that does not, because everything that
 * distinguishes them is inside.
 *
 * ## Nothing needs to be installed for this to work
 *
 * The container formats that matter can be read with what Node already has. An
 * Office document with macros is a ZIP holding vbaProject.bin, and zlib is
 * built in, so the definitive answer to "does this document carry code" needs no
 * dependency at all. Where oletools is installed the answer deepens from whether
 * there is code to what the code says, but the first answer never depends on it.
 *
 * ## What is deliberately not done
 *
 * Nothing here is executed or rendered. Every format is walked as bytes, and
 * where a finding relies on decompression the decompressed size is capped,
 * because a small archive can describe a very large one.
 *
 * There is one exception to staying in memory: olevba takes a path rather than a
 * stream, so a document that carries macros is written to a temporary directory
 * for as long as that call takes. It is written under a generated name, never
 * the sender's, and removed in a finally. See readMacros.
 */

/** A file that claims to be a document is not read past this. Attachments this large are already remarkable. */
const MAX_INSPECT_BYTES = 25 * 1024 * 1024;

/** A single entry inside an archive, after inflation. Caps what a zip bomb can spend. */
const MAX_ENTRY_BYTES = 4 * 1024 * 1024;

/** Enough entries to characterise an archive without walking a hostile one forever. */
const MAX_ENTRIES = 512;

/**
 * What the first bytes say the file is, regardless of what it is called.
 *
 * The claimed type comes from the sender. The signature does not, which is why
 * disagreement between them is worth reporting on its own.
 */
const SIGNATURES = [
    { magic: [0x50, 0x4b, 0x03, 0x04], format: 'ZIP', note: 'A ZIP container. Office documents, archives and installers all take this shape.' },
    { magic: [0x50, 0x4b, 0x05, 0x06], format: 'ZIP_EMPTY', note: 'An empty ZIP container.' },
    { magic: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], format: 'OLE2', note: 'The older Office compound format, used by .doc, .xls and .ppt.' },
    { magic: [0x25, 0x50, 0x44, 0x46], format: 'PDF', note: 'A PDF document.' },
    { magic: [0x4d, 0x5a], format: 'PE_EXECUTABLE', note: 'A Windows program.' },
    { magic: [0x7f, 0x45, 0x4c, 0x46], format: 'ELF_EXECUTABLE', note: 'A Linux program.' },
    { magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], format: 'RAR', note: 'A RAR archive.' },
    { magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], format: 'SEVEN_ZIP', note: 'A 7-Zip archive.' },
    { magic: [0x1f, 0x8b], format: 'GZIP', note: 'A gzip stream.' },
    { magic: [0x49, 0x54, 0x53, 0x46], format: 'CHM', note: 'A compiled HTML help file, which can run code when opened.' }
];

/** Extensions Windows will run, or will treat as instructions, rather than open as data. */
const EXECUTABLE_EXTENSIONS = new Set([
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'msp', 'cpl', 'dll', 'jar',
    'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'psm1', 'reg', 'scf',
    'lnk', 'url', 'chm', 'inf', 'application', 'gadget', 'msc'
]);

/** Containers that carry a file across the boundary where the operating system would have marked it as downloaded. */
const MARK_OF_THE_WEB_CARRIERS = new Set(['iso', 'img', 'vhd', 'vhdx', 'cab']);

/** What the extension says the file should be, for comparison against what it is. */
const EXPECTED_FORMAT = {
    docx: 'ZIP', docm: 'ZIP', dotm: 'ZIP', xlsx: 'ZIP', xlsm: 'ZIP', xltm: 'ZIP',
    pptx: 'ZIP', pptm: 'ZIP', odt: 'ZIP', ods: 'ZIP', zip: 'ZIP', jar: 'ZIP',
    doc: 'OLE2', xls: 'OLE2', ppt: 'OLE2', msi: 'OLE2',
    pdf: 'PDF', exe: 'PE_EXECUTABLE', dll: 'PE_EXECUTABLE', scr: 'PE_EXECUTABLE',
    rar: 'RAR', '7z': 'SEVEN_ZIP', gz: 'GZIP', chm: 'CHM',
    html: 'HTML', htm: 'HTML', svg: 'SVG', rtf: 'RTF', xml: 'XML'
};

/**
 * PDF constructs that cause something to happen on open, rather than describe a page.
 *
 * A PDF is a document format with an execution story attached, and these are the
 * parts of it an attacker uses. Their presence is not proof of anything - a
 * legitimate form uses JavaScript - so each is reported as what it is.
 */
const PDF_ACTIVE_CONTENT = [
    { code: 'PDF_OPEN_ACTION', tokens: ['/OpenAction'], meaning: 'Something is set to run as soon as the document opens.', weight: 'HIGH' },
    { code: 'PDF_EVENT_ACTION', tokens: ['/AA'], meaning: 'An action is attached to a page or field event.', weight: 'MEDIUM' },
    // One concept, two spellings: /JS is the abbreviated form and both appear in
    // the same object. Keyed by concept so the same fact is not reported twice.
    { code: 'PDF_JAVASCRIPT', tokens: ['/JavaScript', '/JS'], meaning: 'The document carries JavaScript.', weight: 'MEDIUM' },
    { code: 'PDF_LAUNCH', tokens: ['/Launch'], meaning: 'The document asks to start an external program.', weight: 'HIGH' },
    { code: 'PDF_EMBEDDED_FILE', tokens: ['/EmbeddedFile'], meaning: 'Another file is carried inside this one.', weight: 'MEDIUM' },
    { code: 'PDF_SUBMIT_FORM', tokens: ['/SubmitForm'], meaning: 'The document can send data to a remote address.', weight: 'MEDIUM' },
    { code: 'PDF_RICH_MEDIA', tokens: ['/RichMedia'], meaning: 'The document embeds media that runs a player.', weight: 'MEDIUM' }
];

class AttachmentInspector {
    constructor(securityTools = require('./securityTools'), rules = yaraRules) {
        this.securityTools = securityTools;
        this.rules = rules;
    }

    /**
     * Everything that can be learned about one attachment's bytes.
     *
     * Returns findings, not a verdict. Scoring belongs to the detection pipeline,
     * which can see the message these bytes arrived in.
     */
    async inspect(buffer, { fileName = '', declaredMimeType = '' } = {}) {
        const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
        const extension = (fileName.match(/\.([a-z0-9]{1,12})$/i) || [])[1]?.toLowerCase() || null;

        const inspection = {
            inspected_bytes: Math.min(bytes.length, MAX_INSPECT_BYTES),
            truncated: bytes.length > MAX_INSPECT_BYTES,
            sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
            format: null,
            findings: [],
            // Filled by whichever deeper tool was available, or left saying why not.
            macro_analysis: null
        };

        if (bytes.length === 0) {
            inspection.format = { detected: 'EMPTY', note: 'The attachment carried no content.' };
            return inspection;
        }

        const readable = bytes.subarray(0, MAX_INSPECT_BYTES);

        inspection.format = this.identify(readable);
        this.checkName(fileName, extension, inspection);
        this.checkFormatAgreement(extension, declaredMimeType, inspection);

        if (inspection.format.detected === 'ZIP') {
            this.inspectZip(readable, inspection);
        } else if (inspection.format.detected === 'OLE2') {
            this.inspectOle2(readable, inspection);
        } else if (inspection.format.detected === 'PDF') {
            this.inspectPdf(readable, inspection);
        }

        inspection.macro_analysis = await this.deepMacroAnalysis(inspection, readable);

        // The detection rules run over every attachment, whatever its format.
        // They cover what walking a container cannot: an HTML file that is a
        // sign-in page, a shortcut that runs a shell, a page that asks the
        // person to paste a command themselves.
        const ruleScan = await this.rules.scan(readable);
        inspection.rule_matching = {
            status: ruleScan.status,
            engine: ruleScan.engine || null,
            engine_note: ruleScan.engine_note || ruleScan.detail || null,
            rules_evaluated: ruleScan.rules_evaluated || 0,
            rule_errors: ruleScan.rule_errors || []
        };
        inspection.findings.push(...(ruleScan.findings || []));

        return inspection;
    }

    /** What the bytes actually are. */
    identify(bytes) {
        for (const signature of SIGNATURES) {
            if (bytes.length < signature.magic.length) continue;
            if (signature.magic.every((byte, index) => bytes[index] === byte)) {
                return { detected: signature.format, note: signature.note };
            }
        }
        // Text formats carry no signature, so they are sniffed from the opening
        // bytes instead. Without this an HTML attachment - which is a whole
        // phishing page, and one of the commoner ones - was reported as
        // UNRECOGNISED, which reads in a report as though nothing at all could
        // be determined about it.
        const opening = bytes.subarray(0, 1024).toString('latin1').trimStart();

        if (/^(<\?xml[^>]*\?>\s*)?<svg[\s>]/i.test(opening)) {
            return { detected: 'SVG', note: 'A vector image. A browser treats one as a document and will run script inside it.' };
        }
        if (/^(<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>])/i.test(opening)) {
            return { detected: 'HTML', note: 'A web page. An HTML attachment opens in the browser as a page in its own right.' };
        }
        if (/^\{\rtf/i.test(opening)) {
            return { detected: 'RTF', note: 'A rich text document.' };
        }
        if (/^<\?xml/i.test(opening)) {
            return { detected: 'XML', note: 'An XML document.' };
        }

        return { detected: 'UNRECOGNISED', note: 'The leading bytes match no format this inspector knows.' };
    }

    /**
     * The filename itself, which is chosen by the sender and is sometimes the attack.
     */
    checkName(fileName, extension, inspection) {
        // U+202E reverses how the rest of the name is drawn, so gpj.exe renders as
        // exe.jpg. The characters are unchanged; only the reading is reversed.
        if (/[‪-‮⁦-⁩]/.test(fileName)) {
            inspection.findings.push({
                code: 'BIDI_FILENAME',
                severity: 'HIGH',
                summary: 'The filename contains characters that reverse how it is displayed.',
                detail: 'A name written this way shows one extension and carries another. There is no ordinary reason for an attachment to use these characters.'
            });
        }

        // A double extension works because the operating system hides the last one
        // by default, so invoice.pdf.exe is shown as invoice.pdf.
        const doubleExtension = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|csv|zip)\.([a-z0-9]{1,5})$/i.exec(fileName);
        if (doubleExtension && EXECUTABLE_EXTENSIONS.has(doubleExtension[2].toLowerCase())) {
            inspection.findings.push({
                code: 'DOUBLE_EXTENSION',
                severity: 'HIGH',
                summary: `The file is named to look like a .${doubleExtension[1]} but ends in .${doubleExtension[2]}.`,
                detail: 'Windows hides known extensions by default, so this is displayed under the earlier one.'
            });
        }

        if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
            inspection.findings.push({
                code: 'EXECUTABLE_ATTACHMENT',
                severity: 'HIGH',
                summary: `A .${extension} attachment is run rather than opened.`,
                detail: 'This extension is treated by the operating system as something to execute or as instructions to follow.'
            });
        }

        if (extension && MARK_OF_THE_WEB_CARRIERS.has(extension)) {
            inspection.findings.push({
                code: 'CONTAINER_BYPASS',
                severity: 'MEDIUM',
                summary: `A .${extension} carries its contents past the warning an emailed file would normally get.`,
                detail: 'Files taken out of this kind of container do not inherit the marking that tells Windows they came from the internet, so the usual warning does not appear.'
            });
        }

        // A name long enough to push its own ending off the edge of a dialog.
        if (fileName.length > 120) {
            inspection.findings.push({
                code: 'OVERLONG_FILENAME',
                severity: 'LOW',
                summary: 'The filename is long enough that its ending may not be visible where it is displayed.',
                detail: `The name is ${fileName.length} characters.`
            });
        }
    }

    /** Does the file agree with what it is called, and with what the message said it was? */
    checkFormatAgreement(extension, declaredMimeType, inspection) {
        const detected = inspection.format.detected;
        const expected = extension ? EXPECTED_FORMAT[extension] : null;

        if (expected && detected !== 'UNRECOGNISED' && expected !== detected) {
            inspection.findings.push({
                code: 'FORMAT_MISMATCH',
                severity: detected.includes('EXECUTABLE') ? 'HIGH' : 'MEDIUM',
                summary: `The file is named .${extension} but its contents are ${detected}.`,
                detail: `A .${extension} should begin as ${expected}. The extension is chosen by the sender; the contents are the file itself.`
            });
        }

        // A program arriving under a document's MIME type is not a mislabelling.
        if (detected === 'PE_EXECUTABLE' && /^(application\/pdf|image\/|text\/)/i.test(declaredMimeType || '')) {
            inspection.findings.push({
                code: 'EXECUTABLE_DECLARED_AS_DOCUMENT',
                severity: 'HIGH',
                summary: `The message declared this as ${declaredMimeType}, but it is a Windows program.`,
                detail: 'The declared type is part of the message and is written by the sender.'
            });
        }
    }

    /**
     * Walks a ZIP through its central directory.
     *
     * This is where an Office document keeps its macros, and also where a modern
     * Office attack keeps no macros at all: a document can be a few harmless
     * parts plus a reference to a template held elsewhere, which is fetched when
     * the file opens.
     */
    inspectZip(bytes, inspection) {
        const entries = this.readZipEntries(bytes);
        if (!entries) {
            inspection.findings.push({
                code: 'ZIP_UNREADABLE',
                severity: 'LOW',
                summary: 'The archive structure could not be read.',
                detail: 'The file begins as a ZIP but its directory could not be walked. It may be damaged or deliberately malformed.'
            });
            return;
        }

        inspection.archive = { entry_count: entries.length, entries: entries.slice(0, 40).map(e => e.name) };

        const macroEntry = entries.find(e => /(^|\/)vbaProject\.bin$/i.test(e.name));
        if (macroEntry) {
            inspection.findings.push({
                code: 'OFFICE_MACROS_PRESENT',
                severity: 'HIGH',
                summary: 'The document contains a macro project.',
                detail: `Macro code is stored at ${macroEntry.name}. Opening the document offers to run it.`
            });
        }

        // Office keeps external references in .rels parts. A template fetched over
        // the network at open time is the shape of remote template injection, and
        // it leaves the document itself carrying nothing detectable.
        for (const entry of entries.filter(e => /\.rels$/i.test(e.name))) {
            const content = this.readZipEntry(bytes, entry);
            if (!content) continue;

            const text = content.toString('utf8');
            const externals = [...text.matchAll(/Target="(https?:\/\/[^"]+)"[^>]*TargetMode="External"/gi)]
                .concat([...text.matchAll(/TargetMode="External"[^>]*Target="(https?:\/\/[^"]+)"/gi)]);

            for (const match of externals.slice(0, 10)) {
                const isTemplate = /attachedTemplate|template/i.test(text) || /settings\.xml\.rels$/i.test(entry.name);
                inspection.findings.push({
                    code: isTemplate ? 'REMOTE_TEMPLATE_REFERENCE' : 'EXTERNAL_REFERENCE',
                    severity: isTemplate ? 'HIGH' : 'MEDIUM',
                    summary: isTemplate
                        ? 'The document loads a template from a remote address when it opens.'
                        : 'The document references a remote address.',
                    detail: `${entry.name} points to ${match[1]}. A document that fetches part of itself on open carries nothing suspicious until it does.`,
                    url: match[1]
                });
            }
        }

        // A document that carries a program is carrying a program whatever it is called.
        const nested = entries.filter(e => EXECUTABLE_EXTENSIONS.has((e.name.match(/\.([a-z0-9]{1,5})$/i) || [])[1]?.toLowerCase() || ''));
        if (nested.length) {
            inspection.findings.push({
                code: 'EXECUTABLE_INSIDE_ARCHIVE',
                severity: 'HIGH',
                summary: `The archive contains ${nested.length} file${nested.length === 1 ? '' : 's'} that would be run rather than opened.`,
                detail: nested.slice(0, 6).map(e => e.name).join(', ')
            });
        }

        // A large declared size behind a small archive is the shape of a decompression bomb.
        const declared = entries.reduce((sum, e) => sum + e.uncompressedSize, 0);
        if (declared > 0 && bytes.length > 0 && declared / bytes.length > 200 && declared > 50 * 1024 * 1024) {
            inspection.findings.push({
                code: 'DECOMPRESSION_RATIO',
                severity: 'MEDIUM',
                summary: 'The archive expands to far more than its own size.',
                detail: `${this.readableSize(bytes.length)} of archive declares ${this.readableSize(declared)} of contents.`
            });
        }
    }

    /**
     * Reads a ZIP's central directory.
     *
     * The directory is at the end, located through a record whose own position is
     * not fixed, so it is found by scanning backwards for its signature.
     */
    readZipEntries(bytes) {
        const EOCD = 0x06054b50;
        const CENTRAL = 0x02014b50;

        // The comment that follows this record can be up to 64KB.
        let eocd = -1;
        const earliest = Math.max(0, bytes.length - 66 * 1024);
        for (let i = bytes.length - 22; i >= earliest; i--) {
            if (bytes.readUInt32LE(i) === EOCD) { eocd = i; break; }
        }
        if (eocd < 0) return null;

        try {
            const count = bytes.readUInt16LE(eocd + 10);
            let offset = bytes.readUInt32LE(eocd + 16);
            const entries = [];

            for (let i = 0; i < Math.min(count, MAX_ENTRIES); i++) {
                if (offset + 46 > bytes.length || bytes.readUInt32LE(offset) !== CENTRAL) break;

                const nameLength = bytes.readUInt16LE(offset + 28);
                const extraLength = bytes.readUInt16LE(offset + 30);
                const commentLength = bytes.readUInt16LE(offset + 32);

                entries.push({
                    name: bytes.subarray(offset + 46, offset + 46 + nameLength).toString('utf8'),
                    compressionMethod: bytes.readUInt16LE(offset + 10),
                    compressedSize: bytes.readUInt32LE(offset + 20),
                    uncompressedSize: bytes.readUInt32LE(offset + 24),
                    localHeaderOffset: bytes.readUInt32LE(offset + 42)
                });

                offset += 46 + nameLength + extraLength + commentLength;
            }

            return entries;
        } catch (e) {
            return null;
        }
    }

    /** One entry's bytes, inflated, capped, and never thrown from. */
    readZipEntry(bytes, entry) {
        const LOCAL = 0x04034b50;
        try {
            if (entry.uncompressedSize > MAX_ENTRY_BYTES) return null;

            const start = entry.localHeaderOffset;
            if (start + 30 > bytes.length || bytes.readUInt32LE(start) !== LOCAL) return null;

            // The local header carries its own lengths, which need not match the
            // central directory's. Trusting the wrong one lands mid-content.
            const nameLength = bytes.readUInt16LE(start + 26);
            const extraLength = bytes.readUInt16LE(start + 28);
            const dataStart = start + 30 + nameLength + extraLength;
            const data = bytes.subarray(dataStart, dataStart + entry.compressedSize);

            if (entry.compressionMethod === 0) return data.subarray(0, MAX_ENTRY_BYTES);
            if (entry.compressionMethod === 8) return zlib.inflateRawSync(data, { maxOutputLength: MAX_ENTRY_BYTES });
            return null;
        } catch (e) {
            return null;
        }
    }

    /**
     * The older Office format, which is a filesystem in a file.
     *
     * Its directory is a linked structure, and walking it properly is what
     * oletools exists for. What can be said without that is whether the streams
     * a macro project needs are named anywhere in the file, which is enough to
     * separate a document that carries code from one that does not.
     */
    inspectOle2(bytes, inspection) {
        // Stream names are stored as UTF-16LE, so they are searched for that way.
        const haystack = bytes.toString('latin1');
        const markers = [
            { name: 'VBA', utf16: 'V\0B\0A\0' },
            { name: 'Macros', utf16: 'M\0a\0c\0r\0o\0s\0' },
            { name: '_VBA_PROJECT', utf16: '_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0' }
        ];

        const found = markers.filter(m => haystack.includes(m.utf16)).map(m => m.name);
        if (found.length) {
            inspection.findings.push({
                code: 'OFFICE_MACROS_PRESENT',
                severity: 'HIGH',
                summary: 'The document contains a macro project.',
                detail: `Macro storage was found in the document (${found.join(', ')}). Opening it offers to run the code.`
            });
        }

        // Excel 4.0 macro sheets predate VBA, are still executed by Excel, and are
        // not what most macro checks look at.
        if (haystack.includes('E\0x\0c\0e\0l\0 \0 \0 \0 \0 \0 \0 \0 \0 \0 \0 \0 \0 \0') || /\x85\x00.{0,4}(Macro|Sheet)/s.test(haystack)) {
            inspection.findings.push({
                code: 'LEGACY_MACRO_SHEET_POSSIBLE',
                severity: 'MEDIUM',
                summary: 'The workbook may contain an Excel 4.0 macro sheet.',
                detail: 'This older macro format still runs and is often missed by checks that look only for the modern one.'
            });
        }
    }

    /** A PDF's active content, found by scanning rather than by parsing its object graph. */
    inspectPdf(bytes, inspection) {
        const text = bytes.toString('latin1');

        for (const marker of PDF_ACTIVE_CONTENT) {
            const seen = marker.tokens.filter(token => text.includes(token));
            if (!seen.length) continue;
            inspection.findings.push({
                code: marker.code,
                severity: marker.weight,
                summary: marker.meaning,
                detail: `The document uses ${seen.join(' and ')}. This appears in legitimate documents too, so it is reported rather than judged.`
            });
        }

        // The addresses a PDF will send somebody to, which is most of what a
        // phishing PDF is for: a page of pretext wrapped around one link.
        const urls = [...new Set([...text.matchAll(/\/URI\s*\(\s*(https?:\/\/[^)]{1,300})\)/gi)].map(m => m[1].trim()))];
        if (urls.length) {
            inspection.pdf_links = urls.slice(0, 25);
            inspection.findings.push({
                code: 'PDF_CONTAINS_LINKS',
                severity: 'LOW',
                summary: `The document links to ${urls.length} address${urls.length === 1 ? '' : 'es'}.`,
                detail: 'These are passed to link analysis with the rest of the message.',
                urls: urls.slice(0, 25)
            });
        }
    }

    /**
     * What the macro code says, where something is installed that can read it.
     *
     * Absent that, this reports its own absence. A caller must be able to tell
     * "the macros were read and were unremarkable" from "nothing here can read
     * macros", and those are the same sentence if this returns null for both.
     */
    async deepMacroAnalysis(inspection, bytes) {
        const carriesMacros = inspection.findings.some(f => f.code === 'OFFICE_MACROS_PRESENT');
        if (!carriesMacros) return null;

        const tool = await this.securityTools.detect('olevba');
        if (!tool.available) {
            return {
                status: 'UNAVAILABLE',
                reason: tool.reason,
                // Phrased as a limit on the finding, never as a reassurance.
                detail: `This document carries macro code, and it was not read. ${tool.detail}`,
                remedy: tool.install_hint,
                what_would_be_added: tool.purpose
            };
        }

        return this.readMacros(inspection, bytes, tool);
    }

    /**
     * Hands the bytes to olevba and turns what comes back into findings.
     *
     * The file has to exist on disk for this, which is the one place untrusted
     * bytes are written down. They are written under a name this code chooses,
     * into a directory it creates, and removed whatever happens next. The
     * sender's filename is not reused: it is an attacker-controlled string, and
     * the last thing to do with one of those is put it in a path.
     */
    async readMacros(inspection, bytes, tool) {
        const fs = require('fs');
        const os = require('os');
        const path = require('path');

        // Chosen from what the bytes are, not from what they are called.
        const extension = inspection.format.detected === 'OLE2' ? 'doc' : 'docm';
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phishlens-macro-'));
        const scratchFile = path.join(directory, `${crypto.randomBytes(8).toString('hex')}.${extension}`);

        try {
            fs.writeFileSync(scratchFile, bytes, { mode: 0o600 });

            const probe = await this.securityTools.run(
                tool.invocation.command,
                [...tool.invocation.prefix, '--json', scratchFile],
                { timeout: 30000 }
            );

            const records = this.parseOlevbaJson(probe.output);
            if (!records) {
                // olevba fell over. A document that breaks the parser is a finding
                // in its own right - malformed structure is a way of not being
                // read - and it is emphatically not a clean result.
                inspection.findings.push({
                    code: 'MACRO_ANALYSIS_FAILED',
                    severity: 'MEDIUM',
                    summary: 'The macro code is present but could not be parsed.',
                    detail: 'The document carries a macro project that the reader could not open. Malformed structure defeats analysis, which is sometimes the point of it.'
                });
                return {
                    status: 'FAILED',
                    tool: tool.name,
                    version: tool.version,
                    detail: 'The document carries macros and the reader could not parse them. This is not a clean result.'
                };
            }

            return this.summariseMacroFindings(inspection, records, tool);
        } catch (e) {
            return {
                status: 'FAILED',
                tool: tool.name,
                version: tool.version,
                detail: `The macros were not read: ${e.message}. This is not a clean result.`
            };
        } finally {
            // Whatever happened, the untrusted bytes do not stay on disk.
            fs.rmSync(directory, { recursive: true, force: true });
        }
    }

    /**
     * olevba prints warnings from its own dependencies alongside its JSON, so the
     * document is found rather than assumed to start at the first character.
     */
    parseOlevbaJson(output) {
        const start = output.indexOf('[');
        const end = output.lastIndexOf(']');
        if (start < 0 || end <= start) return null;

        try {
            const parsed = JSON.parse(output.slice(start, end + 1));
            return Array.isArray(parsed) ? parsed : null;
        } catch (e) {
            return null;
        }
    }

    /** Turns olevba's analysis entries into the same shape as every other finding. */
    summariseMacroFindings(inspection, records, tool) {
        // Found by shape rather than by label. olevba names this record after the
        // container it opened - Text, OLE, OpenXML - so there is no one type value
        // to match, and matching a guessed one silently finds nothing and reports
        // the document as unremarkable. Carrying an analysis array is the property
        // actually being looked for, and several records can carry one when a
        // container holds more than one file.
        const analysed = records.filter(r => Array.isArray(r.analysis));
        const entries = analysed.flatMap(r => r.analysis);

        const errors = records.filter(r => r.type === 'msg' && r.level === 'ERROR');
        if (errors.length && !entries.length) {
            inspection.findings.push({
                code: 'MACRO_ANALYSIS_FAILED',
                severity: 'MEDIUM',
                summary: 'The macro code is present but could not be parsed.',
                detail: String(errors[0].msg || '').split('\n')[0]
            });
            return {
                status: 'FAILED',
                tool: tool.name,
                version: tool.version,
                detail: 'The document carries macros and the reader could not parse them. This is not a clean result.'
            };
        }

        // olevba's own categories, kept rather than flattened. "Runs by itself"
        // and "can reach the network" are different facts about a document and a
        // single score would lose which one was true.
        const grouped = {
            auto_executes: entries.filter(e => e.type === 'AutoExec'),
            suspicious: entries.filter(e => e.type === 'Suspicious'),
            indicators: entries.filter(e => e.type === 'IOC'),
            obfuscation: entries.filter(e => /Base64|Hex|Dridex|obfuscat/i.test(e.type || ''))
        };

        if (grouped.auto_executes.length) {
            inspection.findings.push({
                code: 'MACRO_RUNS_AUTOMATICALLY',
                severity: 'HIGH',
                summary: 'The macro is set to run on its own when the document is opened.',
                detail: grouped.auto_executes.map(e => `${e.keyword}: ${e.description}`).join('; '),
                triggers: grouped.auto_executes.map(e => e.keyword)
            });
        }

        if (grouped.suspicious.length) {
            inspection.findings.push({
                code: 'MACRO_CAPABILITIES',
                severity: 'HIGH',
                summary: `The macro code uses ${grouped.suspicious.length} capabilit${grouped.suspicious.length === 1 ? "y" : "ies"} that do not belong in a document.`,
                detail: grouped.suspicious.slice(0, 12).map(e => `${e.keyword} (${e.description})`).join('; '),
                keywords: grouped.suspicious.map(e => e.keyword)
            });
        }

        if (grouped.obfuscation.length) {
            inspection.findings.push({
                code: 'MACRO_OBFUSCATED',
                severity: 'HIGH',
                summary: 'The macro code is written to be hard to read.',
                detail: 'Encoded or hidden strings were found in the code. Legitimate document macros have no reason to conceal what they contain.'
            });
        }

        if (grouped.indicators.length) {
            inspection.findings.push({
                code: 'MACRO_NETWORK_INDICATORS',
                severity: 'HIGH',
                summary: 'The macro code contains addresses it would contact.',
                detail: grouped.indicators.slice(0, 10).map(e => e.keyword).join(', '),
                indicators: grouped.indicators.map(e => e.keyword)
            });
        }

        return {
            status: 'ANALYSED',
            tool: tool.name,
            version: tool.version,
            macro_count: analysed.reduce((total, r) => total + (r.macros || []).length, 0),
            auto_execute_triggers: grouped.auto_executes.map(e => e.keyword),
            suspicious_keywords: grouped.suspicious.map(e => e.keyword),
            network_indicators: grouped.indicators.map(e => e.keyword),
            // An unremarkable read is worth stating plainly, because it is the one
            // case where silence would have been accurate but unconvincing.
            detail: entries.length
                ? `The macro code was read. ${entries.length} noteworthy construct${entries.length === 1 ? '' : 's'} found.`
                : 'The macro code was read and contained nothing noteworthy.'
        };
    }

    readableSize(bytes) {
        if (bytes < 1024) return `${bytes} bytes`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
}

module.exports = new AttachmentInspector();
module.exports.AttachmentInspector = AttachmentInspector;
module.exports.EXECUTABLE_EXTENSIONS = EXECUTABLE_EXTENSIONS;
