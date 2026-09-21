const crypto = require('crypto');
const attachmentInspector = require('./attachmentInspector');

/**
 * Pulls attachments out of a message and has their contents inspected.
 *
 * This described attachments and never opened them, which made every attachment
 * look alike: the one carrying the attack and the one carrying the invoice have
 * the same name, size and MIME type, and differ only inside. The describing is
 * still here, and attachmentInspector now does the looking.
 *
 * Nothing is executed. See attachmentInspector for what reading the bytes does
 * and does not involve.
 */
class AttachmentAnalyzer {
    parseHeaders(headerBlock) {
        const headers = {};
        headerBlock.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/).forEach(line => {
            const separator = line.indexOf(':');
            if (separator > 0) headers[line.slice(0, separator).toLowerCase()] = line.slice(separator + 1).trim();
        });
        return headers;
    }

    filename(headers) {
        const disposition = headers['content-disposition'] || '';
        const contentType = headers['content-type'] || '';
        const match = /filename\*?=(?:UTF-8''|"|')?([^;"']+)/i.exec(disposition) || /name=(?:"|')?([^;"']+)/i.exec(contentType);
        return match ? decodeURIComponent(match[1].trim()).replace(/[\\/:*?"<>|]/g, '_').slice(0, 255) : 'unnamed-attachment';
    }

    extensionOf(fileName) {
        return (fileName.match(/\.([a-z0-9]{1,12})$/i)?.[1] || '').toLowerCase();
    }

    /** Fallback hand-rolled boundary parser, used only if parsedEmail (mailparser) was not supplied. */
    analyzeFromRawString(threatObject) {
        const raw = threatObject._raw_email_string || '';
        const topHeaders = this.parseHeaders(raw.split(/\r?\n\r?\n/, 1)[0] || '');
        const boundaryMatch = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(topHeaders['content-type'] || '');
        const attachments = [];

        if (!boundaryMatch) {
            threatObject.attachments = attachments;
            return threatObject;
        }

        const boundary = boundaryMatch[1] || boundaryMatch[2];
        const parts = raw.split(`--${boundary}`).slice(1, -1);
        for (const part of parts.slice(0, 20)) {
            const divider = part.search(/\r?\n\r?\n/);
            if (divider < 0) continue;
            const headers = this.parseHeaders(part.slice(0, divider));
            const disposition = headers['content-disposition'] || '';
            if (!/attachment/i.test(disposition) && !/filename=/i.test(disposition)) continue;

            const encodedBody = part.slice(divider).replace(/^\r?\n\r?\n/, '').trim();
            const isBase64 = /base64/i.test(headers['content-transfer-encoding'] || '');
            const bytes = isBase64 ? Buffer.from(encodedBody.replace(/\s/g, ''), 'base64') : Buffer.from(encodedBody, 'utf8');
            const fileName = this.filename(headers);
            attachments.push({
                file_name: fileName,
                extension: this.extensionOf(fileName) || null,
                mime_type: (headers['content-type'] || 'application/octet-stream').split(';')[0].trim().toLowerCase(),
                size_bytes: bytes.length,
                sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
                content_transfer_encoding: headers['content-transfer-encoding'] || 'unknown',
                analysis_status: 'METADATA_ONLY',
                limitation: 'The attachment was not opened or executed; only MIME metadata and a content hash were analyzed.'
            });
        }

        threatObject.attachments = attachments;
        return threatObject;
    }

    async analyze(threatObject, parsedEmail) {
        if (!parsedEmail) {
            return this.analyzeFromRawString(threatObject);
        }

        const attachments = [];

        // One at a time. Inspecting a document that carries macros starts a
        // separate process, and a message with a dozen attachments should not
        // start a dozen of them at once.
        for (const a of (parsedEmail.attachments || [])) {
            const fileName = (a.filename || 'unnamed-attachment').replace(/[\/:*?"<>|]/g, '_').slice(0, 255);
            attachments.push(await this.describe(a.content, {
                fileName,
                mimeType: a.contentType,
                sizeBytes: a.size || a.content.length,
                encoding: a.contentTransferEncoding
            }));
        }

        threatObject.attachments = attachments;
        return threatObject;
    }

    /** One attachment, described and inspected, in the shape the rest of the pipeline reads. */
    async describe(content, { fileName, mimeType, sizeBytes, encoding }) {
        const inspection = await attachmentInspector.inspect(content, {
            fileName,
            declaredMimeType: mimeType || ''
        });

        return {
            file_name: fileName,
            extension: this.extensionOf(fileName) || null,
            mime_type: mimeType,
            size_bytes: sizeBytes,
            sha256: inspection.sha256,
            content_transfer_encoding: encoding || 'unknown',
            analysis_status: 'CONTENT_INSPECTED',
            // What the bytes are, which is not always what the message called them.
            format: inspection.format,
            findings: inspection.findings,
            // Null where the document carries no macros; where it does, this says
            // either what the code contained or why it could not be read.
            macro_analysis: inspection.macro_analysis,
            archive: inspection.archive || null,
            embedded_links: inspection.pdf_links || null,
            limitation: 'The attachment was read as bytes and never opened or executed. Findings describe its structure and contents, not what it would do if run.'
        };
    }
}

module.exports = new AttachmentAnalyzer();
