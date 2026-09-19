const crypto = require('crypto');

/** Safe, metadata-only MIME attachment analysis. Untrusted bytes are never executed or written to disk. */
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

    analyze(threatObject, parsedEmail) {
        if (!parsedEmail) {
            return this.analyzeFromRawString(threatObject);
        }

        threatObject.attachments = (parsedEmail.attachments || []).map(a => {
            const fileName = (a.filename || 'unnamed-attachment').replace(/[\\/:*?"<>|]/g, '_').slice(0, 255);
            return {
                file_name: fileName,
                extension: this.extensionOf(fileName) || null,
                mime_type: a.contentType,
                size_bytes: a.size || a.content.length,
                sha256: crypto.createHash('sha256').update(a.content).digest('hex'),
                content_transfer_encoding: a.contentTransferEncoding,
                analysis_status: 'METADATA_ONLY',
                limitation: 'The attachment was not opened or executed; only MIME metadata and a content hash were analyzed.'
            };
        });

        return threatObject;
    }
}

module.exports = new AttachmentAnalyzer();
