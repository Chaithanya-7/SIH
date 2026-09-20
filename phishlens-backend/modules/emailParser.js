const { simpleParser } = require('mailparser');

/**
 * Independent RFC 5322 / MIME parsing of the raw email, owned entirely by
 * PhishLens. This is the one place the raw message is structurally parsed;
 * every downstream module (auth analysis, forensics, NLP, IOC extraction,
 * attachments, the rule engine) consumes this shared result instead of each
 * re-parsing the raw string its own way. It has no dependency on an external
 * detection provider being configured or reachable.
 */
class EmailParser {
    async parse(rawEmailString) {
        const raw = rawEmailString || '';
        const parsed = await simpleParser(raw, { skipHtmlToText: false, skipImageLinks: true });

        const fromEntry = parsed.from?.value?.[0] || null;
        const replyToEntry = parsed.replyTo?.value?.[0] || null;
        const toAddresses = (parsed.to?.value || []).map(v => v.address).filter(Boolean);

        const authResultsHeader = parsed.headers.get('authentication-results');
        const authenticationResultsRaw = Array.isArray(authResultsHeader)
            ? authResultsHeader
            : (authResultsHeader ? [authResultsHeader] : []);

        const returnPathRaw = parsed.headers.get('return-path');
        const returnPath = typeof returnPathRaw === 'string' ? returnPathRaw.replace(/[<>]/g, '').trim() : null;

        return {
            from: {
                address: (fromEntry?.address || '').toLowerCase(),
                name: fromEntry?.name || ''
            },
            to: toAddresses,
            replyTo: replyToEntry?.address ? replyToEntry.address.toLowerCase() : null,
            returnPath: returnPath || null,
            subject: parsed.subject || '',
            date: parsed.date ? parsed.date.toISOString() : null,
            messageId: parsed.messageId || null,
            // Thread headers (RFC 5322 §3.6.4). Parsed all along and discarded
            // here, which meant nothing downstream could tell a genuine reply
            // from a message that merely claims to be one.
            inReplyTo: parsed.inReplyTo || null,
            references: Array.isArray(parsed.references)
                ? parsed.references
                : (parsed.references ? [parsed.references] : []),
            textBody: parsed.text || '',
            htmlBody: typeof parsed.html === 'string' ? parsed.html : '',
            authenticationResultsRaw,
            headers: parsed.headers,
            attachments: (parsed.attachments || []).map(a => ({
                filename: a.filename || 'unnamed-attachment',
                contentType: (a.contentType || 'application/octet-stream').toLowerCase(),
                size: a.size || (a.content ? a.content.length : 0),
                contentTransferEncoding: a.contentTransferEncoding || 'unknown',
                content: a.content || Buffer.alloc(0),
                related: !!a.related
            }))
        };
    }
}

module.exports = new EmailParser();
