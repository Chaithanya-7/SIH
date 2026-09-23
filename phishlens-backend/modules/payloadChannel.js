/**
 * Where the actionable payload of a message actually lives.
 *
 * Every other detector in PhishLens assumes the thing it should look at is
 * present: the link analyser reads links, the attachment inspector reads
 * attachments, the language analysis reads text. Two families of modern
 * phishing are built precisely so that none of those have anything to read.
 *
 * ## 1. The payload is a phone number
 *
 * Telephone-oriented attack delivery. The email contains no link and no
 * attachment - the entire payload is a number to call, usually attached to a
 * fake invoice, subscription renewal or fraud alert. The victim calls, and the
 * rest of the attack happens over the phone: remote-access software, a
 * "refund" that needs their banking session, a credential read aloud.
 *
 * It defeats a mail gateway completely, and not by accident. There is nothing
 * to detonate, no URL to reputation-check, no file to scan. Proofpoint and
 * Abnormal both report it passing SPF and DMARC routinely, because it is often
 * sent from a real account on a real provider. A filter looking for a malicious
 * payload finds no payload at all and concludes the message is fine.
 *
 * What is detectable is the *shape*: a message whose only call to action is a
 * telephone number is unusual. Legitimate mail that gives you a number almost
 * always gives you a link as well, or is a reply within a conversation, or
 * comes from a sender the recipient has heard from before. This module reports
 * the shape; the rule engine decides what it means alongside the language
 * signals and the sender history.
 *
 * ### Why the number alone is never the signal
 *
 * Signatures contain phone numbers. Support footers contain phone numbers.
 * Scoring a message for carrying one would flag a large share of ordinary
 * business mail. So a number is only recorded when it sits near language that
 * asks the reader to ring it, and even then it is a fact, not a finding.
 *
 * ## 2. The payload is a picture
 *
 * The body is one image - usually a single linked image spanning the whole
 * message - with little or no real text. The reader sees a perfectly ordinary
 * invoice or security notice; every text-based check sees an almost empty
 * message and scores it at zero.
 *
 * This is the most common body-obfuscation technique measured in the
 * literature, and it is measured as significantly reducing antispam scores
 * (arXiv 2506.20228, "Measuring Modern Phishing Tactics", 47.0% prevalence).
 * PhishLens is exactly as vulnerable to it as any other text-reading analyser,
 * and was scoring such messages near zero before this module existed.
 *
 * ### What this deliberately does not do
 *
 * It does not read the image. Optical character recognition would mean a new
 * dependency, minutes of CPU per message, and a new class of wrong answer. It
 * is not needed: the *ratio* is the signal. A message whose rendered body is
 * one large image, carrying a link, with almost no text to explain itself, is
 * structurally anomalous whatever the picture says. That costs nothing to
 * measure and cannot be defeated by changing the words in the image.
 *
 * QR codes inside those images are already decoded elsewhere (qrAnalyzer), and
 * that stays the right place for it.
 */

/**
 * Words that turn a number in the text into an instruction to ring it.
 *
 * Deliberately about the act of calling rather than about urgency or money -
 * those are the language analyser's job, and duplicating them here would count
 * one fact twice in two different evidence families.
 */
const CALL_INTENT_TERMS = [
    'call', 'calling', 'phone', 'telephone', 'dial', 'contact us', 'contact our',
    'reach us', 'reach out', 'speak to', 'speak with', 'talk to',
    'helpline', 'help line', 'hotline', 'toll free', 'toll-free',
    'customer care', 'customer service', 'customer support', 'support team',
    'billing department', 'cancel', 'cancellation', 'to cancel',
    'representative', 'agent', 'helpdesk', 'help desk'
];

/** How far either side of a number the intent word may sit, in characters. */
const INTENT_WINDOW = 160;

/**
 * Shapes that count as a telephone number.
 *
 * Kept tight on purpose. A loose pattern matches order numbers, tracking
 * references, dates and prices, and every one of those is common in exactly
 * the invoice-shaped mail this is meant to read.
 */
const PHONE_PATTERNS = [
    // +1 (888) 555-0199 / +44 20 7946 0958 / +91-80-4000-1234
    /\+\d{1,3}[\s.\-]?\(?\d{2,4}\)?(?:[\s.\-]?\d{2,4}){1,4}/g,
    // 1-888-555-0199 / 888-555-0199 / (888) 555 0199
    /\(?\b\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b/g,
    // 1 888 555 0199 with a leading trunk digit
    /\b1[\s.\-]\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b/g
];

/** Below this many characters of visible text, a body is not carrying its own meaning. */
const THIN_TEXT_CHARS = 220;

/** A body this short with an image in it is an image message, whatever else is present. */
const VERY_THIN_TEXT_CHARS = 60;

class PayloadChannel {
    /** Visible text from HTML: what the reader actually sees, with markup and invisible blocks gone. */
    visibleTextFrom(html) {
        if (!html) return '';
        return html
            .replace(/<style[\s\S]*?<\/style>/gi, ' ')
            .replace(/<script[\s\S]*?<\/script>/gi, ' ')
            .replace(/<head[\s\S]*?<\/head>/gi, ' ')
            .replace(/<!--[\s\S]*?-->/g, ' ')
            .replace(/<[^>]+>/g, ' ')
            .replace(/&nbsp;/gi, ' ')
            .replace(/&[a-z]+;/gi, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    /**
     * Prose the reader can actually read, with addresses taken out.
     *
     * A mail parser handed HTML with no text part generates one, and for an
     * image-only message that generated text is almost entirely the URLs it
     * found - the image source and the link target, written out in full.
     *
     * Measuring that as readable content gets the answer exactly backwards.
     * The emptier the message, the longer its addresses loom in the count, so
     * the messages this is meant to catch are the ones that score as having
     * the most to read. A single long CDN URL was enough to carry a body with
     * no words in it over the threshold.
     */
    prose(text) {
        if (!text) return '';
        return text
            .replace(/\[?\bhttps?:\/\/[^\s\]<>"']+\]?/gi, ' ')
            .replace(/\[?\bwww\.[^\s\]<>"']+\]?/gi, ' ')
            .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    /**
     * Numbers in the text that something nearby asks the reader to ring.
     *
     * Returns the number, the intent word that qualified it, and the
     * surrounding text - so a case can quote why this was read as a call to
     * action rather than as a signature.
     */
    findCallToActionNumbers(text) {
        if (!text) return [];

        const haystack = text.toLowerCase();
        const found = new Map();

        for (const pattern of PHONE_PATTERNS) {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const raw = match[0].trim();
                const digits = raw.replace(/\D/g, '');

                // Too short to dial, or long enough to be an account number.
                if (digits.length < 7 || digits.length > 15) continue;

                // A run of identical digits is a placeholder, not a number.
                if (/^(\d)\1+$/.test(digits)) continue;

                const from = Math.max(0, match.index - INTENT_WINDOW);
                const to = Math.min(text.length, match.index + raw.length + INTENT_WINDOW);
                const window = haystack.slice(from, to);

                const intent = CALL_INTENT_TERMS.find(term => window.includes(term));
                if (!intent) continue;

                if (!found.has(digits)) {
                    found.set(digits, {
                        number: raw,
                        digits,
                        intent_term: intent,
                        context: text.slice(from, to).replace(/\s+/g, ' ').trim()
                    });
                }
            }
        }

        return [...found.values()];
    }

    /** How image-heavy the rendered body is, and whether the images carry the links. */
    describeImagery(html, visibleText, parsedEmail) {
        const imgTags = html ? (html.match(/<img\b[^>]*>/gi) || []) : [];

        // An image wrapped in a link is the classic shape: the whole message is
        // a picture, and clicking anywhere on it goes to the attacker.
        const linkedImages = html
            ? (html.match(/<a\b[^>]*>(?:(?!<\/a>)[\s\S]){0,400}?<img\b[^>]*>(?:(?!<\/a>)[\s\S]){0,400}?<\/a>/gi) || [])
            : [];

        // Images that travelled with the message rather than being fetched.
        const inlineAttachments = (parsedEmail?.attachments || [])
            .filter(a => /^image\//i.test(a.contentType || '') || /\.(png|jpe?g|gif|bmp|webp|svg)$/i.test(a.filename || ''));

        const imageCount = imgTags.length + inlineAttachments.length;
        const textLength = visibleText.length;

        return {
            image_count: imageCount,
            inline_image_count: inlineAttachments.length,
            linked_image_count: linkedImages.length,
            visible_text_length: textLength,
            // "The message is a picture": at least one image, and not enough text
            // for the message to be saying anything on its own.
            image_dominant: imageCount > 0 && textLength < THIN_TEXT_CHARS,
            // The strong form - there is essentially no text at all.
            body_is_image_only: imageCount > 0 && textLength < VERY_THIN_TEXT_CHARS,
            linked_image_only: linkedImages.length > 0 && textLength < THIN_TEXT_CHARS
        };
    }

    analyze(threatObject, parsedEmail) {
        try {
            const html = parsedEmail?.htmlBody || '';
            const plain = parsedEmail?.textBody || '';

            // Prefer the de-obfuscated copy where text deception produced one,
            // for the same reason the language analyser does: a number split by
            // zero-width characters is still a number to the person reading it.
            const normalised = threatObject.text_deception?.normalised?.body;
            const readable = normalised || plain || this.visibleTextFrom(html);

            // Addresses are not reading matter. See prose() for why counting
            // them inverts the answer on exactly the messages this detects.
            const visibleText = this.prose(plain ? plain.replace(/\s+/g, ' ').trim() : this.visibleTextFrom(html));

            const subject = threatObject.message?.subject || parsedEmail?.subject || '';
            const phones = this.findCallToActionNumbers(`${subject}\n${readable}`);
            const imagery = this.describeImagery(html, visibleText, parsedEmail);

            const urls = threatObject.iocs?.urls || [];
            const attachments = threatObject.attachments || [];

            // Links away from the sender's own domain, used for the image
            // rules: a message that is a picture plus an unsubscribe footer is
            // not the same as one that is a picture wired to somewhere else.
            const fromDomain = (parsedEmail?.from?.address || '').split('@')[1]?.toLowerCase() || '';
            const outboundUrls = urls.filter(u => {
                try {
                    const host = new URL(u).hostname.toLowerCase();
                    return !(fromDomain && (host === fromDomain || host.endsWith(`.${fromDomain}`)));
                } catch (e) {
                    return true;
                }
            });

            const channels = [];
            if (outboundUrls.length) channels.push('LINK');
            if (attachments.length) channels.push('ATTACHMENT');
            if (phones.length) channels.push('PHONE');
            if (threatObject.qr?.codes_found) channels.push('QR');
            if (imagery.image_dominant) channels.push('IMAGE');
            if (!channels.length) channels.push('NONE');

            // The defining shape of a callback attack: something to ring, and
            // nothing else at all.
            //
            // Measured against *every* link rather than only outbound ones.
            // The distinction that matters here is not whether a link is
            // interesting, it is whether a gateway has anything to inspect -
            // and a link to the sender's own site is still a link. Counting
            // only outbound ones read an ordinary reply with a company address
            // in the signature as a callback lure, which is the false positive
            // that would matter most: phone numbers in signatures are
            // everywhere.
            const phoneIsOnlyChannel = phones.length > 0
                && urls.length === 0
                && !threatObject.qr?.codes_found;

            threatObject.payload_channel = {
                channels,
                phone_numbers: phones,
                phone_is_only_channel: phoneIsOnlyChannel,
                // An attachment that exists only to carry the number - the usual
                // fake invoice - still leaves the telephone as the sole action.
                phone_only_with_document: phoneIsOnlyChannel && attachments.length > 0,
                outbound_link_count: outboundUrls.length,
                attachment_count: attachments.length,
                ...imagery,
                summary: this.summarise(phoneIsOnlyChannel, phones, imagery, outboundUrls.length)
            };
        } catch (err) {
            // A detector that throws must not take the message analysis with it.
            console.error('[PayloadChannel] Analysis failed:', err.message);
            threatObject.payload_channel = {
                channels: ['UNKNOWN'],
                status: 'UNAVAILABLE',
                reason: err.message,
                phone_numbers: [],
                phone_is_only_channel: false,
                image_dominant: false
            };
        }

        return threatObject;
    }

    summarise(phoneOnly, phones, imagery, linkCount) {
        const parts = [];

        if (phoneOnly) {
            parts.push(`The only action this message offers is a telephone number (${phones[0].number}), quoted near "${phones[0].intent_term}". There is no link to follow and nothing to open, which is the shape of a callback attack and the reason such messages pass gateways that look for a malicious payload.`);
        } else if (phones.length) {
            parts.push(`A telephone number is offered as a call to action alongside ${linkCount} link(s).`);
        }

        if (imagery.body_is_image_only) {
            parts.push(`The body is an image with ${imagery.visible_text_length} characters of readable text, so no text-based analysis can see what this message actually says.`);
        } else if (imagery.image_dominant) {
            parts.push(`The body is image-led: ${imagery.image_count} image(s) against ${imagery.visible_text_length} characters of text.`);
        }

        return parts.length ? parts.join(' ') : 'Payload is carried in the ordinary way, as text with links or attachments.';
    }
}

module.exports = new PayloadChannel();
