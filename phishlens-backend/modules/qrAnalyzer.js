const jsQR = require('jsqr');
const jpeg = require('jpeg-js');
const { PNG } = require('pngjs');

/**
 * Reads QR codes out of attached images.
 *
 * This closes a gap that the rest of the pipeline cannot reach. Every URL
 * check PhishLens runs - the indicator feeds, domain age, lookalike detection -
 * operates on URLs found in the message text. A QR code is a URL that is not in
 * the text: it is pixels in an attachment, invisible to any amount of language
 * analysis, and the recipient resolves it on a phone that is usually outside
 * whatever protection the organisation has on its desktops.
 *
 * The shape that motivates this is a message with little or no body and one
 * image or PDF attachment, where the entire payload is the code. A content
 * classifier reading that message sees nothing to object to, because there is
 * nothing there to read. Decoding the code puts the URL back into the pipeline
 * so the existing intelligence applies to it normally.
 *
 * Everything here runs locally on bytes already in hand: no service, no upload,
 * no key. The decoder is pure JavaScript, so it adds nothing to build or
 * install.
 */

/** A QR code smaller than this is unlikely to be a real payload; larger images cost time. */
const MAX_PIXELS = 4_000_000;

class QrAnalyzer {
    /** Decode an image attachment to the raw RGBA buffer jsQR expects. */
    toImageData(buffer, contentType) {
        const type = String(contentType || '').toLowerCase();

        if (type.includes('png')) {
            const png = PNG.sync.read(buffer);
            return { data: png.data, width: png.width, height: png.height };
        }
        if (type.includes('jpeg') || type.includes('jpg')) {
            const raw = jpeg.decode(buffer, { useTArray: true, formatAsRGBA: true });
            return { data: raw.data, width: raw.width, height: raw.height };
        }
        return null;
    }

    /**
     * One call into jsQR, and one only.
     *
     * jsQR carries state between invocations. A `dontInvert` call that fails
     * leaves the library in a condition where the *next* call returns null for
     * an image it decodes perfectly well on its own - verified directly: the
     * default mode decodes an inverted code, and the same call after a failed
     * `dontInvert` attempt on a brand-new buffer does not. Two earlier versions
     * of this method made two calls, and both silently failed to read inverted
     * codes, which is precisely the case the second call was added for.
     *
     * `onlyInvert` is unusable for a different reason: it throws a TypeError
     * from inside the library on a valid image.
     *
     * So: the default mode, once. It attempts both polarities internally, which
     * was measured rather than assumed.
     */
    decode(imageData) {
        const result = jsQR(new Uint8ClampedArray(imageData.data), imageData.width, imageData.height);
        if (!result || !result.data) return null;
        return { text: result.data, polarity: this.observePolarity(imageData) };
    }

    /**
     * Whether the image is mostly dark, observed from the pixels rather than
     * inferred from which decoder pass succeeded - which is not knowable, since
     * only one pass can safely be made.
     *
     * Worth recording because a light-on-dark code is unusual in an ordinary
     * document and is a cheap way past a decoder that reads one polarity only.
     */
    observePolarity(imageData) {
        const { data, width, height } = imageData;
        // Sampled rather than exhaustive: polarity is a property of the whole
        // image, so every hundredth pixel answers it just as well.
        const step = 4 * Math.max(1, Math.floor((width * height) / 10000));
        let total = 0;
        let count = 0;
        for (let i = 0; i < data.length - 3; i += step) {
            total += (data[i] * 0.2126 + data[i + 1] * 0.7152 + data[i + 2] * 0.0722);
            count++;
        }
        if (count === 0) return 'unknown';
        return (total / count) < 128 ? 'inverted' : 'normal';
    }

    /**
     * Reads every decodable image attachment and returns what the codes contain.
     *
     * A PDF is reported as undecoded rather than skipped silently. Pulling
     * images out of a PDF needs a full PDF renderer, which is a large
     * dependency and a parser attackers actively target; claiming to handle
     * PDFs and quietly missing them would be worse than saying so.
     */
    analyze(threatObject, parsedEmail) {
        const attachments = (parsedEmail && parsedEmail.attachments) || [];
        const findings = [];
        const undecodable = [];

        for (const attachment of attachments) {
            const contentType = attachment.contentType || '';
            const filename = attachment.filename || '(unnamed)';
            const content = attachment.content;

            if (!content || !Buffer.isBuffer(content)) continue;

            if (/^application\/pdf/i.test(contentType) || /\.pdf$/i.test(filename)) {
                undecodable.push({
                    filename,
                    content_type: contentType,
                    reason: 'PDF attachments are not rendered, so a QR code inside one is not decoded. Reading it would require a full PDF renderer - a large dependency and a parser attackers actively target.'
                });
                continue;
            }

            if (!/^image\/(png|jpe?g)/i.test(contentType) && !/\.(png|jpe?g)$/i.test(filename)) {
                continue;
            }

            let imageData;
            try {
                imageData = this.toImageData(content, contentType || filename);
            } catch (e) {
                undecodable.push({ filename, content_type: contentType, reason: `The image could not be decoded: ${e.message}` });
                continue;
            }
            if (!imageData) continue;

            if (imageData.width * imageData.height > MAX_PIXELS) {
                undecodable.push({
                    filename,
                    content_type: contentType,
                    reason: `The image is ${imageData.width}x${imageData.height}, above the ${MAX_PIXELS}-pixel scanning limit.`
                });
                continue;
            }

            let decoded;
            try {
                decoded = this.decode(imageData);
            } catch (e) {
                undecodable.push({ filename, content_type: contentType, reason: `QR scanning failed: ${e.message}` });
                continue;
            }

            if (decoded) {
                findings.push({
                    filename,
                    content_type: contentType,
                    dimensions: `${imageData.width}x${imageData.height}`,
                    polarity: decoded.polarity,
                    payload: decoded.text,
                    payload_kind: this.classifyPayload(decoded.text)
                });
            }
        }

        threatObject.qr = {
            scanned_attachments: attachments.length,
            codes_found: findings.length,
            codes: findings,
            not_scanned: undecodable,
            // The URLs the rest of the pipeline should treat exactly as it
            // treats a URL written in the body.
            extracted_urls: findings
                .filter(f => f.payload_kind === 'url')
                .map(f => f.payload)
        };

        return threatObject;
    }

    /**
     * What the code actually contains. A QR code is not always a link, and the
     * non-link kinds carry their own risk: a `WIFI:` code joins a network, and
     * `BEGIN:VCARD` or `MATMSG:` can seed a convincing follow-up contact.
     */
    classifyPayload(text) {
        const value = String(text || '').trim();
        if (/^https?:\/\//i.test(value)) return 'url';
        if (/^(www\.|[a-z0-9-]+\.[a-z]{2,}\/)/i.test(value)) return 'url';
        if (/^mailto:/i.test(value)) return 'email_address';
        if (/^tel:/i.test(value)) return 'telephone_number';
        if (/^WIFI:/i.test(value)) return 'wifi_credentials';
        if (/^BEGIN:VCARD/i.test(value)) return 'contact_card';
        if (/^(SMSTO|MATMSG):/i.test(value)) return 'message_template';
        if (/^bitcoin:|^ethereum:/i.test(value)) return 'cryptocurrency_address';
        return 'text';
    }
}

module.exports = new QrAnalyzer();
