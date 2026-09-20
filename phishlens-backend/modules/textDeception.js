/**
 * Detects text that reads one way to a person and another way to a machine.
 *
 * This exists because the language layer could be switched off completely with
 * a trivial edit. Inserting a zero-width space between every character of
 * "Please verify your password immediately" takes the NLP analysis from two
 * matched signals and a score of 0.48 to **zero signals and a score of zero** -
 * measured, not assumed - while the message renders identically in every mail
 * client. Any detector that matches substrings against a body is defeated this
 * way, and the technique costs the attacker one line of code.
 *
 * That makes this the direct answer to "attackers no longer use obvious
 * keywords". Often they still do; the keywords are simply arranged so the
 * filter cannot see them.
 *
 * Two outputs, and both matter:
 *
 *   1. A *normalised* copy of the text, with invisible characters removed and
 *      lookalike characters folded to their Latin skeleton, which the rest of
 *      the pipeline analyses instead of the raw text. This repairs the bypass.
 *   2. Findings describing what was done to the text. These are worth more than
 *      the keywords they were hiding: ordinary correspondence does not contain
 *      zero-width joiners between the letters of "password", and nothing an
 *      AI writes changes that. Fluent prose is still fluent prose after
 *      normalisation; deliberately obfuscated prose is not.
 */

/**
 * Characters with no visual width, or whose only purpose is to alter how
 * surrounding text is ordered. Legitimate uses exist - ZWNJ and ZWJ are
 * meaningful in Arabic, Persian and several Indic scripts - which is why the
 * findings below weigh where these appear rather than merely that they do.
 */
const INVISIBLE = {
    '​': 'zero-width space',
    '‌': 'zero-width non-joiner',
    '‍': 'zero-width joiner',
    '⁠': 'word joiner',
    '﻿': 'zero-width no-break space',
    '­': 'soft hyphen',
    '᠎': 'Mongolian vowel separator',
    '⁡': 'function application',
    '⁢': 'invisible times',
    '⁣': 'invisible separator',
    '⁤': 'invisible plus'
};

/**
 * Bidirectional overrides. These reverse rendering order, and the classic use
 * is disguising a file extension: a name containing an override can display as
 * "invoice_txt.exe" while actually ending in .txt, or the reverse.
 */
const BIDI_OVERRIDES = {
    '‪': 'left-to-right embedding',
    '‫': 'right-to-left embedding',
    '‬': 'pop directional formatting',
    '‭': 'left-to-right override',
    '‮': 'right-to-left override',
    '⁦': 'left-to-right isolate',
    '⁧': 'right-to-left isolate',
    '⁨': 'first strong isolate',
    '⁩': 'pop directional isolate'
};

/**
 * Non-Latin characters that render as Latin letters.
 *
 * A curated set covering Cyrillic and Greek, which is what homograph attacks
 * actually use, rather than the full Unicode confusables table. Said plainly
 * because the difference matters: this folds the characters an attacker reaches
 * for, not every character that has ever been confused with another. Fullwidth
 * and mathematical variants are handled separately by NFKC normalisation, which
 * is exact and needs no table.
 */
const CONFUSABLES = {
    // Cyrillic
    'а': 'a', 'в': 'b', 'с': 'c', 'е': 'e', 'н': 'h', 'к': 'k', 'м': 'm',
    'о': 'o', 'р': 'p', 'ѕ': 's', 'т': 't', 'у': 'y', 'х': 'x', 'і': 'i',
    'ј': 'j', 'ԁ': 'd', 'ց': 'g', 'ӏ': 'l', 'ԛ': 'q', 'ѡ': 'w', 'ѵ': 'v',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'І': 'I',
    'Ј': 'J', 'Ԁ': 'D', 'Ԛ': 'Q', 'Ѡ': 'W', 'Ѵ': 'V', 'Ғ': 'F', 'Ԍ': 'G',
    // Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
    'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'γ': 'y', 'σ': 'o',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    // Armenian and Cherokee letters that render as Latin
    'օ': 'o', 'ա': 'w', 'Ꭺ': 'A', 'Ꮯ': 'C', 'Ꭼ': 'E', 'Ꮋ': 'H', 'Ꮶ': 'K',
    'Ꮲ': 'P', 'Ꮪ': 'S', 'Ꭲ': 'T', 'Ꮩ': 'V', 'Ꮃ': 'W'
};

/** Which script a character belongs to, for the mixed-script check. */
function scriptOf(ch) {
    const code = ch.codePointAt(0);
    if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) return 'Latin';
    if (code >= 0x0400 && code <= 0x04FF) return 'Cyrillic';
    if (code >= 0x0370 && code <= 0x03FF) return 'Greek';
    if (code >= 0x0530 && code <= 0x058F) return 'Armenian';
    if (code >= 0x13A0 && code <= 0x13FF) return 'Cherokee';
    if (code >= 0x0590 && code <= 0x05FF) return 'Hebrew';
    if (code >= 0x0600 && code <= 0x06FF) return 'Arabic';
    if (code >= 0x4E00 && code <= 0x9FFF) return 'Han';
    return null; // digits, punctuation, whitespace - script-neutral
}

class TextDeception {
    /**
     * Removes what is invisible and folds what is deceptive, returning text the
     * rest of the pipeline can analyse safely.
     */
    normalise(text) {
        if (typeof text !== 'string' || !text) return '';

        // NFKC folds fullwidth forms, mathematical alphanumerics and other
        // compatibility variants onto their plain equivalents. Exact, and it
        // removes a whole family of substitutions without a lookup table.
        let out = text.normalize('NFKC');

        out = [...out]
            .filter(ch => !(ch in INVISIBLE) && !(ch in BIDI_OVERRIDES))
            .map(ch => CONFUSABLES[ch] || ch)
            .join('');

        return out;
    }

    /** Every invisible or direction-altering character, with where it appeared. */
    findHiddenCharacters(text, field) {
        const findings = [];
        const counts = new Map();

        for (const ch of String(text || '')) {
            const name = INVISIBLE[ch] || BIDI_OVERRIDES[ch];
            if (!name) continue;
            counts.set(name, (counts.get(name) || 0) + 1);
        }

        counts.forEach((count, name) => {
            findings.push({
                field,
                character: name,
                count,
                directional: Object.values(BIDI_OVERRIDES).includes(name)
            });
        });

        return findings;
    }

    /**
     * Words mixing scripts.
     *
     * A single word drawing on two alphabets is close to meaningless in
     * ordinary writing and is the signature of a homograph substitution -
     * "раypal" is two Cyrillic letters followed by four Latin ones. Words are
     * checked individually rather than the whole text, because a message that
     * legitimately contains both English and Greek sentences is unremarkable;
     * a single *word* built from both is not.
     */
    findMixedScriptWords(text) {
        const findings = [];
        const words = String(text || '').split(/[\s\p{P}]+/u).filter(w => w.length > 2);

        for (const word of words) {
            const scripts = new Set();
            for (const ch of word) {
                const script = scriptOf(ch);
                if (script) scripts.add(script);
            }
            if (scripts.size > 1) {
                findings.push({
                    word,
                    scripts: [...scripts],
                    resolves_to: this.normalise(word)
                });
            }
        }

        return findings;
    }

    /**
     * Analyses the parts of a message a person actually reads.
     *
     * Deliberately covers the display name and subject as well as the body.
     * Those are the fields shown before a message is even opened, and a
     * deceptive display name does more work than a deceptive paragraph.
     */
    analyze(threatObject, parsedEmail) {
        const fields = {
            display_name: parsedEmail?.from?.name || '',
            sender_address: parsedEmail?.from?.address || '',
            subject: parsedEmail?.subject || threatObject?.message?.subject || '',
            body: parsedEmail?.textBody || ''
        };

        const hidden = [];
        const mixedScript = [];

        for (const [field, value] of Object.entries(fields)) {
            hidden.push(...this.findHiddenCharacters(value, field));
            this.findMixedScriptWords(value).forEach(f => mixedScript.push({ ...f, field }));
        }

        const bodyChanged = fields.body !== this.normalise(fields.body);
        const subjectChanged = fields.subject !== this.normalise(fields.subject);

        threatObject.text_deception = {
            hidden_characters: hidden,
            mixed_script_words: mixedScript,
            // What the rest of the pipeline should read instead of the raw text.
            normalised: {
                display_name: this.normalise(fields.display_name),
                subject: this.normalise(fields.subject),
                body: this.normalise(fields.body)
            },
            normalisation_changed_the_text: bodyChanged || subjectChanged,
            summary: this.summarise(hidden, mixedScript)
        };

        return threatObject;
    }

    summarise(hidden, mixedScript) {
        if (!hidden.length && !mixedScript.length) {
            return 'No invisible characters or mixed-script words were found. The text means to a filter what it shows to a reader.';
        }

        const parts = [];
        if (hidden.length) {
            const total = hidden.reduce((sum, h) => sum + h.count, 0);
            const where = [...new Set(hidden.map(h => h.field))].join(', ');
            parts.push(`${total} invisible or direction-altering character(s) in the ${where}`);
        }
        if (mixedScript.length) {
            parts.push(`${mixedScript.length} word(s) built from more than one alphabet (${mixedScript.slice(0, 3).map(m => `"${m.word}" reads as "${m.resolves_to}"`).join('; ')})`);
        }
        return `${parts.join('; ')}. Text is analysed after normalisation, so what was concealed is still examined.`;
    }
}

module.exports = new TextDeception();
module.exports.INVISIBLE = INVISIBLE;
module.exports.BIDI_OVERRIDES = BIDI_OVERRIDES;
