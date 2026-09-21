/**
 * Reads rules written in YARA syntax and matches them against bytes.
 *
 * ## Why this is not simply YARA
 *
 * YARA is a C library. On this machine pip had no wheel for it and fell back to
 * compiling from source, which needs a toolchain that a person installing a
 * phishing detector has no reason to own. An optional tool that is absent
 * everywhere is not an optional tool, it is a feature nobody gets - so the rules
 * that ship with PhishLens run on an engine that is already here.
 *
 * Where real YARA *is* installed it should be preferred, because it implements
 * the whole language and this does not. See yaraRules.js for that choice.
 *
 * ## What this supports, precisely
 *
 * Stated rather than implied, because a rule that silently fails to compile is
 * worse than no rule: it reads as "scanned, nothing found".
 *
 *   strings      text, hex with ?? wildcards and [n-m] jumps, /regex/
 *   modifiers    nocase, wide, ascii, fullword
 *   conditions   and, or, not, parentheses
 *                all|any|N of them, all|any|N of ($a, $b*)
 *                $a, $a at N, #a > N, filesize < N, uint8|16|32(N) == V
 *   meta         kept and returned with every match
 *
 * Anything else is refused at load time and reported. It is never skipped.
 *
 * ## Matching over bytes
 *
 * The haystack is the buffer decoded as latin1, which maps bytes 0-255 to code
 * points 0-255 unchanged. That makes a byte pattern expressible as a string
 * pattern without ever pretending the content is text.
 */

/** A rule that runs forever is a rule that stops the pipeline. */
const MAX_SCAN_BYTES = 25 * 1024 * 1024;

const KEYWORDS = new Set(['all', 'any', 'of', 'them', 'and', 'or', 'not', 'at', 'filesize', 'true', 'false']);

class RuleSyntaxError extends Error {
    constructor(message, ruleName) {
        super(ruleName ? `${ruleName}: ${message}` : message);
        this.name = 'RuleSyntaxError';
        this.ruleName = ruleName;
    }
}

/** Escapes a byte-string so it can sit inside a regular expression literally. */
function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Parsing rule text
// ---------------------------------------------------------------------------

/**
 * Splits a .yar file into rules.
 *
 * Braces are counted rather than matched with a regular expression, because a
 * rule body legitimately contains braces inside hex strings.
 */
function splitRules(source) {
    const rules = [];
    const header = /(?:^|\s)(private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(:\s*[^{]+)?\{/g;

    let match;
    while ((match = header.exec(source)) !== null) {
        const bodyStart = header.lastIndex;
        let depth = 1;
        let index = bodyStart;

        while (index < source.length && depth > 0) {
            const character = source[index];

            // Braces inside a string literal are content, not structure. An RTF
            // rule looks for "{\rt", and counting that brace loses the rest of
            // the file - which is how the document rules silently went missing.
            if (character === '"') {
                index++;
                while (index < source.length && source[index] !== '"') {
                    if (source[index] === '\\') index++;
                    index++;
                }
                index++;
                continue;
            }

            // A regex literal is skipped whole for the same reason, and for one
            // more: it can contain a quote, as ["']? does, and treating that as
            // the start of a string swallows everything up to the next one.
            if (character === '/') {
                index++;
                while (index < source.length && source[index] !== '/' && source[index] !== '\n') {
                    if (source[index] === '\\') index++;
                    index++;
                }
                index++;
                continue;
            }

            if (character === '{') depth++;
            else if (character === '}') depth--;
            index++;
        }

        if (depth !== 0) throw new RuleSyntaxError('unterminated rule body', match[2]);

        rules.push({
            name: match[2],
            tags: (match[3] || '').replace(':', '').trim().split(/\s+/).filter(Boolean),
            body: source.slice(bodyStart, index - 1)
        });

        header.lastIndex = index;
    }

    return rules;
}

/** Strips comments without disturbing text inside string literals. */
function stripComments(source) {
    let output = '';
    let index = 0;

    while (index < source.length) {
        const character = source[index];

        if (character === '"' || character === '/') {
            // A quoted string, or a regex literal, is copied across whole.
            const isRegex = character === '/' && !'*/'.includes(source[index + 1] || '');
            if (character === '"' || isRegex) {
                const quote = character;
                let end = index + 1;
                while (end < source.length && source[end] !== quote) {
                    if (source[end] === '\\') end++;
                    end++;
                }
                output += source.slice(index, end + 1);
                index = end + 1;
                continue;
            }
        }

        if (character === '/' && source[index + 1] === '/') {
            while (index < source.length && source[index] !== '\n') index++;
            continue;
        }

        if (character === '/' && source[index + 1] === '*') {
            const end = source.indexOf('*/', index + 2);
            index = end < 0 ? source.length : end + 2;
            continue;
        }

        output += character;
        index++;
    }

    return output;
}

/** The meta, strings and condition sections of one rule body. */
function parseSections(body, ruleName) {
    const positions = [];
    for (const section of ['meta', 'strings', 'condition']) {
        const found = new RegExp(`(?:^|\\s)${section}\\s*:`).exec(body);
        if (found) positions.push({ section, start: found.index + found[0].length });
    }

    positions.sort((a, b) => a.start - b.start);
    if (!positions.some(p => p.section === 'condition')) {
        throw new RuleSyntaxError('no condition section', ruleName);
    }

    const sections = {};
    positions.forEach((position, index) => {
        const end = index + 1 < positions.length
            ? body.lastIndexOf(positions[index + 1].section, positions[index + 1].start)
            : body.length;
        sections[position.section] = body.slice(position.start, end).trim();
    });

    return sections;
}

function parseMeta(text) {
    const meta = {};
    if (!text) return meta;

    const entry = /([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|true|false|-?\d+)/g;
    let match;
    while ((match = entry.exec(text)) !== null) {
        const raw = match[2];
        meta[match[1]] = raw.startsWith('"')
            ? raw.slice(1, -1).replace(/\\(.)/g, '$1')
            : (raw === 'true' ? true : raw === 'false' ? false : Number(raw));
    }
    return meta;
}

/**
 * Turns one string definition into something that can be searched for.
 *
 * Every kind ends up as a regular expression over the latin1 haystack, so the
 * matcher itself does not care which kind it started as.
 */
function parseString(identifier, definition, modifiers, ruleName) {
    const flags = new Set(modifiers.trim().split(/\s+/).filter(Boolean));

    for (const flag of flags) {
        if (!['nocase', 'wide', 'ascii', 'fullword', 'private'].includes(flag)) {
            throw new RuleSyntaxError(`unsupported string modifier "${flag}" on ${identifier}`, ruleName);
        }
    }

    const nocase = flags.has('nocase');
    const patterns = [];

    if (definition.startsWith('"')) {
        // One pass, left to right. Replacing each escape in turn instead reads
        // the second backslash of an escaped backslash as the start of the next
        // escape: "{\\rt" became "{\<CR>t", and the RTF rule then matched
        // nothing while appearing to compile perfectly.
        const literal = definition.slice(1, -1).replace(/\\(x[0-9a-fA-F]{2}|.)/g, (_, sequence) => {
            if (sequence[0] === 'x') return String.fromCharCode(parseInt(sequence.slice(1), 16));
            switch (sequence) {
                case 'n': return '\n';
                case 'r': return '\r';
                case 't': return '\t';
                case '"': return '"';
                case '\\': return '\\';
                default: return sequence;
            }
        });

        // ascii is the default; wide means the same text with a null after every
        // character, which is how Windows stores it. Asking for both means either.
        const wantsWide = flags.has('wide');
        const wantsAscii = flags.has('ascii') || !wantsWide;

        if (wantsAscii) patterns.push(escapeRegex(literal));
        if (wantsWide) patterns.push(escapeRegex(literal.split('').join(' ')) + ' ?');

        return { identifier, kind: 'text', patterns, nocase, fullword: flags.has('fullword'), literal };
    }

    if (definition.startsWith('{')) {
        const inner = definition.slice(1, -1).trim();
        let pattern = '';

        // Tokens are bytes, ?? wildcards, or [n-m] jumps.
        for (const token of inner.split(/\s+/).filter(Boolean)) {
            if (/^[0-9a-fA-F]{2}$/.test(token)) {
                pattern += escapeRegex(String.fromCharCode(parseInt(token, 16)));
            } else if (token === '??') {
                pattern += '[\\s\\S]';
            } else if (/^\?[0-9a-fA-F]$/.test(token) || /^[0-9a-fA-F]\?$/.test(token)) {
                // A nibble wildcard: enumerate the sixteen bytes it can be.
                const options = [];
                for (let value = 0; value < 256; value++) {
                    const hex = value.toString(16).padStart(2, '0');
                    const matches = token[0] === '?' ? hex[1] === token[1].toLowerCase() : hex[0] === token[0].toLowerCase();
                    if (matches) options.push(escapeRegex(String.fromCharCode(value)));
                }
                pattern += `(?:${options.join('|')})`;
            } else if (/^\[\d+\]$/.test(token)) {
                pattern += `[\\s\\S]{${token.slice(1, -1)}}`;
            } else if (/^\[\d+-\d*\]$/.test(token)) {
                const [low, high] = token.slice(1, -1).split('-');
                pattern += high === '' ? `[\\s\\S]{${low},}` : `[\\s\\S]{${low},${high}}`;
            } else {
                throw new RuleSyntaxError(`unsupported hex token "${token}" in ${identifier}`, ruleName);
            }
        }

        return { identifier, kind: 'hex', patterns: [pattern], nocase: false, fullword: false };
    }

    if (definition.startsWith('/')) {
        const end = definition.lastIndexOf('/');
        const body = definition.slice(1, end);
        const regexFlags = definition.slice(end + 1);
        return {
            identifier,
            kind: 'regex',
            patterns: [body],
            nocase: nocase || regexFlags.includes('i'),
            fullword: flags.has('fullword')
        };
    }

    throw new RuleSyntaxError(`unrecognised string definition for ${identifier}`, ruleName);
}

function parseStrings(text, ruleName) {
    const strings = [];
    if (!text) return strings;

    // Definitions start at a $identifier = at the beginning of a line.
    const definition = /(\$[A-Za-z0-9_*]*)\s*=\s*/g;
    const starts = [];
    let match;
    while ((match = definition.exec(text)) !== null) {
        starts.push({ identifier: match[1], valueStart: definition.lastIndex });
    }

    starts.forEach((start, index) => {
        const end = index + 1 < starts.length
            ? text.lastIndexOf(starts[index + 1].identifier, starts[index + 1].valueStart)
            : text.length;

        const remainder = text.slice(start.valueStart, end).trim();

        // Where the value ends and its modifiers begin depends on the kind.
        let value = remainder;
        let modifiers = '';

        if (remainder.startsWith('"')) {
            let cursor = 1;
            while (cursor < remainder.length && remainder[cursor] !== '"') {
                if (remainder[cursor] === '\\') cursor++;
                cursor++;
            }
            value = remainder.slice(0, cursor + 1);
            modifiers = remainder.slice(cursor + 1);
        } else if (remainder.startsWith('{')) {
            const close = remainder.indexOf('}');
            value = remainder.slice(0, close + 1);
            modifiers = remainder.slice(close + 1);
        } else if (remainder.startsWith('/')) {
            let cursor = 1;
            while (cursor < remainder.length && remainder[cursor] !== '/') {
                if (remainder[cursor] === '\\') cursor++;
                cursor++;
            }
            const trailing = /^[a-z]*/.exec(remainder.slice(cursor + 1))[0];
            value = remainder.slice(0, cursor + 1 + trailing.length);
            modifiers = remainder.slice(cursor + 1 + trailing.length);
        }

        strings.push(parseString(start.identifier, value, modifiers, ruleName));
    });

    return strings;
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

function tokenizeCondition(text, ruleName) {
    const tokens = [];
    const pattern = /\s*(\(|\)|,|>=|<=|==|!=|>|<|[#$][A-Za-z0-9_]*\*?|0x[0-9a-fA-F]+|\d+(?:KB|MB)?|[A-Za-z_][A-Za-z0-9_]*)/y;

    let index = 0;
    while (index < text.length) {
        pattern.lastIndex = index;
        const match = pattern.exec(text);
        if (!match) {
            if (!text.slice(index).trim()) break;
            throw new RuleSyntaxError(`cannot read condition at "${text.slice(index, index + 20)}"`, ruleName);
        }
        tokens.push(match[1]);
        index = pattern.lastIndex;
    }

    return tokens;
}

/**
 * Builds an evaluator for a condition.
 *
 * Recursive descent over the token list, returning a function of the match
 * state rather than a tree, so evaluation costs nothing beyond the calls.
 */
function parseCondition(tokens, ruleName, stringIds) {
    let position = 0;

    const peek = () => tokens[position];
    const next = () => tokens[position++];
    const expect = value => {
        if (tokens[position] !== value) {
            throw new RuleSyntaxError(`expected "${value}" but found "${tokens[position] || 'end of condition'}"`, ruleName);
        }
        return tokens[position++];
    };

    const numberOf = token => {
        if (/^0x/.test(token)) return parseInt(token, 16);
        if (/KB$/.test(token)) return parseInt(token, 10) * 1024;
        if (/MB$/.test(token)) return parseInt(token, 10) * 1024 * 1024;
        return parseInt(token, 10);
    };

    const compare = (left, operator, right) => {
        switch (operator) {
            case '>': return left > right;
            case '<': return left < right;
            case '>=': return left >= right;
            case '<=': return left <= right;
            case '==': return left === right;
            case '!=': return left !== right;
            default: throw new RuleSyntaxError(`unsupported operator "${operator}"`, ruleName);
        }
    };

    /** Expands "them" and "$prefix*" into the identifiers they stand for. */
    const resolveSet = () => {
        if (peek() === 'them') { next(); return stringIds.slice(); }

        expect('(');
        const chosen = [];
        while (peek() !== ')') {
            const token = next();
            if (token === ',') continue;
            if (token.endsWith('*')) {
                const prefix = token.slice(0, -1);
                chosen.push(...stringIds.filter(id => id.startsWith(prefix)));
            } else {
                chosen.push(token);
            }
        }
        expect(')');
        return chosen;
    };

    const parsePrimary = () => {
        const token = peek();

        if (token === '(') {
            next();
            const inner = parseOr();
            expect(')');
            return inner;
        }

        if (token === 'not') { next(); const inner = parsePrimary(); return state => !inner(state); }
        if (token === 'true') { next(); return () => true; }
        if (token === 'false') { next(); return () => false; }

        // all of them / any of ($a*) / 2 of them
        if (token === 'all' || token === 'any' || (/^\d+$/.test(token) && tokens[position + 1] === 'of')) {
            const quantifier = next();
            expect('of');
            const chosen = resolveSet();
            return state => {
                const hits = chosen.filter(id => (state.counts[id] || 0) > 0).length;
                if (quantifier === 'all') return hits === chosen.length && chosen.length > 0;
                if (quantifier === 'any') return hits > 0;
                return hits >= Number(quantifier);
            };
        }

        if (token === 'filesize') {
            next();
            const operator = next();
            const value = numberOf(next());
            return state => compare(state.size, operator, value);
        }

        if (/^uint(8|16|32)$/.test(token)) {
            const width = Number(next().replace('uint', ''));
            expect('(');
            const offset = numberOf(next());
            expect(')');
            const operator = next();
            const value = numberOf(next());
            return state => {
                const read = state.readUint(width, offset);
                return read === null ? false : compare(read, operator, value);
            };
        }

        if (token.startsWith('#')) {
            const identifier = '$' + next().slice(1);
            const operator = next();
            const value = numberOf(next());
            return state => compare(state.counts[identifier] || 0, operator, value);
        }

        if (token.startsWith('$')) {
            const identifier = next();

            if (peek() === 'at') {
                next();
                const offset = numberOf(next());
                return state => (state.offsets[identifier] || []).includes(offset);
            }

            if (identifier.endsWith('*')) {
                const prefix = identifier.slice(0, -1);
                return state => stringIds.some(id => id.startsWith(prefix) && (state.counts[id] || 0) > 0);
            }

            return state => (state.counts[identifier] || 0) > 0;
        }

        throw new RuleSyntaxError(`unsupported condition term "${token}"`, ruleName);
    };

    const parseAnd = () => {
        let left = parsePrimary();
        while (peek() === 'and') {
            next();
            const right = parsePrimary();
            const previous = left;
            left = state => previous(state) && right(state);
        }
        return left;
    };

    const parseOr = () => {
        let left = parseAnd();
        while (peek() === 'or') {
            next();
            const right = parseAnd();
            const previous = left;
            left = state => previous(state) || right(state);
        }
        return left;
    };

    const evaluate = parseOr();
    if (position < tokens.length) {
        throw new RuleSyntaxError(`unexpected "${tokens[position]}" after the end of the condition`, ruleName);
    }
    return evaluate;
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

class YaraEngine {
    constructor() {
        this.rules = [];
        this.errors = [];
    }

    /**
     * Compiles rule text. A rule that will not compile is recorded as an error
     * and kept out of the set, never dropped quietly.
     */
    load(source, origin = 'inline') {
        const cleaned = stripComments(source);

        for (const raw of splitRules(cleaned)) {
            try {
                const sections = parseSections(raw.body, raw.name);
                const strings = parseStrings(sections.strings, raw.name);
                const identifiers = strings.map(s => s.identifier);

                const compiled = strings.map(string => ({
                    ...string,
                    regexes: string.patterns.map(pattern =>
                        new RegExp(pattern, string.nocase ? 'gis' : 'gs'))
                }));

                this.rules.push({
                    name: raw.name,
                    tags: raw.tags,
                    meta: parseMeta(sections.meta),
                    strings: compiled,
                    evaluate: parseCondition(tokenizeCondition(sections.condition, raw.name), raw.name, identifiers),
                    origin
                });
            } catch (error) {
                this.errors.push({ rule: raw.name, origin, message: error.message });
            }
        }

        return this;
    }

    /** Every rule that matches these bytes, with what made each one match. */
    scan(buffer) {
        const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
        const readable = bytes.subarray(0, MAX_SCAN_BYTES);
        const haystack = readable.toString('latin1');

        const state = {
            size: bytes.length,
            counts: {},
            offsets: {},
            readUint: (width, offset) => {
                if (offset + width / 8 > readable.length) return null;
                if (width === 8) return readable.readUInt8(offset);
                if (width === 16) return readable.readUInt16LE(offset);
                return readable.readUInt32LE(offset);
            }
        };

        const matches = [];

        for (const rule of this.rules) {
            // Counts are per rule, because two rules may use the same identifier.
            state.counts = {};
            state.offsets = {};

            for (const string of rule.strings) {
                let count = 0;
                const offsets = [];

                for (const regex of string.regexes) {
                    regex.lastIndex = 0;
                    let found;
                    while ((found = regex.exec(haystack)) !== null) {
                        if (string.fullword && !this.isFullWord(haystack, found.index, found[0].length)) {
                            if (found.index === regex.lastIndex) regex.lastIndex++;
                            continue;
                        }
                        count++;
                        if (offsets.length < 64) offsets.push(found.index);
                        // A zero-length match would otherwise loop here forever.
                        if (found.index === regex.lastIndex) regex.lastIndex++;
                    }
                }

                state.counts[string.identifier] = count;
                state.offsets[string.identifier] = offsets;
            }

            let matched = false;
            try {
                matched = rule.evaluate(state);
            } catch (error) {
                this.errors.push({ rule: rule.name, origin: rule.origin, message: `evaluation failed: ${error.message}` });
                continue;
            }

            if (!matched) continue;

            matches.push({
                rule: rule.name,
                tags: rule.tags,
                meta: rule.meta,
                matched_strings: rule.strings
                    .filter(s => (state.counts[s.identifier] || 0) > 0)
                    .map(s => ({ identifier: s.identifier, count: state.counts[s.identifier], offsets: state.offsets[s.identifier].slice(0, 8) }))
            });
        }

        return matches;
    }

    /** Whether a match sits on word boundaries, for the fullword modifier. */
    isFullWord(haystack, index, length) {
        const before = index > 0 ? haystack[index - 1] : '';
        const after = index + length < haystack.length ? haystack[index + length] : '';
        return !/[A-Za-z0-9_]/.test(before) && !/[A-Za-z0-9_]/.test(after);
    }
}

module.exports = YaraEngine;
module.exports.YaraEngine = YaraEngine;
module.exports.RuleSyntaxError = RuleSyntaxError;
