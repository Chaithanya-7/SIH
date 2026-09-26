/**
 * A display filter for the mail flow list, modelled on Wireshark's.
 *
 * ## Why a language rather than a search box
 *
 * A search box answers "does this row contain that text". The question an
 * analyst actually has is narrower and structured: high-risk mail from one
 * country, or anything on port 443 that is not from a domain they trust, or
 * every message where a connection was observed. Wireshark solved this with a
 * small expression language, and the reason it has lasted is that it composes -
 * two conditions and an operator give a third.
 *
 * ## What is implemented, and why it stops where it does
 *
 *   field == value        field != value
 *   field > value         field < value       (and >=, <=, on numbers)
 *   field contains text   field matches regex
 *   field                 (the field is present at all)
 *   && || !               and or not          ( )
 *
 * Wireshark also has slices, membership sets, arithmetic and per-layer
 * addressing, all of which exist because a packet is a nested structure. A row
 * here is flat, so those would be syntax with nothing to address.
 *
 * ## Errors are the point, not an afterthought
 *
 * Wireshark colours its filter bar green for a valid expression and red for an
 * invalid one, and that instant feedback is most of why the language is usable
 * at all. So this never throws and never silently returns everything: it returns
 * a predicate *or* an error naming the problem and where it is. A filter that
 * fails open would quietly show an analyst the wrong set of mail and look like
 * it had worked.
 */

/**
 * The addressable fields. Each says how to read it from a row and what it is,
 * because comparing a port as text would make `dport > 100` nonsense.
 */
export const FIELDS = {
    no: { type: 'number', read: r => r.no, help: 'Sequence number' },
    verdict: { type: 'enum', read: r => r.verdict, values: ['HIGH_RISK', 'SUSPICIOUS', 'SAFE'], help: 'HIGH_RISK, SUSPICIOUS or SAFE' },
    colour: { type: 'enum', read: r => r.colour, values: ['RED', 'YELLOW', 'GREEN'], help: 'RED, YELLOW or GREEN' },
    severity: { type: 'enum', read: r => r.severity, values: ['HIGH', 'MEDIUM', 'LOW'], help: 'HIGH, MEDIUM or LOW' },
    src: { type: 'text', read: r => r.source, help: 'Source address' },
    'src.host': { type: 'text', read: r => r.source_host, help: 'Source hostname' },
    'src.country': { type: 'text', read: r => r.source_country, help: 'Source country' },
    'src.asn': { type: 'text', read: r => r.source_asn, help: 'Source ASN' },
    dst: { type: 'text', read: r => r.destination, help: 'Destination address' },
    'dst.host': { type: 'text', read: r => r.destination_host, help: 'Destination host' },
    sport: { type: 'number', read: r => r.source_port, help: 'Source port, where a header stated one' },
    dport: { type: 'number', read: r => r.destination_port, help: 'Destination port' },
    proto: { type: 'text', read: r => r.protocol, help: 'Protocol' },
    channel: { type: 'text', read: r => r.channel, help: 'How the message arrived' },
    subject: { type: 'text', read: r => r.name, help: 'Subject line' },
    sender: { type: 'text', read: r => r.sender, help: 'Sender address' },
    recipient: { type: 'text', read: r => r.recipient, help: 'Recipient address' },
    info: { type: 'text', read: r => r.info, help: 'Summary column' },
    len: { type: 'number', read: r => r.length, help: 'Message size in bytes' },
    confidence: { type: 'number', read: r => r.confidence, help: 'Threat confidence, 0 to 1' },
    attachments: { type: 'number', read: r => r.attachments, help: 'Number of attachments' },
    rules: { type: 'number', read: r => r.rules_matched, help: 'Detection rules matched' },
    conn: { type: 'bool', read: r => r.connection_observed, help: 'A connection to the destination was observed' },
    historical: { type: 'bool', read: r => r.analysis_mode === 'HISTORICAL', help: 'Analysed after the fact' }
};

const COMPARISONS = ['>=', '<=', '==', '!=', '>', '<'];
const WORD_OPERATORS = { contains: 'contains', matches: 'matches' };

/** Splits an expression into tokens, keeping each one's position for error reporting. */
function tokenise(input) {
    const tokens = [];
    let i = 0;

    while (i < input.length) {
        const ch = input[i];

        if (/\s/.test(ch)) { i++; continue; }

        if (ch === '(' || ch === ')') { tokens.push({ kind: ch, at: i }); i++; continue; }

        if (input.startsWith('&&', i)) { tokens.push({ kind: 'and', at: i }); i += 2; continue; }
        if (input.startsWith('||', i)) { tokens.push({ kind: 'or', at: i }); i += 2; continue; }

        const comparison = COMPARISONS.find(op => input.startsWith(op, i));
        if (comparison) { tokens.push({ kind: 'cmp', value: comparison, at: i }); i += comparison.length; continue; }

        if (ch === '!' && input[i + 1] !== '=') { tokens.push({ kind: 'not', at: i }); i++; continue; }

        // A quoted string keeps its spaces, which is how a subject is matched.
        if (ch === '"' || ch === "'") {
            const close = input.indexOf(ch, i + 1);
            if (close === -1) return { error: { message: 'Unclosed quote', at: i } };
            tokens.push({ kind: 'value', value: input.slice(i + 1, close), quoted: true, at: i });
            i = close + 1;
            continue;
        }

        const word = input.slice(i).match(/^[^\s()!<>=&|"']+/);
        if (!word) return { error: { message: `Unexpected character "${ch}"`, at: i } };

        const text = word[0];
        const lower = text.toLowerCase();

        if (lower === 'and' || lower === 'or' || lower === 'not') tokens.push({ kind: lower, at: i });
        else if (WORD_OPERATORS[lower]) tokens.push({ kind: 'cmp', value: lower, at: i });
        else tokens.push({ kind: 'word', value: text, at: i });

        i += text.length;
    }

    return { tokens };
}

const truthy = v => v !== null && v !== undefined && v !== '' && v !== false;

/** One `field op value` test, or a bare field-present test. */
function buildComparison(fieldToken, opToken, valueToken) {
    const name = fieldToken.value;
    const field = FIELDS[name] || FIELDS[name.toLowerCase()];

    if (!field) {
        return { error: { message: `There is no field called "${name}"`, at: fieldToken.at } };
    }

    // A bare field name means "this row has a value for it", as in Wireshark.
    if (!opToken) return { test: row => truthy(field.read(row)) };

    const op = opToken.value;
    const raw = valueToken.value;

    if (field.type === 'number') {
        const wanted = Number(raw);
        if (!Number.isFinite(wanted) && op !== 'contains' && op !== 'matches') {
            return { error: { message: `"${raw}" is not a number, and ${name} is numeric`, at: valueToken.at } };
        }
        return {
            test: row => {
                const value = field.read(row);

                // A row with no value for a numeric field matches no comparison.
                // Treating a missing port as zero would make `sport < 1024` true
                // for every message that never recorded one, which is most of
                // them.
                //
                // The emptiness has to be checked *before* coercing, not after:
                // `Number(null)` is 0, and 0 is finite, so a Number.isFinite
                // guard on its own lets null straight through. That is precisely
                // what this was written to prevent, and it did not.
                if (value === null || value === undefined || value === '') return false;

                const actual = Number(value);
                if (!Number.isFinite(actual)) return false;
                switch (op) {
                    case '==': return actual === wanted;
                    case '!=': return actual !== wanted;
                    case '>': return actual > wanted;
                    case '<': return actual < wanted;
                    case '>=': return actual >= wanted;
                    case '<=': return actual <= wanted;
                    default: return String(actual).includes(raw);
                }
            }
        };
    }

    if (field.type === 'bool') {
        const wanted = !/^(false|no|0)$/i.test(raw);
        return { test: row => Boolean(field.read(row)) === (op === '!=' ? !wanted : wanted) };
    }

    if (op === 'matches') {
        let expression;
        try {
            expression = new RegExp(raw, 'i');
        } catch (e) {
            return { error: { message: `Not a valid regular expression: ${e.message}`, at: valueToken.at } };
        }
        return { test: row => expression.test(String(field.read(row) ?? '')) };
    }

    const wanted = String(raw).toLowerCase();
    return {
        test: row => {
            const actual = String(field.read(row) ?? '').toLowerCase();
            switch (op) {
                case '==': return actual === wanted;
                case '!=': return actual !== wanted;
                case 'contains': return actual.includes(wanted);
                case '>': return actual > wanted;
                case '<': return actual < wanted;
                case '>=': return actual >= wanted;
                case '<=': return actual <= wanted;
                default: return actual.includes(wanted);
            }
        }
    };
}

/**
 * Compiles an expression.
 *
 * Returns `{ test }` when it is valid, `{ error: { message, at } }` when it is
 * not, and `{ test: () => true }` for an empty filter. It never throws, because
 * this runs on every keystroke.
 */
export function compileFilter(input) {
    const text = String(input || '').trim();
    if (!text) return { test: () => true, empty: true };

    const { tokens, error: lexError } = tokenise(text);
    if (lexError) return { error: lexError };
    if (!tokens.length) return { test: () => true, empty: true };

    let position = 0;
    const peek = () => tokens[position];
    const next = () => tokens[position++];

    let failure = null;
    const fail = (message, at) => { if (!failure) failure = { message, at: at ?? text.length }; return { test: () => false }; };

    function parsePrimary() {
        const token = peek();
        if (!token) return fail('The expression ends before it is finished');

        if (token.kind === 'not') { next(); const inner = parsePrimary(); return { test: row => !inner.test(row) }; }

        if (token.kind === '(') {
            next();
            const inner = parseOr();
            if (peek()?.kind !== ')') return fail('Missing a closing bracket', token.at);
            next();
            return inner;
        }

        if (token.kind !== 'word') return fail(`Expected a field name, found "${token.value ?? token.kind}"`, token.at);
        next();

        const op = peek();
        if (!op || op.kind !== 'cmp') {
            const built = buildComparison(token, null, null);
            if (built.error) return fail(built.error.message, built.error.at);
            return built;
        }
        next();

        const value = peek();
        if (!value || (value.kind !== 'word' && value.kind !== 'value')) {
            return fail(`Nothing to compare ${token.value} against`, op.at);
        }
        next();

        const built = buildComparison(token, op, value);
        if (built.error) return fail(built.error.message, built.error.at);
        return built;
    }

    function parseAnd() {
        let left = parsePrimary();
        while (peek()?.kind === 'and') {
            next();
            const right = parsePrimary();
            const l = left, r = right;
            left = { test: row => l.test(row) && r.test(row) };
        }
        return left;
    }

    function parseOr() {
        let left = parseAnd();
        while (peek()?.kind === 'or') {
            next();
            const right = parseAnd();
            const l = left, r = right;
            left = { test: row => l.test(row) || r.test(row) };
        }
        return left;
    }

    const compiled = parseOr();
    if (failure) return { error: failure };
    if (position < tokens.length) {
        return { error: { message: `Unexpected "${tokens[position].value ?? tokens[position].kind}"`, at: tokens[position].at } };
    }

    return { test: compiled.test };
}

/** Field names for the hint list, so the language is discoverable without docs. */
export function fieldSuggestions(partial) {
    const query = String(partial || '').toLowerCase();
    const last = query.split(/[\s()!&|]+/).pop() || '';
    if (!last) return [];
    return Object.entries(FIELDS)
        .filter(([name]) => name.startsWith(last) && name !== last)
        .slice(0, 8)
        .map(([name, field]) => ({ name, help: field.help, type: field.type }));
}

/** A few worked examples, which is how anybody actually learns a filter language. */
export const FILTER_EXAMPLES = [
    { expression: 'verdict == HIGH_RISK', describes: 'only dangerous mail' },
    { expression: 'colour == RED || colour == YELLOW', describes: 'anything not judged legitimate' },
    { expression: 'subject contains invoice && attachments > 0', describes: 'invoice mail carrying a file' },
    { expression: 'conn', describes: 'messages where a connection to the destination was observed' },
    { expression: 'sport', describes: 'the few messages whose headers recorded a source port' },
    { expression: 'src.country != India && verdict != SAFE', describes: 'flagged mail from outside one country' },
    { expression: 'proto == SMTP && dport == 2525', describes: 'mail that came through the SMTP gateway' },
    { expression: 'sender matches "@(gmail|outlook)\\.com$"', describes: 'senders on the big free providers' }
];
