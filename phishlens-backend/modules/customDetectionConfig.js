const fs = require('fs');
const path = require('path');
const { dataFile } = require('./dataPaths');

/**
 * Operator-supplied detection content.
 *
 * Lets a deployment teach PhishLens about phishing it is seeing without
 * touching the source: custom MQL rules, custom NLP language patterns, and the
 * operator's own indicator lists. Everything lives in one local JSON file that
 * can be edited directly or managed through the API, and it is reloaded
 * without restarting the service.
 *
 * Custom rules are declarative on purpose. A rule engine that executed
 * operator-supplied JavaScript would be a remote code execution hole the moment
 * anyone could reach the API or drop a file in the data directory, so
 * conditions are expressed as field/operator/value structures and evaluated by
 * the fixed interpreter below. Nothing here is ever passed to eval or Function.
 */

/** Fields a custom rule may test, mapped to how each is derived. */
const FIELDS = {
    subject: ctx => ctx.subject,
    body: ctx => ctx.body,
    subject_and_body: ctx => `${ctx.subject}\n${ctx.body}`,
    sender_address: ctx => ctx.senderAddress,
    sender_domain: ctx => ctx.senderDomain,
    sender_display_name: ctx => ctx.senderDisplayName,
    reply_to_domain: ctx => ctx.replyToDomain,
    url_hosts: ctx => ctx.urlHosts,
    urls: ctx => ctx.urls,
    url_count: ctx => ctx.urls.length,
    attachment_names: ctx => ctx.attachmentNames,
    attachment_extensions: ctx => ctx.attachmentExtensions,
    attachment_count: ctx => ctx.attachmentExtensions.length,
    spf: ctx => ctx.auth.spf,
    dkim: ctx => ctx.auth.dkim,
    dmarc: ctx => ctx.auth.dmarc,
    nlp_signals: ctx => ctx.nlpSignals,
    matched_rules: ctx => ctx.matchedRuleIds,
    sender_domain_age_days: ctx => ctx.senderDomainAgeDays
};

const STRING_OPERATORS = new Set(['equals', 'not_equals', 'contains', 'not_contains', 'contains_any', 'contains_all', 'starts_with', 'ends_with', 'matches_regex']);
const LIST_OPERATORS = new Set(['includes_any', 'includes_all', 'not_includes_any']);
const NUMBER_OPERATORS = new Set(['gt', 'gte', 'lt', 'lte', 'equals', 'not_equals']);

const MAX_RULES = 500;
const MAX_PATTERNS = 300;
const MAX_REGEX_LENGTH = 200;
const MAX_TEXT_FOR_REGEX = 100000;

/**
 * Rejects patterns with nested quantifiers, the classic catastrophic
 * backtracking shape. A rule author should not be able to hang analysis of
 * every incoming message with one unfortunate pattern.
 */
function isRegexSafe(pattern) {
    if (typeof pattern !== 'string' || pattern.length > MAX_REGEX_LENGTH) return false;
    if (/(\([^)]*[+*][^)]*\)|\[[^\]]*[+*][^\]]*\])\s*[+*{]/.test(pattern)) return false;
    if (/(\{\d{3,},?\d*\})/.test(pattern)) return false;
    try {
        new RegExp(pattern, 'i');
        return true;
    } catch (e) {
        return false;
    }
}

function asText(value) {
    if (value === null || value === undefined) return '';
    if (Array.isArray(value)) return value.join(' ');
    return String(value);
}

function asList(value) {
    if (Array.isArray(value)) return value.map(v => String(v).toLowerCase());
    if (value === null || value === undefined) return [];
    return [String(value).toLowerCase()];
}

class CustomDetectionConfig {
    constructor() {
        this.configFile = dataFile('custom_detection.json');
        this.rules = [];
        this.nlpPatterns = [];
        this.indicators = { urls: [], domains: [], ips: [] };
        this.loadErrors = [];
        this.load();
    }

    load() {
        this.loadErrors = [];
        try {
            const dataDir = path.dirname(this.configFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.configFile)) {
                this.rules = [];
                this.nlpPatterns = [];
                this.indicators = { urls: [], domains: [], ips: [] };
                return;
            }

            const stored = JSON.parse(fs.readFileSync(this.configFile, 'utf8') || '{}');

            // Invalid entries are dropped individually and reported, so one bad
            // rule never silently disables the operator's whole configuration.
            this.rules = [];
            (stored.mql_rules || []).forEach((rule, index) => {
                const errors = this.validateRule(rule);
                if (errors.length) this.loadErrors.push({ type: 'mql_rule', index, id: rule?.id, errors });
                else this.rules.push(rule);
            });

            this.nlpPatterns = [];
            (stored.nlp_patterns || []).forEach((pattern, index) => {
                const errors = this.validateNlpPattern(pattern);
                if (errors.length) this.loadErrors.push({ type: 'nlp_pattern', index, type_name: pattern?.type, errors });
                else this.nlpPatterns.push(pattern);
            });

            const indicators = stored.indicators || {};
            this.indicators = {
                urls: (indicators.urls || []).filter(u => typeof u === 'string'),
                domains: (indicators.domains || []).map(d => String(d).toLowerCase()),
                ips: (indicators.ips || []).filter(ip => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip))
            };

            console.log(`[CustomDetection] Loaded ${this.rules.length} custom rule(s), ${this.nlpPatterns.length} language pattern(s), ${this.indicators.urls.length + this.indicators.domains.length + this.indicators.ips.length} operator indicator(s).`
                + (this.loadErrors.length ? ` ${this.loadErrors.length} invalid entr(y/ies) were skipped.` : ''));
        } catch (e) {
            this.loadErrors.push({ type: 'file', errors: [e.message] });
            console.error('[CustomDetection] Configuration load error:', e.message);
        }
    }

    save() {
        try {
            const payload = {
                mql_rules: this.rules,
                nlp_patterns: this.nlpPatterns,
                indicators: this.indicators,
                updated_at: new Date().toISOString()
            };
            fs.writeFileSync(this.configFile, JSON.stringify(payload, null, 2));
        } catch (e) {
            console.error('[CustomDetection] Configuration save error:', e.message);
            throw e;
        }
    }

    validateRule(rule) {
        const errors = [];
        if (!rule || typeof rule !== 'object') return ['Rule must be an object'];
        if (!rule.id || !/^[A-Za-z0-9_-]{3,64}$/.test(rule.id)) errors.push('id must be 3-64 characters of letters, digits, hyphen or underscore');
        if (!rule.name || String(rule.name).length < 3) errors.push('name is required');
        if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(rule.severity)) errors.push('severity must be CRITICAL, HIGH, MEDIUM or LOW');
        const confidence = Number(rule.confidence);
        if (!Number.isFinite(confidence) || confidence <= 0 || confidence > 1) errors.push('confidence must be a number greater than 0 and at most 1');
        if (!rule.source || String(rule.source).length < 3) errors.push('source is required so the rule remains auditable');
        // A rule that can single-handedly force a high-risk verdict is a
        // deliberate choice, not something to enable by accident, so it is
        // gated behind the highest severity.
        if (rule.decisive === true && rule.severity !== 'CRITICAL') {
            errors.push('decisive rules must be declared CRITICAL, since a decisive match raises the verdict to high risk on its own');
        }
        if (rule.decisive !== undefined && typeof rule.decisive !== 'boolean') errors.push('decisive must be true or false');
        if (!rule.conditions) errors.push('conditions are required');
        else errors.push(...this.validateConditions(rule.conditions, 0));
        return errors;
    }

    validateConditions(node, depth) {
        if (depth > 5) return ['conditions nested too deeply (max 5 levels)'];
        if (!node || typeof node !== 'object') return ['condition must be an object'];

        if (Array.isArray(node.all) || Array.isArray(node.any)) {
            const branch = node.all || node.any;
            if (!branch.length) return ['all/any must contain at least one condition'];
            return branch.flatMap(child => this.validateConditions(child, depth + 1));
        }
        if (node.not) return this.validateConditions(node.not, depth + 1);

        const errors = [];
        if (!FIELDS[node.field]) errors.push(`unknown field "${node.field}". Available: ${Object.keys(FIELDS).join(', ')}`);
        const op = node.op;
        if (!STRING_OPERATORS.has(op) && !LIST_OPERATORS.has(op) && !NUMBER_OPERATORS.has(op)) {
            errors.push(`unknown operator "${op}"`);
        }
        if (op === 'matches_regex' && !isRegexSafe(node.value)) {
            errors.push('matches_regex value must be a valid pattern under 200 characters without nested quantifiers');
        }
        if (node.value === undefined) errors.push('value is required');
        return errors;
    }

    validateNlpPattern(pattern) {
        const errors = [];
        if (!pattern || typeof pattern !== 'object') return ['Pattern must be an object'];
        if (!pattern.type || !/^[A-Z0-9_]{3,48}$/.test(pattern.type)) errors.push('type must be 3-48 uppercase letters, digits or underscores');
        if (!Array.isArray(pattern.terms) || pattern.terms.length === 0) errors.push('terms must be a non-empty array');
        else if (pattern.terms.some(t => typeof t !== 'string' || !t.trim())) errors.push('every term must be a non-empty string');
        if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(pattern.severity)) errors.push('severity must be CRITICAL, HIGH, MEDIUM or LOW');
        const confidence = Number(pattern.confidence);
        if (!Number.isFinite(confidence) || confidence <= 0 || confidence > 1) errors.push('confidence must be a number greater than 0 and at most 1');
        if (!pattern.explanation || String(pattern.explanation).length < 10) errors.push('explanation is required so analysts understand why the signal fired');
        return errors;
    }

    /** Evaluates a declarative condition tree. No operator executes supplied code. */
    evaluate(node, ctx) {
        if (!node || typeof node !== 'object') return false;

        if (Array.isArray(node.all)) return node.all.every(child => this.evaluate(child, ctx));
        if (Array.isArray(node.any)) return node.any.some(child => this.evaluate(child, ctx));
        if (node.not) return !this.evaluate(node.not, ctx);

        const resolver = FIELDS[node.field];
        if (!resolver) return false;
        const actual = resolver(ctx);
        return this.applyOperator(node.op, actual, node.value);
    }

    applyOperator(op, actual, expected) {
        if (NUMBER_OPERATORS.has(op) && typeof actual === 'number') {
            const target = Number(expected);
            if (!Number.isFinite(target)) return false;
            switch (op) {
                case 'gt': return actual > target;
                case 'gte': return actual >= target;
                case 'lt': return actual < target;
                case 'lte': return actual <= target;
                case 'equals': return actual === target;
                case 'not_equals': return actual !== target;
                default: return false;
            }
        }

        if (LIST_OPERATORS.has(op)) {
            const list = asList(actual);
            const wanted = asList(expected);
            switch (op) {
                case 'includes_any': return wanted.some(w => list.includes(w));
                case 'includes_all': return wanted.every(w => list.includes(w));
                case 'not_includes_any': return !wanted.some(w => list.includes(w));
                default: return false;
            }
        }

        const text = asText(actual).toLowerCase();
        switch (op) {
            case 'equals': return text === asText(expected).toLowerCase();
            case 'not_equals': return text !== asText(expected).toLowerCase();
            case 'contains': return text.includes(asText(expected).toLowerCase());
            case 'not_contains': return !text.includes(asText(expected).toLowerCase());
            case 'contains_any': return asList(expected).some(v => text.includes(v));
            case 'contains_all': return asList(expected).every(v => text.includes(v));
            case 'starts_with': return text.startsWith(asText(expected).toLowerCase());
            case 'ends_with': return text.endsWith(asText(expected).toLowerCase());
            case 'matches_regex': {
                if (!isRegexSafe(expected)) return false;
                try {
                    return new RegExp(expected, 'i').test(text.slice(0, MAX_TEXT_FOR_REGEX));
                } catch (e) {
                    return false;
                }
            }
            default: return false;
        }
    }

    // ---------- management API ----------

    addRule(rule) {
        const errors = this.validateRule(rule);
        if (errors.length) return { ok: false, errors };
        if (this.rules.length >= MAX_RULES) return { ok: false, errors: [`Rule limit of ${MAX_RULES} reached`] };
        if (this.rules.some(r => r.id === rule.id)) return { ok: false, errors: [`A custom rule with id "${rule.id}" already exists`] };

        this.rules.push({ ...rule, created_at: new Date().toISOString() });
        this.save();
        return { ok: true, rule };
    }

    removeRule(id) {
        const before = this.rules.length;
        this.rules = this.rules.filter(r => r.id !== id);
        if (this.rules.length === before) return { ok: false, errors: [`No custom rule with id "${id}"`] };
        this.save();
        return { ok: true };
    }

    addNlpPattern(pattern) {
        const errors = this.validateNlpPattern(pattern);
        if (errors.length) return { ok: false, errors };
        if (this.nlpPatterns.length >= MAX_PATTERNS) return { ok: false, errors: [`Pattern limit of ${MAX_PATTERNS} reached`] };
        if (this.nlpPatterns.some(p => p.type === pattern.type)) return { ok: false, errors: [`A language pattern of type "${pattern.type}" already exists`] };

        this.nlpPatterns.push({ ...pattern, created_at: new Date().toISOString() });
        this.save();
        return { ok: true, pattern };
    }

    removeNlpPattern(type) {
        const before = this.nlpPatterns.length;
        this.nlpPatterns = this.nlpPatterns.filter(p => p.type !== type);
        if (this.nlpPatterns.length === before) return { ok: false, errors: [`No language pattern of type "${type}"`] };
        this.save();
        return { ok: true };
    }

    addIndicators({ urls = [], domains = [], ips = [] }) {
        const accepted = { urls: 0, domains: 0, ips: 0 };
        urls.filter(u => /^https?:\/\//i.test(u)).forEach(u => {
            if (!this.indicators.urls.includes(u)) { this.indicators.urls.push(u); accepted.urls++; }
        });
        domains.map(d => String(d).toLowerCase().trim()).filter(Boolean).forEach(d => {
            if (!this.indicators.domains.includes(d)) { this.indicators.domains.push(d); accepted.domains++; }
        });
        ips.filter(ip => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)).forEach(ip => {
            if (!this.indicators.ips.includes(ip)) { this.indicators.ips.push(ip); accepted.ips++; }
        });
        this.save();
        return { ok: true, accepted, totals: this.indicatorTotals() };
    }

    removeIndicator(value) {
        const target = String(value).toLowerCase();
        const before = this.indicatorTotals();
        this.indicators.urls = this.indicators.urls.filter(u => u.toLowerCase() !== target);
        this.indicators.domains = this.indicators.domains.filter(d => d !== target);
        this.indicators.ips = this.indicators.ips.filter(ip => ip !== target);
        this.save();
        const after = this.indicatorTotals();
        const removed = (before.urls + before.domains + before.ips) - (after.urls + after.domains + after.ips);
        return removed > 0 ? { ok: true } : { ok: false, errors: [`Indicator "${value}" not found`] };
    }

    indicatorTotals() {
        return { urls: this.indicators.urls.length, domains: this.indicators.domains.length, ips: this.indicators.ips.length };
    }

    getSchema() {
        return {
            fields: Object.keys(FIELDS),
            operators: {
                text: Array.from(STRING_OPERATORS),
                list: Array.from(LIST_OPERATORS),
                number: Array.from(NUMBER_OPERATORS)
            },
            severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            notes: [
                'Conditions combine with "all", "any" and "not" and may nest up to 5 levels.',
                'Conditions are declarative and are never executed as code.',
                'A source is required on every rule so custom detections stay as auditable as the built-in ones.',
                'Custom rules contribute evidence through the same fusion and scoring path as built-in rules; they cannot set a verdict directly.'
            ],
            example_rule: {
                id: 'CUSTOM-GIFTCARD-01',
                name: 'Gift card request from outside the organisation',
                severity: 'HIGH',
                confidence: 0.8,
                source: 'Internal threat brief, September 2026',
                description: 'Finance reported repeated gift-card requests from lookalike external senders.',
                conditions: {
                    all: [
                        { field: 'subject_and_body', op: 'contains_any', value: ['gift card', 'giftcard'] },
                        { field: 'sender_domain', op: 'not_equals', value: 'company.example' }
                    ]
                }
            },
            example_nlp_pattern: {
                type: 'CRYPTO_WALLET_LURE',
                severity: 'HIGH',
                confidence: 0.8,
                terms: ['seed phrase', 'wallet recovery', 'private key'],
                explanation: 'Requests for wallet recovery material are used to drain cryptocurrency accounts.',
                source: 'Operator-defined'
            }
        };
    }

    getAll() {
        return {
            mql_rules: this.rules,
            nlp_patterns: this.nlpPatterns,
            indicators: this.indicators,
            totals: {
                mql_rules: this.rules.length,
                nlp_patterns: this.nlpPatterns.length,
                indicators: this.indicatorTotals()
            },
            load_errors: this.loadErrors
        };
    }
}

module.exports = new CustomDetectionConfig();
