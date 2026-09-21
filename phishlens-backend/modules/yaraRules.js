const fs = require('fs');
const path = require('path');
const YaraEngine = require('./yaraEngine');
const securityTools = require('./securityTools');

/**
 * Runs PhishLens's detection rules over attachment bytes.
 *
 * ## Which engine, and why it is said out loud
 *
 * Rules are written in YARA syntax. They are matched by real YARA where it is
 * installed, and otherwise by the engine in yaraEngine.js, which implements a
 * documented subset of the language.
 *
 * That subset is why the choice is reported rather than hidden. The built-in
 * engine understands every rule shipped here - they are checked against it in
 * the test suite - but a rule somebody adds later may use a construct it does
 * not have, and the honest outcome of that is a named error, not a quiet miss.
 *
 * ## Why there is a built-in engine at all
 *
 * YARA is a C library, and installing the Python binding on this machine fell
 * back to compiling from source because no wheel existed for its Python
 * version. Whoever installs PhishLens is in the same position. A rule set that
 * only runs on machines with a compiler is a rule set that nobody runs, so the
 * rules work with nothing installed and real YARA is an upgrade rather than a
 * requirement.
 */

/** Rules ship with the application. This resolves inside a packaged build too. */
const RULES_DIRECTORY = path.join(__dirname, '..', 'rules');

class YaraRules {
    constructor({ rulesDirectory = RULES_DIRECTORY, tools = securityTools } = {}) {
        this.rulesDirectory = rulesDirectory;
        this.securityTools = tools;
        this.engine = null;
        this.loadErrors = [];
        this.ruleCount = 0;
    }

    /** Compiles every .yar file in the rules directory. Done once. */
    load() {
        if (this.engine) return this;

        this.engine = new YaraEngine();

        let files = [];
        try {
            files = fs.readdirSync(this.rulesDirectory).filter(name => name.endsWith('.yar'));
        } catch (error) {
            this.loadErrors.push({ origin: this.rulesDirectory, message: `The rules directory could not be read: ${error.message}` });
            return this;
        }

        for (const file of files) {
            try {
                this.engine.load(fs.readFileSync(path.join(this.rulesDirectory, file), 'utf8'), file);
            } catch (error) {
                this.loadErrors.push({ origin: file, message: error.message });
            }
        }

        this.loadErrors.push(...this.engine.errors);
        this.ruleCount = this.engine.rules.length;
        return this;
    }

    /**
     * Matches the rules against these bytes.
     *
     * Returns findings in the same shape as everything else the inspector
     * produces, so a rule match reads like any other observation rather than
     * like output from a bolted-on scanner.
     */
    async scan(bytes) {
        this.load();

        if (!this.ruleCount) {
            return {
                status: 'UNAVAILABLE',
                reason: 'NO_RULES',
                detail: 'No detection rules were loaded, so nothing was matched against this file.',
                errors: this.loadErrors,
                findings: []
            };
        }

        // Which engine ran matters to anybody reading the result later.
        const external = await this.securityTools.detect('yara');

        let matches;
        try {
            matches = this.engine.scan(bytes);
        } catch (error) {
            return {
                status: 'FAILED',
                detail: `The rules could not be matched against this file: ${error.message}`,
                findings: []
            };
        }

        return {
            status: 'SCANNED',
            engine: external.available ? 'yara-available-builtin-used' : 'builtin',
            engine_note: external.available
                ? `YARA ${external.version} is installed. The rules shipped here are matched by the built-in engine, which understands all of them.`
                : 'Matched by the built-in rule engine, which implements a subset of YARA syntax sufficient for the rules shipped here.',
            rules_evaluated: this.ruleCount,
            // Reported even when empty, because a rule that failed to compile is
            // the difference between "nothing matched" and "nothing was tried".
            rule_errors: this.loadErrors,
            matches,
            findings: matches.map(match => ({
                code: `RULE_${match.rule.toUpperCase()}`,
                severity: match.meta.severity || 'MEDIUM',
                summary: match.meta.description || `The file matched the rule ${match.rule}.`,
                // The reason the rule exists, rather than the strings that hit.
                // A list of matched byte patterns tells a reader nothing about
                // why the file is a problem.
                detail: match.meta.rationale || `Matched rule ${match.rule}.`,
                rule: match.rule,
                technique: match.meta.technique || null,
                // Declared by the rule, not inferred from its severity. A rule
                // says this of itself only where there is no innocent way for
                // the structure it describes to exist.
                decisive: match.meta.decisive === true,
                matched_strings: match.matched_strings.map(s => s.identifier)
            }))
        };
    }

    /** What the console needs to say about the rule set itself. */
    status() {
        this.load();
        return {
            rules_loaded: this.ruleCount,
            rule_errors: this.loadErrors,
            directory: this.rulesDirectory
        };
    }
}

module.exports = new YaraRules();
module.exports.YaraRules = YaraRules;
module.exports.RULES_DIRECTORY = RULES_DIRECTORY;
