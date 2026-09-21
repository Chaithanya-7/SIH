const { execFile } = require('child_process');
const fs = require('fs');

/**
 * Finds the open-source security tools this machine happens to have, and is
 * honest about the ones it does not.
 *
 * ## Why these are optional
 *
 * PhishLens is meant to cost nothing and to run entirely on the machine that
 * installed it. Every tool here satisfies that - all are open source, all run
 * locally, none report anywhere - but each is a separate install, and somebody
 * who wanted a phishing detector did not sign up to install four of them. So
 * none of this is required. Detection deepens where a tool is present and says
 * so plainly where it is not.
 *
 * ## The rule that matters
 *
 * A missing tool is reported as a missing tool. It is never reported as a clean
 * result. "No macros found" and "nothing capable of looking for macros is
 * installed" are opposite findings, and blurring them teaches people to trust a
 * silence that means nothing. Every capability carries the reason it is
 * unavailable, and callers pass that through rather than folding it into a
 * score.
 *
 * ## Looking in the right places
 *
 * PATH alone is not enough. The Wireshark installer puts tshark.exe in its own
 * program folder and leaves PATH untouched, so a PATH-only check calls a machine
 * that has Wireshark a machine that does not. Each tool therefore carries the
 * locations its own installer actually uses, and an explicit override wins over
 * both.
 */

/** Detection runs a fixed argument list with no shell, so nothing here can be injected into. */
const PROBE_TIMEOUT_MS = 5000;

const TOOLS = {
    tshark: {
        name: 'TShark (Wireshark)',
        license: 'GPL-2.0-or-later',
        // Described by what it adds to the pipeline rather than by what it is.
        capability: 'connection_telemetry',
        purpose: 'Reports whether this machine went on to connect to a host that a suspicious email pointed at.',
        limitation: 'Mail travels over TLS, so captured traffic cannot be read. Only connection metadata is available: host names, addresses, ports and timing.',
        commands: ['tshark'],
        // The Wireshark installer does not put itself on PATH on Windows.
        knownPaths: [
            'C:\\Program Files\\Wireshark\\tshark.exe',
            'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
            '/usr/bin/tshark',
            '/usr/local/bin/tshark',
            '/opt/homebrew/bin/tshark'
        ],
        versionArgs: ['--version'],
        versionPattern: /TShark[^\d]*(\d+\.\d+\.\d+)/i,
        installHint: 'Install Wireshark from wireshark.org with TShark included. Capturing also needs the Npcap driver and administrator rights.'
    },

    olevba: {
        name: 'oletools (olevba)',
        license: 'BSD-2-Clause',
        capability: 'macro_analysis',
        purpose: 'Extracts the macro code inside an Office attachment and reports what would run it automatically.',
        limitation: 'Reads Office documents only, and reports what the code says rather than what it would do if it ran.',
        // A Python module rather than an executable, so it is probed through the
        // interpreter. Not with --version: olevba has no such flag and exits 2 on
        // it, which reads exactly like the tool being absent. Importing the module
        // is also the better question, since that is what will actually be done
        // with it.
        pythonModule: 'oletools.olevba',
        distribution: 'oletools',
        installHint: 'pip install oletools'
    },

    yara: {
        name: 'YARA',
        license: 'BSD-3-Clause',
        capability: 'pattern_matching',
        purpose: 'Matches attachment and message content against named detection rules kept as plain text files.',
        limitation: 'Finds only what a rule describes. Rules are supplied locally and are never fetched from anywhere.',
        commands: ['yara'],
        knownPaths: [
            'C:\\Program Files\\YARA\\yara.exe',
            '/usr/bin/yara',
            '/usr/local/bin/yara',
            '/opt/homebrew/bin/yara'
        ],
        versionArgs: ['--version'],
        versionPattern: /(\d+\.\d+\.\d+)/,
        installHint: 'Install from virustotal.github.io/yara, or "pip install yara-python" for the library.'
    },

    clamscan: {
        name: 'ClamAV',
        license: 'GPL-2.0-only',
        capability: 'signature_scanning',
        purpose: 'Scans attachment bytes against a signature database kept on this machine.',
        limitation: 'Signatures find files that are already known. A document written for one campaign is in no database.',
        commands: ['clamscan'],
        knownPaths: [
            'C:\\Program Files\\ClamAV\\clamscan.exe',
            '/usr/bin/clamscan',
            '/usr/local/bin/clamscan',
            '/opt/homebrew/bin/clamscan'
        ],
        versionArgs: ['--version'],
        versionPattern: /ClamAV[^\d]*(\d+\.\d+\.\d+)/i,
        installHint: 'Install from clamav.net, then run freshclam once to fetch the signature database.'
    }
};

/** Python is not one of the security tools; it is how one of them is reached. */
const PYTHON_CANDIDATES = ['python3', 'python', 'py'];

/**
 * Asks Python whether a module is usable, and what version is installed.
 *
 * The import is the real question - a distribution can be recorded as installed
 * while its module fails to load - and the version is read from packaging
 * metadata, because where a module keeps its own __version__ varies. oletools,
 * for one, has none at the top level and one inside each submodule.
 */
function pythonProbeFor(spec) {
    return [
        `import ${spec.pythonModule}`,
        'import importlib.metadata as _meta',
        `print('PHISHLENS_TOOL_VERSION=' + _meta.version(${JSON.stringify(spec.distribution)}))`
    ].join('; ');
}

class SecurityTools {
    constructor() {
        /** Detection touches the filesystem and starts processes, so it is done once and kept. */
        this.cache = new Map();
        this.pythonPath = undefined;
    }

    /** Forget what was detected, so a tool installed while the app was running can be found. */
    reset() {
        this.cache.clear();
        this.pythonPath = undefined;
    }

    /** Runs a fixed argument list, never a shell string, and always gives up eventually. */
    run(file, args, { timeout = PROBE_TIMEOUT_MS, maxBuffer = 4 * 1024 * 1024 } = {}) {
        return new Promise(resolve => {
            execFile(file, args, { timeout, maxBuffer, shell: false, windowsHide: true }, (error, stdout, stderr) => {
                resolve({
                    ok: !error,
                    // A tool that prints its version to stderr is still a tool that is present.
                    output: `${stdout || ''}${stderr || ''}`,
                    error: error ? error.message : null
                });
            });
        });
    }

    /** An explicit path, set by whoever installed things, wins over anything guessed. */
    configuredPath(key) {
        const configured = process.env[`PHISHLENS_${key.toUpperCase()}_PATH`];
        return configured && fs.existsSync(configured) ? configured : null;
    }

    async findPython() {
        if (this.pythonPath !== undefined) return this.pythonPath;

        const configured = this.configuredPath('python');
        const candidates = configured ? [configured, ...PYTHON_CANDIDATES] : PYTHON_CANDIDATES;

        for (const candidate of candidates) {
            const probe = await this.run(candidate, ['--version']);
            // Windows ships stubs named python3 that exist, print nothing and exit
            // non-zero. Requiring the version text keeps those out.
            if (probe.ok && /Python \d/.test(probe.output)) {
                this.pythonPath = candidate;
                return candidate;
            }
        }

        this.pythonPath = null;
        return null;
    }

    /** Where a tool's program actually is, or null. */
    async locate(spec, key) {
        const configured = this.configuredPath(key);
        if (configured) return configured;

        for (const command of spec.commands || []) {
            const probe = await this.run(command, spec.versionArgs);
            if (probe.ok) return command;
        }

        for (const candidate of spec.knownPaths || []) {
            if (fs.existsSync(candidate)) return candidate;
        }

        return null;
    }

    /**
     * Is this tool available, and if not, why not?
     *
     * The negative answer carries its reason, because a caller that learns only
     * "false" has nothing useful to tell anybody.
     */
    async detect(key) {
        if (this.cache.has(key)) return this.cache.get(key);

        const spec = TOOLS[key];
        if (!spec) throw new Error(`No such tool: ${key}`);

        const result = await this.probe(key, spec);
        this.cache.set(key, result);
        return result;
    }

    async probe(key, spec) {
        const base = {
            key,
            name: spec.name,
            license: spec.license,
            capability: spec.capability,
            purpose: spec.purpose,
            limitation: spec.limitation,
            install_hint: spec.installHint
        };

        if (spec.pythonModule) {
            const python = await this.findPython();
            if (!python) {
                return { ...base, available: false, reason: 'NO_PYTHON', detail: 'No Python interpreter was found, and this tool runs as a Python module.' };
            }

            const probe = await this.run(python, ['-c', pythonProbeFor(spec)]);
            if (!probe.ok) {
                return { ...base, available: false, reason: 'NOT_INSTALLED', detail: `Python is present but the ${spec.name} module is not installed.` };
            }

            // Matched on a marker rather than on a loose version pattern. These
            // modules print deprecation warnings of their own, and a bare
            // three-number pattern happily matches one of those instead.
            const version = (/PHISHLENS_TOOL_VERSION=(\S+)/.exec(probe.output) || [])[1];

            return {
                ...base,
                available: true,
                version: version || 'unknown',
                invocation: { command: python, prefix: ['-m', spec.pythonModule] }
            };
        }

        const located = await this.locate(spec, key);
        if (!located) {
            return { ...base, available: false, reason: 'NOT_INSTALLED', detail: `${spec.name} was not found on PATH or in the locations its installer uses.` };
        }

        const probe = await this.run(located, spec.versionArgs);
        if (!probe.ok) {
            return { ...base, available: false, reason: 'NOT_RUNNABLE', detail: `${spec.name} was found at ${located} but would not run: ${probe.error}` };
        }

        return {
            ...base,
            available: true,
            version: (spec.versionPattern.exec(probe.output) || [])[1] || 'unknown',
            invocation: { command: located, prefix: [] }
        };
    }

    /** Every tool at once, for the console's own status panel. */
    async detectAll() {
        const tools = await Promise.all(Object.keys(TOOLS).map(key => this.detect(key)));
        const available = tools.filter(t => t.available);

        return {
            tools,
            summary: {
                available: available.length,
                total: tools.length,
                capabilities_present: available.map(t => t.capability),
                capabilities_absent: tools.filter(t => !t.available).map(t => t.capability),
                // Said in full, because "2 of 4" reads as detection being half
                // broken rather than as two optional depths being unopened.
                note: 'PhishLens analyses every message without any of these. Each one present adds a kind of evidence that the message alone cannot provide.'
            }
        };
    }
}

module.exports = new SecurityTools();
module.exports.SecurityTools = SecurityTools;
module.exports.TOOLS = TOOLS;
