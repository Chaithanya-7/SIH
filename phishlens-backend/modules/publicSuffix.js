const fs = require('fs');
const path = require('path');
const { domainToASCII } = require('url');
const { dataFile } = require('./dataPaths');

/**
 * Registrable-domain extraction using the Public Suffix List.
 *
 * This replaces a hand-rolled heuristic that got 7 of 10 test hosts wrong, and
 * got them wrong in the direction that matters. It treated any two trailing
 * labels as the registrable domain, with a hardcoded allowance for `co.uk` and
 * six similar cases. So `evil-bank-login.github.io` reduced to `github.io`, and
 * a domain-age lookup returned GitHub's registration date - sixteen years old,
 * thoroughly reputable - for a phishing page created that morning. The
 * newly-registered-domain signal could not fire on any free hosting platform:
 * github.io, pages.dev, workers.dev, web.app, netlify.app, blogspot.com. Those
 * are not obscure edge cases; they are where phishing pages actually live.
 *
 * The list is maintained by Mozilla with registry input and is the only
 * authoritative answer to "where does the registry boundary sit". There is no
 * pattern that derives it: `co.uk` is a public suffix and `co.com` is not, and
 * no amount of label counting will tell you which.
 *
 * Bundled as a file rather than fetched at analysis time - a detection decision
 * must not depend on a network call - and refreshable, because the list gains
 * entries as new platforms appear.
 */

const BUNDLED = path.join(__dirname, '..', 'reference', 'public_suffix_list.dat');

/** Any character outside the ASCII range - a label that needs punycode conversion. */
const NON_ASCII = new RegExp('[^' + String.fromCharCode(0) + '-' + String.fromCharCode(127) + ']');

class PublicSuffix {
    constructor() {
        /** Exact rules, wildcard rules and exception rules are matched differently. */
        this.rules = new Set();
        this.wildcards = new Set();
        this.exceptions = new Set();
        this.source = null;
        this.load();
    }

    load() {
        // An operator-refreshed copy wins over the bundled one, so the list can
        // be updated without reinstalling.
        const candidates = [dataFile('public_suffix_list.dat'), BUNDLED];
        for (const file of candidates) {
            try {
                if (!fs.existsSync(file)) continue;
                const text = fs.readFileSync(file, 'utf8');
                if (this.parse(text) > 0) {
                    this.source = file;
                    console.log(`[PublicSuffix] Loaded ${this.rules.size + this.wildcards.size + this.exceptions.size} rule(s) from ${path.basename(file)}.`);
                    return;
                }
            } catch (e) {
                console.error(`[PublicSuffix] Could not read ${file}: ${e.message}`);
            }
        }
        console.error('[PublicSuffix] No Public Suffix List available. Registrable-domain extraction will fall back to the last two labels, which is wrong for multi-label suffixes and for every free hosting platform.');
    }

    parse(text) {
        this.rules.clear();
        this.wildcards.clear();
        this.exceptions.clear();

        for (const raw of text.split(/\r?\n/)) {
            const line = raw.trim();
            if (!line || line.startsWith('//')) continue;

            // Stored in ASCII form. The list is published with unicode labels
            // (公司.cn), while hosts arrive from mail headers already in
            // punycode (xn--55qx5d.cn). Comparing the two directly fails, and
            // fails silently: the rule simply never matches and the host falls
            // back to its last two labels.
            if (line.startsWith('!')) {
                this.exceptions.add(this.toAscii(line.slice(1)));
            } else if (line.startsWith('*.')) {
                this.wildcards.add(this.toAscii(line.slice(2)));
            } else {
                this.rules.add(this.toAscii(line));
            }
        }
        return this.rules.size;
    }

    /**
     * Unicode labels to their punycode equivalent; ASCII input is returned
     * unchanged rather than round-tripped, because this runs for every label
     * of every host examined.
     */
    toAscii(value) {
        const lower = String(value).toLowerCase();
        if (!NON_ASCII.test(lower)) return lower;
        const converted = domainToASCII(lower);
        return converted || lower;
    }

    loaded() {
        return this.rules.size > 0;
    }

    /**
     * The public suffix of a host, per the algorithm in the list's own
     * specification: exception rules win outright; otherwise the longest
     * matching rule prevails; a wildcard matches exactly one label; and a host
     * matching no rule is treated as having the single-label rule `*`.
     */
    publicSuffix(host) {
        const labels = this.normalise(host);
        if (!labels) return null;

        // An exception rule removes the leftmost label from the suffix it names,
        // which is how a registrable domain is carved out of a wildcard suffix.
        for (let i = 0; i < labels.length; i++) {
            const candidate = labels.slice(i).join('.');
            if (this.exceptions.has(candidate)) {
                return labels.slice(i + 1).join('.');
            }
        }

        let longest = null;
        for (let i = 0; i < labels.length; i++) {
            const candidate = labels.slice(i).join('.');
            if (this.rules.has(candidate)) {
                longest = candidate;
                break; // Scanning left to right, the first hit is the longest.
            }
        }

        // A wildcard rule `*.foo` makes `<anything>.foo` a public suffix, so it
        // is checked against the parent of each candidate.
        for (let i = 0; i < labels.length - 1; i++) {
            const parent = labels.slice(i + 1).join('.');
            if (this.wildcards.has(parent)) {
                const candidate = labels.slice(i).join('.');
                if (!longest || candidate.split('.').length > longest.split('.').length) {
                    longest = candidate;
                }
                break;
            }
        }

        // No rule matched: the implicit `*` rule makes the rightmost label the
        // public suffix.
        return longest || labels[labels.length - 1];
    }

    /**
     * The public suffix plus one label - the part somebody actually registered.
     *
     * Returns null where there is nothing registrable: a bare public suffix, an
     * IP address, or a single label.
     */
    registrableDomain(host) {
        const labels = this.normalise(host);
        if (!labels) return null;

        if (!this.loaded()) {
            // Explicitly degraded rather than silently wrong: with no list, the
            // last two labels are the best available guess and the caller can
            // see from `loaded()` that it is a guess.
            return labels.length >= 2 ? labels.slice(-2).join('.') : null;
        }

        const suffix = this.publicSuffix(host);
        if (!suffix) return null;

        const suffixLabels = suffix.split('.').length;
        if (labels.length <= suffixLabels) return null; // the host *is* a public suffix

        return labels.slice(labels.length - suffixLabels - 1).join('.');
    }

    /** Whether the host sits directly under a public suffix anyone can register within. */
    isPublicSuffix(host) {
        const labels = this.normalise(host);
        if (!labels || !this.loaded()) return false;
        return this.publicSuffix(host) === labels.join('.');
    }

    normalise(host) {
        if (typeof host !== 'string') return null;
        const clean = host.trim().toLowerCase().replace(/\.$/, '');
        if (!clean || clean.includes(' ')) return null;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return null; // IPv4
        if (clean.includes(':')) return null;                    // IPv6
        // An empty label - a leading dot, or '..' - makes the host invalid.
        // Filtering empty labels out instead would quietly turn '.example.com'
        // into 'example.com' and answer a question that was never valid.
        const labels = clean.split('.');
        if (labels.length === 0 || labels.some(l => l.length === 0)) return null;
        return labels.map(l => this.toAscii(l));
    }

    /**
     * Refresh the list from its canonical location.
     *
     * The bundled copy stays correct for a long time - a public suffix is
     * rarely removed - but new platforms are added regularly, and a platform
     * missing from the list is exactly the blind spot this module exists to
     * close. Written to the data directory so the refreshed copy survives a
     * reinstall and takes precedence over the bundled one.
     *
     * A failed refresh keeps the existing list rather than clearing it: a stale
     * list is far better than none.
     */
    async refresh(url = 'https://publicsuffix.org/list/public_suffix_list.dat') {
        const https = require('https');
        try {
            const text = await new Promise((resolve, reject) => {
                const request = https.get(url, { headers: { 'User-Agent': 'PhishLens/1.0' }, timeout: 30000 }, response => {
                    if (response.statusCode !== 200) {
                        response.resume();
                        return reject(new Error(`HTTP ${response.statusCode}`));
                    }
                    let body = '';
                    response.setEncoding('utf8');
                    response.on('data', c => { body += c; });
                    response.on('end', () => resolve(body));
                });
                request.on('timeout', () => request.destroy(new Error('timeout')));
                request.on('error', reject);
            });

            // Sanity-checked before it replaces a working list. A truncated
            // download or an error page would otherwise silently disable
            // registrable-domain extraction for every host.
            if (!/^\/\/ ===BEGIN ICANN DOMAINS===/m.test(text) || text.length < 100000) {
                throw new Error('the downloaded list does not look like the Public Suffix List');
            }

            const target = dataFile('public_suffix_list.dat');
            fs.writeFileSync(target, text, 'utf8');
            this.parse(text);
            this.source = target;
            return { ok: true, rules: this.rules.size, source: target };
        } catch (e) {
            console.error(`[PublicSuffix] Refresh failed, keeping the existing list: ${e.message}`);
            return { ok: false, error: e.message, rules: this.rules.size };
        }
    }

    state() {
        return {
            loaded: this.loaded(),
            source: this.source,
            rules: this.rules.size,
            wildcard_rules: this.wildcards.size,
            exception_rules: this.exceptions.size
        };
    }
}

module.exports = new PublicSuffix();
