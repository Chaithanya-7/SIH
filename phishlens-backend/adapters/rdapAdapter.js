const fs = require('fs');
const path = require('path');
const https = require('https');

/**
 * Domain age via RDAP (RFC 7483 / RFC 9083), the IANA-bootstrapped successor
 * to WHOIS. It is a free, open, key-less registry protocol.
 *
 * Domain age is one of the strongest available phishing indicators: phishing
 * infrastructure is typically registered days or hours before use, while
 * organisations a message claims to be from have usually held their domain for
 * years.
 *
 * Results are cached on disk. A registration date never changes, so a domain is
 * looked up once and then answered locally forever, which keeps the registries
 * from being queried repeatedly and keeps analysis fast and offline-friendly.
 */
class RdapAdapter {
    constructor() {
        this.cacheFile = path.join(__dirname, '../data/domain_age_cache.json');
        this.cache = new Map();
        this.negativeTtlMs = 7 * 24 * 3600 * 1000;
        this.loadCache();
    }

    loadCache() {
        try {
            const dataDir = path.dirname(this.cacheFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.cacheFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8') || '[]');
            stored.forEach(entry => { if (entry.domain) this.cache.set(entry.domain, entry); });
            console.log(`[RDAP] Loaded cached registration data for ${this.cache.size} domain(s).`);
        } catch (e) {
            console.error('[RDAP] Cache load error:', e.message);
        }
    }

    saveCache() {
        try {
            // Bounded so a long-running deployment cannot grow this file without limit.
            const entries = Array.from(this.cache.values()).slice(-5000);
            fs.writeFileSync(this.cacheFile, JSON.stringify(entries));
        } catch (e) {
            console.error('[RDAP] Cache save error:', e.message);
        }
    }

    /** Reduces a hostname to the registrable domain RDAP will answer for. */
    registrableDomain(host) {
        if (!host) return null;
        const clean = host.toLowerCase().replace(/\.$/, '');
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return null;
        const parts = clean.split('.');
        if (parts.length < 2) return null;

        // Handles common two-label public suffixes (co.uk, com.au, co.in, ...).
        const twoLevel = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
        if (parts.length >= 3 && twoLevel.includes(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    }

    fetchRdap(domain, timeoutMs = 6000) {
        return new Promise((resolve, reject) => {
            const request = https.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
                headers: { 'User-Agent': 'PhishLens/1.0', 'Accept': 'application/rdap+json' },
                timeout: timeoutMs
            }, response => {
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    response.resume();
                    return this.fetchFromUrl(response.headers.location, timeoutMs).then(resolve, reject);
                }
                if (response.statusCode !== 200) {
                    response.resume();
                    return reject(new Error(`RDAP HTTP ${response.statusCode}`));
                }
                let body = '';
                response.setEncoding('utf8');
                response.on('data', c => { body += c; });
                response.on('end', () => {
                    try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('Malformed RDAP response')); }
                });
            });
            request.on('timeout', () => request.destroy(new Error('RDAP lookup timeout')));
            request.on('error', reject);
        });
    }

    fetchFromUrl(url, timeoutMs) {
        return new Promise((resolve, reject) => {
            const request = https.get(url, {
                headers: { 'User-Agent': 'PhishLens/1.0', 'Accept': 'application/rdap+json' },
                timeout: timeoutMs
            }, response => {
                if (response.statusCode !== 200) {
                    response.resume();
                    return reject(new Error(`RDAP HTTP ${response.statusCode}`));
                }
                let body = '';
                response.setEncoding('utf8');
                response.on('data', c => { body += c; });
                response.on('end', () => {
                    try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('Malformed RDAP response')); }
                });
            });
            request.on('timeout', () => request.destroy(new Error('RDAP lookup timeout')));
            request.on('error', reject);
        });
    }

    async lookupDomainAge(host) {
        const domain = this.registrableDomain(host);
        if (!domain) {
            return { status: 'NOT_APPLICABLE', domain: null, reason: 'Not a registrable domain name' };
        }

        const cached = this.cache.get(domain);
        if (cached) {
            if (cached.status === 'AVAILABLE') {
                return { ...cached, age_days: this.ageDays(cached.registered_at), cached: true };
            }
            if (Date.now() - new Date(cached.checked_at).getTime() < this.negativeTtlMs) {
                return { ...cached, cached: true };
            }
        }

        try {
            const rdap = await this.fetchRdap(domain);
            const registrationEvent = (rdap.events || []).find(e => e.eventAction === 'registration');
            if (!registrationEvent || !registrationEvent.eventDate) {
                const miss = { domain, status: 'UNAVAILABLE', reason: 'Registry returned no registration date', checked_at: new Date().toISOString() };
                this.cache.set(domain, miss);
                this.saveCache();
                return miss;
            }

            const entry = {
                domain,
                status: 'AVAILABLE',
                registered_at: registrationEvent.eventDate,
                source: 'RDAP',
                checked_at: new Date().toISOString()
            };
            this.cache.set(domain, entry);
            this.saveCache();
            return { ...entry, age_days: this.ageDays(entry.registered_at) };
        } catch (err) {
            const miss = { domain, status: 'UNAVAILABLE', reason: err.message, checked_at: new Date().toISOString() };
            this.cache.set(domain, miss);
            this.saveCache();
            return miss;
        }
    }

    ageDays(registeredAt) {
        const registered = new Date(registeredAt).getTime();
        if (!Number.isFinite(registered)) return null;
        return Math.floor((Date.now() - registered) / 86400000);
    }

    getStats() {
        return { domains_cached: this.cache.size };
    }
}

module.exports = new RdapAdapter();
