const fs = require('fs');
const path = require('path');
const https = require('https');
const { dataFile } = require('./dataPaths');

/**
 * Local threat-intelligence store.
 *
 * Open indicator feeds are downloaded, normalised and indexed on this machine.
 * Every lookup afterwards is an in-memory hit against that local index.
 *
 * This is deliberately not a per-message reputation API client:
 *
 *  - Free and key-less. The feeds below are public downloads. Nothing here
 *    requires an account, an API key, or a paid tier.
 *  - Private. Querying a hosted reputation service would mean sending the
 *    domains, URLs and addresses found in the operator's own mail to a third
 *    party, one message at a time. Downloading the list instead and matching
 *    locally reveals nothing about what mail this installation receives.
 *  - Offline-capable. Once synced, detection keeps working with no network at
 *    all, and with no rate limit to exhaust.
 *  - Self-hosted. The indicators live in this installation's own data
 *    directory. No PhishLens-operated server is involved at any point.
 *
 * Feed licences differ and are recorded per feed below, and reported through
 * the status endpoint, so an operator can make an informed decision before
 * deploying commercially rather than discovering the terms later.
 */

/**
 * Splits one CSV line, honouring double-quoted fields.
 *
 * Needed because a phishing URL routinely contains a comma inside a quoted
 * field, and splitting on commas alone silently truncates the URL - producing
 * an indicator that matches nothing and looks like a working feed.
 */
function splitCsvLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
            if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
            else inQuotes = !inQuotes;
        } else if (ch === ',' && !inQuotes) {
            fields.push(current);
            current = '';
        } else {
            current += ch;
        }
    }
    fields.push(current);
    return fields;
}

const FEEDS = [
    {
        id: 'urlhaus',
        name: 'abuse.ch URLhaus (recent malicious URLs)',
        url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        indicator: 'url',
        licence: 'abuse.ch Terms of Use - https://urlhaus.abuse.ch/api/',
        enabledByDefault: true,
        parse: (text) => {
            const urls = [];
            for (const line of text.split(/\r?\n/)) {
                if (!line || line.startsWith('#')) continue;
                // "id","dateadded","url","url_status",...
                const fields = line.split('","');
                if (fields.length < 3) continue;
                const url = fields[2];
                if (url && /^https?:\/\//i.test(url)) urls.push(url);
            }
            return urls;
        }
    },
    {
        id: 'openphish',
        name: 'OpenPhish community phishing feed',
        url: 'https://openphish.com/feed.txt',
        indicator: 'url',
        licence: 'OpenPhish community feed - free for personal/research use; review terms before commercial deployment - https://openphish.com/terms.html',
        enabledByDefault: true,
        parse: (text) => text.split(/\r?\n/).map(l => l.trim()).filter(l => /^https?:\/\//i.test(l))
    },
    {
        id: 'phishtank',
        name: 'PhishTank verified phishing URLs',
        // Reachable without a key. An earlier version of this entry gated it
        // behind PHISHTANK_API_KEY on the strength of a 429 seen during
        // testing - that was rate limiting from three requests in a row, not an
        // authentication requirement. Checked properly: the keyless URL
        // redirects to a signed CDN link and returns the full verified set
        // (14 MB, ~76,000 URLs), and three spaced requests all succeeded.
        //
        // A key still helps, because it raises the rate limit rather than
        // unlocking the data, so it is used when present and not required.
        url: 'https://data.phishtank.com/data/online-valid.csv',
        keyedUrl: 'https://data.phishtank.com/data/{key}/online-valid.csv',
        optionalKey: 'PHISHTANK_API_KEY',
        indicator: 'url',
        licence: 'PhishTank - free to use; registration raises rate limits. Review terms before commercial deployment - https://phishtank.org/api_info.php',
        enabledByDefault: true,
        // This feed is large and aggressively rate limited, so it is fetched
        // far less often than the others. Asking for 14 MB every sync would
        // earn a 429 and gain nothing: the set does not turn over minute to
        // minute.
        minimumIntervalMinutes: 360,
        parse: (text) => {
            const urls = [];
            const lines = text.split(/\r?\n/);
            // phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
            for (let i = 1; i < lines.length; i++) {
                const fields = splitCsvLine(lines[i]);
                const url = fields[1];
                const online = (fields[6] || '').trim().toLowerCase();
                // Only what PhishTank still considers live. A verified-then-
                // taken-down URL is history, not a current indicator, and
                // treating it as one is how a feed starts firing on recycled
                // hosting.
                if (url && /^https?:\/\//i.test(url) && online !== 'no') urls.push(url);
            }
            return urls;
        }
    },
    {
        id: 'feodo',
        name: 'abuse.ch Feodo Tracker botnet C2 IPs',
        url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        indicator: 'ip',
        licence: 'abuse.ch Terms of Use - https://feodotracker.abuse.ch/blocklist/',
        enabledByDefault: true,
        parse: (text) => text.split(/\r?\n/).map(l => l.trim()).filter(l => /^\d{1,3}(\.\d{1,3}){3}$/.test(l))
    },
    {
        id: 'threatfox',
        name: 'abuse.ch ThreatFox (recent IOCs)',
        url: 'https://threatfox.abuse.ch/export/csv/recent/',
        indicator: 'mixed',
        licence: 'abuse.ch Terms of Use - https://threatfox.abuse.ch/faq/#tos',
        enabledByDefault: true,
        parse: (text) => {
            const out = [];
            for (const line of text.split(/\r?\n/)) {
                if (!line || line.startsWith('#')) continue;
                const fields = line.split(',').map(f => f.trim().replace(/^"|"$/g, ''));
                if (fields.length < 4) continue;
                const value = fields[2];
                const type = fields[3];
                if (!value) continue;
                if (type === 'domain') out.push({ kind: 'domain', value: value.toLowerCase() });
                else if (type === 'url') out.push({ kind: 'url', value });
                else if (type === 'ip:port') {
                    const ip = value.split(':')[0];
                    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) out.push({ kind: 'ip', value: ip });
                }
            }
            return out;
        }
    },
    {
        id: 'spamhaus_drop',
        name: 'Spamhaus DROP (hijacked / rogue netblocks)',
        url: 'https://www.spamhaus.org/drop/drop.txt',
        indicator: 'cidr',
        licence: 'The Spamhaus Project - free use for network operators - https://www.spamhaus.org/drop/',
        enabledByDefault: true,
        parse: (text) => {
            const cidrs = [];
            for (const line of text.split(/\r?\n/)) {
                if (!line || line.startsWith(';')) continue;
                const cidr = line.split(';')[0].trim();
                if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(cidr)) cidrs.push(cidr);
            }
            return cidrs;
        }
    }
];

/**
 * Multi-tenant platforms that host content for anyone.
 *
 * URL feeds legitimately list malicious content hosted on these services, but
 * the malicious party controls a path, not the host. Indexing the host would
 * condemn the entire platform and flag every message linking to Google Drive,
 * GitHub or a Discord CDN attachment - a false positive severe enough to make
 * the whole threat-intelligence signal useless.
 *
 * Exact URLs on these hosts are still matched. Attacker-controlled subdomains
 * (for example a lookalike login page on a site builder) are distinct
 * hostnames and remain indexed normally.
 */
const MULTI_TENANT_HOSTS = new Set([
    'github.com', 'raw.githubusercontent.com', 'gist.github.com', 'objects.githubusercontent.com',
    'gitlab.com', 'bitbucket.org',
    'drive.google.com', 'docs.google.com', 'sites.google.com', 'storage.googleapis.com',
    'firebasestorage.googleapis.com', 'script.google.com', 'forms.gle', 'goo.gl',
    'dropbox.com', 'www.dropbox.com', 'dl.dropboxusercontent.com',
    'onedrive.live.com', '1drv.ms', 'sharepoint.com', 'blob.core.windows.net',
    'discord.com', 'cdn.discordapp.com', 'media.discordapp.net',
    's3.amazonaws.com', 'amazonaws.com', 'mediafire.com', 'wetransfer.com',
    'pastebin.com', 'archive.org', 'web.archive.org',
    't.me', 'telegram.org', 'telegra.ph',
    'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'youtube.com',
    'imgur.com', 'i.imgur.com', 'cloudfront.net', 'akamaihd.net'
]);

function ipv4ToLong(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function hostOf(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch (e) {
        return null;
    }
}

class ThreatIntelStore {
    constructor() {
        this.storageFile = dataFile('threat_intel.json');
        this.urls = new Set();
        /** Hosts observed serving malicious/phishing content, from URL feeds. */
        this.urlHosts = new Map();
        this.domains = new Map();
        this.ips = new Map();
        this.cidrs = [];
        this.feedStatus = {};
        this.lastSync = null;
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.storageFile)) return;

            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '{}');
            (stored.urls || []).forEach(u => this.urls.add(u));
            (stored.url_hosts || []).forEach(([host, feed]) => this.urlHosts.set(host, feed));
            (stored.domains || []).forEach(([d, feed]) => this.domains.set(d, feed));
            (stored.ips || []).forEach(([ip, feed]) => this.ips.set(ip, feed));
            this.cidrs = stored.cidrs || [];
            this.feedStatus = stored.feed_status || {};
            this.lastSync = stored.last_sync || null;

            console.log(`[ThreatIntel] Loaded local indicator set: ${this.urls.size} URL(s), ${this.urlHosts.size} host(s), ${this.domains.size} domain(s), ${this.ips.size} IP(s), ${this.cidrs.length} netblock(s). Last sync: ${this.lastSync || 'never'}.`);
        } catch (e) {
            console.error('[ThreatIntel] Local indicator load error:', e.message);
        }
    }

    saveStorage() {
        try {
            const payload = {
                last_sync: this.lastSync,
                feed_status: this.feedStatus,
                urls: Array.from(this.urls),
                url_hosts: Array.from(this.urlHosts.entries()),
                domains: Array.from(this.domains.entries()),
                ips: Array.from(this.ips.entries()),
                cidrs: this.cidrs
            };
            fs.writeFileSync(this.storageFile, JSON.stringify(payload));
        } catch (e) {
            console.error('[ThreatIntel] Local indicator save error:', e.message);
        }
    }

    download(url, timeoutMs = 30000) {
        return new Promise((resolve, reject) => {
            const request = https.get(url, {
                headers: { 'User-Agent': 'PhishLens/1.0 (local threat intelligence sync)' },
                timeout: timeoutMs
            }, response => {
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    response.resume();
                    return this.download(response.headers.location, timeoutMs).then(resolve, reject);
                }
                if (response.statusCode !== 200) {
                    response.resume();
                    return reject(new Error(`HTTP ${response.statusCode}`));
                }
                let body = '';
                response.setEncoding('utf8');
                response.on('data', chunk => { body += chunk; });
                response.on('end', () => resolve(body));
            });

            request.on('timeout', () => request.destroy(new Error('Feed download timeout')));
            request.on('error', reject);
        });
    }

    enabledFeeds() {
        const disabled = (process.env.THREAT_INTEL_DISABLED_FEEDS || '')
            .split(',').map(s => s.trim()).filter(Boolean);

        return FEEDS.filter(feed => {
            if (disabled.includes(feed.id)) return false;
            // A key-gated feed switches itself on once the operator supplies the
            // key, and stays off otherwise. Fetching it without one returns an
            // error page that parses to zero indicators, which looks
            // indistinguishable from a quiet day.
            if (feed.requiresKey) return !!process.env[feed.requiresKey];
            return feed.enabledByDefault;
        });
    }

    /**
     * The URL to fetch. A required key is substituted; an optional one switches
     * to the keyed form only when it is actually set, so the feed keeps working
     * without it.
     */
    feedUrl(feed) {
        if (feed.requiresKey) {
            return feed.url.replace('{key}', encodeURIComponent(process.env[feed.requiresKey] || ''));
        }
        if (feed.optionalKey && process.env[feed.optionalKey] && feed.keyedUrl) {
            return feed.keyedUrl.replace('{key}', encodeURIComponent(process.env[feed.optionalKey]));
        }
        return feed.url;
    }

    /**
     * Whether enough time has passed to fetch this feed again.
     *
     * Only large, rate-limited feeds declare an interval. Requesting 14 MB on
     * every sync earns a 429 and gains nothing, because the set does not turn
     * over minute to minute.
     */
    dueForSync(feed) {
        if (!feed.minimumIntervalMinutes) return true;
        const last = this.lastFeedSync?.[feed.id];
        if (!last) return true;
        return (Date.now() - new Date(last).getTime()) >= feed.minimumIntervalMinutes * 60 * 1000;
    }

    /**
     * Refreshes the local indicator set. A feed that fails is recorded as
     * failed and the previously synced indicators are kept: stale intelligence
     * is more useful than none, provided its age is reported honestly.
     */
    async sync() {
        console.log('[ThreatIntel] Synchronising open indicator feeds to local store...');
        const results = [];

        this.lastFeedSync = this.lastFeedSync || {};

        for (const feed of this.enabledFeeds()) {
            if (!this.dueForSync(feed)) {
                results.push({ feed: feed.id, status: 'SKIPPED_NOT_DUE', detail: `Fetched less than ${feed.minimumIntervalMinutes} minutes ago; the previously synced indicators are still in use.` });
                continue;
            }
            try {
                const body = await this.download(this.feedUrl(feed));
                this.lastFeedSync[feed.id] = new Date().toISOString();
                const parsed = feed.parse(body);
                let added = 0;

                parsed.forEach(entry => {
                    if (typeof entry === 'string') {
                        if (feed.indicator === 'url') {
                            this.urls.add(entry);
                            const host = hostOf(entry);
                            if (host && !MULTI_TENANT_HOSTS.has(host)) this.urlHosts.set(host, feed.id);
                            added++;
                        } else if (feed.indicator === 'ip') {
                            this.ips.set(entry, feed.id);
                            added++;
                        } else if (feed.indicator === 'cidr') {
                            if (!this.cidrs.find(c => c.cidr === entry)) {
                                this.cidrs.push({ cidr: entry, feed: feed.id });
                            }
                            added++;
                        }
                    } else if (entry && entry.kind) {
                        if (entry.kind === 'url') {
                            this.urls.add(entry.value);
                            const host = hostOf(entry.value);
                            if (host && !MULTI_TENANT_HOSTS.has(host)) this.urlHosts.set(host, feed.id);
                        } else if (entry.kind === 'domain') {
                            if (!MULTI_TENANT_HOSTS.has(entry.value)) this.domains.set(entry.value, feed.id);
                        } else if (entry.kind === 'ip') {
                            this.ips.set(entry.value, feed.id);
                        }
                        added++;
                    }
                });

                this.feedStatus[feed.id] = {
                    name: feed.name,
                    licence: feed.licence,
                    status: 'SYNCED',
                    indicators: added,
                    synced_at: new Date().toISOString()
                };
                results.push({ feed: feed.id, status: 'SYNCED', indicators: added });
                console.log(`[ThreatIntel]   ${feed.id}: ${added} indicator(s)`);
            } catch (err) {
                const previous = this.feedStatus[feed.id];
                this.feedStatus[feed.id] = {
                    name: feed.name,
                    licence: feed.licence,
                    status: 'FAILED',
                    error: err.message,
                    indicators: previous ? previous.indicators : 0,
                    synced_at: previous ? previous.synced_at : null
                };
                results.push({ feed: feed.id, status: 'FAILED', error: err.message });
                console.warn(`[ThreatIntel]   ${feed.id}: FAILED (${err.message}) - previously synced indicators retained`);
            }
        }

        this.lastSync = new Date().toISOString();
        this.saveStorage();
        return { synced_at: this.lastSync, feeds: results, totals: this.counts() };
    }

    counts() {
        return {
            urls: this.urls.size,
            url_hosts: this.urlHosts.size,
            domains: this.domains.size,
            ips: this.ips.size,
            netblocks: this.cidrs.length
        };
    }

    isSynced() {
        return !!this.lastSync && (this.urls.size + this.domains.size + this.ips.size + this.cidrs.length) > 0;
    }

    ageHours() {
        if (!this.lastSync) return null;
        return (Date.now() - new Date(this.lastSync).getTime()) / 3600000;
    }

    /**
     * Exact URL match first, then the weaker but far more durable host match -
     * attackers rotate paths much more readily than hosts.
     *
     * Multi-tenant platforms are excluded from host-level matching even if an
     * index built by an earlier version contains them, so the guard holds
     * without requiring a re-sync.
     */
    lookupUrl(url) {
        // Operator-supplied indicators are authoritative for this deployment and
        // are checked before, and independently of, the downloaded feeds - they
        // work even when no feed has ever been synchronised.
        const operatorHit = this.lookupOperatorIndicator(url, 'url');
        if (operatorHit) return operatorHit;

        if (!this.isSynced()) return null;
        if (this.urls.has(url)) {
            return { matched: 'EXACT_URL', indicator: url, feed: this.feedForUrl(url) };
        }
        const host = hostOf(url);
        if (!host || MULTI_TENANT_HOSTS.has(host)) return null;

        if (this.urlHosts.has(host)) {
            return { matched: 'URL_HOST', indicator: host, feed: this.urlHosts.get(host) };
        }
        if (this.domains.has(host)) {
            return { matched: 'DOMAIN', indicator: host, feed: this.domains.get(host) };
        }
        return null;
    }

    /** Checks the operator's own indicator lists, which always take effect. */
    lookupOperatorIndicator(value, kind) {
        const custom = require('./customDetectionConfig').indicators;
        if (kind === 'url') {
            if (custom.urls.includes(value)) {
                return { matched: 'EXACT_URL', indicator: value, feed: 'operator_defined' };
            }
            const host = hostOf(value);
            if (host && custom.domains.includes(host)) {
                return { matched: 'DOMAIN', indicator: host, feed: 'operator_defined' };
            }
            return null;
        }
        if (kind === 'domain' && custom.domains.includes(String(value).toLowerCase())) {
            return { matched: 'DOMAIN', indicator: value, feed: 'operator_defined' };
        }
        if (kind === 'ip' && custom.ips.includes(value)) {
            return { matched: 'IP', indicator: value, feed: 'operator_defined' };
        }
        return null;
    }

    feedForUrl(url) {
        const host = hostOf(url);
        return (host && this.urlHosts.get(host)) || 'urlhaus';
    }

    lookupDomain(domain) {
        if (!domain) return null;
        const operatorHit = this.lookupOperatorIndicator(domain, 'domain');
        if (operatorHit) return operatorHit;

        if (!this.isSynced()) return null;
        const key = domain.toLowerCase();
        if (MULTI_TENANT_HOSTS.has(key)) return null;
        if (this.domains.has(key)) return { matched: 'DOMAIN', indicator: key, feed: this.domains.get(key) };
        if (this.urlHosts.has(key)) return { matched: 'URL_HOST', indicator: key, feed: this.urlHosts.get(key) };
        return null;
    }

    lookupIp(ip) {
        if (!ip) return null;
        const operatorHit = this.lookupOperatorIndicator(ip, 'ip');
        if (operatorHit) return operatorHit;

        if (!this.isSynced()) return null;
        if (this.ips.has(ip)) return { matched: 'IP', indicator: ip, feed: this.ips.get(ip) };

        const asLong = ipv4ToLong(ip);
        if (asLong === null) return null;
        for (const entry of this.cidrs) {
            const [base, bitsRaw] = entry.cidr.split('/');
            const bits = parseInt(bitsRaw, 10);
            const baseLong = ipv4ToLong(base);
            if (baseLong === null || !Number.isInteger(bits)) continue;
            const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
            if ((asLong & mask) >>> 0 === (baseLong & mask) >>> 0) {
                return { matched: 'NETBLOCK', indicator: entry.cidr, feed: entry.feed };
            }
        }
        return null;
    }

    getStatus() {
        return {
            synced: this.isSynced(),
            last_sync: this.lastSync,
            age_hours: this.ageHours() === null ? null : Number(this.ageHours().toFixed(1)),
            totals: this.counts(),
            feeds: this.feedStatus,
            model: 'Indicator feeds are downloaded and matched locally. No indicator from your mail is ever sent to a third-party reputation service, and no PhishLens-operated server is involved.',
            limitation: this.isSynced()
                ? 'Feed coverage is a snapshot. Absence from these lists is not evidence that an indicator is safe.'
                : 'No indicator feed has been synchronised yet, so threat-intelligence matching contributes nothing. Run a sync to enable it.'
        };
    }

    availableFeeds() {
        return FEEDS.map(f => ({
            id: f.id,
            name: f.name,
            indicator: f.indicator,
            licence: f.licence,
            enabled_by_default: f.enabledByDefault,
            requires_key: f.requiresKey || null,
            optional_key: f.optionalKey || null,
            key_present: (f.requiresKey || f.optionalKey) ? !!process.env[f.requiresKey || f.optionalKey] : null,
            minimum_interval_minutes: f.minimumIntervalMinutes || null,
            // Stated so a feed that is off is visibly off, rather than simply
            // contributing nothing and looking like a feed with no hits.
            active: f.requiresKey ? !!process.env[f.requiresKey] : f.enabledByDefault,
            key_hint: f.keyHint || (f.optionalKey ? `Optional: setting ${f.optionalKey} raises PhishTank's rate limit. The feed works without it.` : null)
        }));
    }
}

module.exports = new ThreatIntelStore();
