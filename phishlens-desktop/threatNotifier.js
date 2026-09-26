const { Notification } = require('electron');
const fs = require('fs');
const path = require('path');
const http = require('http');

/**
 * Tells the person using this machine, on this machine, that something arrived.
 *
 * ## Why this exists
 *
 * Notification previously meant one thing: an HTTP POST to a webhook, if an
 * operator had configured `SOC_WEBHOOK_URL`. That is the right mechanism for a
 * security team with somewhere to send alerts, and it does nothing at all for a
 * person who installed this on their own laptop to watch their own mail - which
 * is most of the people who will run it.
 *
 * For them a verdict that nobody is told about might as well not exist. They
 * would have to open the console and look, which means the tool only works when
 * somebody is already worried.
 *
 * ## What it will not do
 *
 * **It never says a message is safe.** Only high-risk and suspicious verdicts
 * raise anything. A notification reading "this email is fine" would train
 * somebody to trust the absence of one, and the absence of one also happens when
 * the backend is down, the poll failed, or the message never reached the system.
 *
 * **It never shows the message body.** The subject and the sender, which the
 * person can already see in their mail client, and nothing more. A notification
 * is rendered by the operating system, may be logged by it, and can appear on a
 * lock screen in front of whoever is standing there.
 *
 * **It does not notify about old mail.** A backlog scan can produce hundreds of
 * verdicts about messages from years ago in a single afternoon. Every one of
 * them would be a toast about something long since dealt with, and the result is
 * that all notifications get switched off - so historical cases are skipped
 * entirely, and a burst of live ones is summarised into one rather than fired
 * individually.
 */

/** How often the backend is asked for new verdicts. */
const POLL_MS = 20 * 1000;

/** More than this in one poll is summarised rather than fired one by one. */
const BURST_THRESHOLD = 3;

/** Nothing older than this raises a notification, however new the case is to us. */
const MAX_MESSAGE_AGE_MS = 6 * 60 * 60 * 1000;

const NOTIFY_VERDICTS = new Set(['HIGH_RISK', 'SUSPICIOUS']);

class ThreatNotifier {
    /**
     * @param supervisor   the backend supervisor, for its base URL and API key
     * @param options.dataDir  where the high-water mark is kept
     * @param options.onOpenCase  called with a case id when a notification is clicked
     * @param options.log  where to record what happened
     */
    constructor(supervisor, { dataDir, onOpenCase = () => {}, log = () => {} } = {}) {
        this.supervisor = supervisor;
        this.onOpenCase = onOpenCase;
        this.log = log;
        this.stateFile = dataDir ? path.join(dataDir, 'notified-cases.json') : null;

        this.timer = null;
        /** Case ids already notified about, so a restart is not a second round. */
        this.notified = new Set();
        this.lastError = null;
        this.raised = 0;

        this.load();
    }

    load() {
        if (!this.stateFile) return;
        try {
            if (!fs.existsSync(this.stateFile)) return;
            const stored = JSON.parse(fs.readFileSync(this.stateFile, 'utf8') || '{}');
            (stored.notified || []).forEach(id => this.notified.add(id));
        } catch (e) {
            // A lost high-water mark costs one duplicate round, not correctness.
            this.log(`[Notifier] Could not read notification state: ${e.message}`);
        }
    }

    save() {
        if (!this.stateFile) return;
        try {
            // Bounded: only the most recent matter, and the list would otherwise
            // grow for the life of the install.
            const recent = Array.from(this.notified).slice(-2000);
            this.notified = new Set(recent);
            fs.writeFileSync(this.stateFile, JSON.stringify({ notified: recent, saved_at: new Date().toISOString() }, null, 2));
        } catch (e) {
            this.log(`[Notifier] Could not write notification state: ${e.message}`);
        }
    }

    start() {
        if (this.timer) return;
        if (!Notification.isSupported()) {
            this.log('[Notifier] This system does not support notifications; nothing will be raised.');
            return;
        }
        // First pass deferred: at startup the backend is usually still coming up,
        // and a failed poll in the first second is not worth recording as an error.
        this.timer = setInterval(() => this.poll(), POLL_MS);
        if (this.timer.unref) this.timer.unref();
        setTimeout(() => this.poll(), 8000);
        this.log('[Notifier] Watching for high-risk and suspicious verdicts.');
    }

    stop() {
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
    }

    /** A plain GET against the local backend, with the key the supervisor holds. */
    request(routePath) {
        return new Promise((resolve, reject) => {
            let url;
            try {
                url = new URL(routePath, this.supervisor.baseUrl);
            } catch (e) {
                return reject(new Error(`Bad backend URL: ${e.message}`));
            }

            const req = http.get({
                hostname: url.hostname,
                port: url.port,
                path: url.pathname + url.search,
                headers: { 'x-api-key': this.supervisor.apiKey || '' },
                timeout: 8000
            }, res => {
                let body = '';
                res.on('data', chunk => { body += chunk; });
                res.on('end', () => {
                    if (res.statusCode !== 200) return reject(new Error(`Backend answered ${res.statusCode}`));
                    try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('The backend did not return JSON.')); }
                });
            });

            req.on('timeout', () => { req.destroy(new Error('The backend did not answer in time.')); });
            req.on('error', reject);
        });
    }

    async poll() {
        try {
            const answer = await this.request('/api/cases');
            const cases = answer?.cases || [];
            this.lastError = null;

            const fresh = cases.filter(item => this.shouldNotify(item));
            if (!fresh.length) return;

            // Newest last, so a summary names the most recent.
            fresh.sort((a, b) => Date.parse(a.timestamps?.ingested_at || 0) - Date.parse(b.timestamps?.ingested_at || 0));

            if (fresh.length > BURST_THRESHOLD) {
                this.raiseSummary(fresh);
            } else {
                fresh.forEach(item => this.raiseOne(item));
            }

            fresh.forEach(item => this.notified.add(item.case_id));
            this.save();
        } catch (err) {
            // A backend that is restarting must not fill the log with one error
            // every twenty seconds, so only a change of error is recorded.
            if (this.lastError !== err.message) {
                this.lastError = err.message;
                this.log(`[Notifier] Could not read verdicts: ${err.message}`);
            }
        }
    }

    shouldNotify(item) {
        if (!item?.case_id || this.notified.has(item.case_id)) return false;
        if (!NOTIFY_VERDICTS.has(item.detection?.verdict)) return false;

        // A backlog scan produces verdicts about mail from years ago. Each one
        // would be a toast about something long since dealt with.
        if (item.analysis_mode?.mode === 'HISTORICAL') return false;

        // And a case about a genuinely old message is not news either, however
        // new the case is to this installation.
        const at = Date.parse(item.message?.delivered_at || item.timestamps?.ingested_at || '');
        if (Number.isFinite(at) && Date.now() - at > MAX_MESSAGE_AGE_MS) return false;

        return true;
    }

    /** Only what the person can already see in their own mail client. */
    raiseOne(item) {
        const high = item.detection?.verdict === 'HIGH_RISK';
        const confidence = Math.round((item.confidence?.threat ?? 0) * 100);
        const reason = this.topFinding(item);

        const notification = new Notification({
            title: high ? 'PhishLens: dangerous email' : 'PhishLens: suspicious email',
            body: [
                this.trim(item.message?.subject || '(no subject)', 90),
                `From ${this.trim(item.message?.sender || 'unknown sender', 70)}`,
                reason ? `${reason} (${confidence}% confident)` : `${confidence}% confident`,
                'Do not act on it before opening the case.'
            ].join('\n'),
            urgency: high ? 'critical' : 'normal',
            timeoutType: high ? 'never' : 'default'
        });

        notification.on('click', () => this.onOpenCase(item.case_id));
        notification.show();
        this.raised += 1;
    }

    raiseSummary(items) {
        const high = items.filter(i => i.detection?.verdict === 'HIGH_RISK').length;
        const notification = new Notification({
            title: `PhishLens: ${items.length} messages need attention`,
            body: [
                high ? `${high} dangerous, ${items.length - high} suspicious.` : `${items.length} suspicious.`,
                `Most recent: ${this.trim(items[items.length - 1].message?.subject || '(no subject)', 80)}`,
                'Open PhishLens to review them.'
            ].join('\n'),
            urgency: high ? 'critical' : 'normal'
        });

        // The most recent one, since a summary cannot open several.
        notification.on('click', () => this.onOpenCase(items[items.length - 1].case_id));
        notification.show();
        this.raised += 1;
    }

    /** The single clearest reason, so the notification says why and not only what. */
    topFinding(item) {
        const evidence = (item.evidence || [])
            .slice()
            .sort((a, b) => (b.signal_strength || 0) - (a.signal_strength || 0));
        return evidence[0]?.finding ? this.trim(evidence[0].finding, 80) : null;
    }

    trim(text, limit) {
        const value = String(text || '').replace(/\s+/g, ' ').trim();
        return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
    }

    state() {
        return {
            running: this.timer !== null,
            supported: Notification.isSupported(),
            poll_seconds: POLL_MS / 1000,
            notifications_raised: this.raised,
            cases_known: this.notified.size,
            last_error: this.lastError,
            policy: 'Only high-risk and suspicious verdicts on recent mail. Never a notification that a message is safe, never any body text, and nothing from a backlog scan.'
        };
    }
}

module.exports = ThreatNotifier;
module.exports.POLL_MS = POLL_MS;
module.exports.NOTIFY_VERDICTS = NOTIFY_VERDICTS;
