/**
 * Inventory of every way mail can enter PhishLens.
 *
 * The goal is that no message slips in through a door nobody is watching. That
 * requires more than having adapters: it requires being able to say, at any
 * moment, which entry paths are configured, which are actually running, and
 * which have gone quiet when they should not have.
 *
 * A poller that dies silently is worse than one that was never enabled, because
 * the dashboard keeps looking healthy while mail stops being examined. Sources
 * that are expected to report in therefore declare a heartbeat interval, and
 * are marked STALLED when they stop.
 *
 * Nothing here claims a source is covered because its code exists. State is
 * reported by the adapters themselves as they start, poll and ingest.
 */

const STATUS = {
    NOT_CONFIGURED: 'NOT_CONFIGURED',
    DISABLED: 'DISABLED',
    ACTIVE: 'ACTIVE',
    STALLED: 'STALLED',
    FAILED: 'FAILED'
};

class IngestionRegistry {
    constructor() {
        this.sources = new Map();
        this.registerKnownSources();
    }

    /**
     * Every supported entry path is declared up front, including the ones that
     * are switched off. An operator needs to see the doors that exist and are
     * unwatched, not only the ones already in use.
     */
    registerKnownSources() {
        const known = [
            {
                id: 'smtp_gateway',
                name: 'Inline SMTP gateway',
                transport: 'SMTP',
                description: 'Mail delivered directly to the PhishLens SMTP listener, typically from an MTA relay or milter placed at the network boundary.',
                enable_hint: 'Set ENABLE_SMTP_INGESTION=true with SMTP_USERNAME and SMTP_PASSWORD.',
                expects_heartbeat: false
            },
            {
                id: 'imap_poller',
                name: 'IMAP mailbox poller',
                transport: 'IMAP',
                description: 'Polls an IMAP mailbox for newly delivered messages.',
                enable_hint: 'Set IMAP_ENABLED=true with IMAP_USER, IMAP_PASSWORD and IMAP_HOST.',
                expects_heartbeat: true,
                heartbeat_seconds: 60
            },
            {
                id: 'gmail_api',
                name: 'Gmail API (OAuth + Pub/Sub push)',
                transport: 'GMAIL_API',
                description: 'Receives Gmail push notifications and pulls new messages through the Gmail history API.',
                enable_hint: 'Configure GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GMAIL_REDIRECT_URI, then connect a mailbox through the dashboard.',
                expects_heartbeat: false
            },
            {
                id: 'rest_api',
                name: 'REST analysis API',
                transport: 'HTTP',
                description: 'Authenticated POST /api/analyze, used by integrations and for analyst-submitted samples.',
                enable_hint: 'Always available to authenticated callers.',
                expects_heartbeat: false,
                always_available: true
            },
            {
                id: 'webhook',
                name: 'Inbound webhook',
                transport: 'HTTP',
                description: 'Authenticated POST /api/ingest/email, for SIEM, SOAR, ticketing or mail-relay integrations pushing messages in.',
                enable_hint: 'Always available to authenticated callers.',
                expects_heartbeat: false,
                always_available: true
            },
            {
                id: 'file_upload',
                name: 'Message file upload (.eml / .msg)',
                transport: 'HTTP',
                description: 'Authenticated POST /api/ingest/file, for analyst-submitted message files and user-reported phishing.',
                enable_hint: 'Always available to authenticated callers.',
                expects_heartbeat: false,
                always_available: true
            }
        ];

        known.forEach(source => {
            this.sources.set(source.id, {
                ...source,
                configured: !!source.always_available,
                enabled: !!source.always_available,
                status: source.always_available ? STATUS.ACTIVE : STATUS.NOT_CONFIGURED,
                detail: source.always_available ? 'Available to authenticated callers.' : 'Not configured.',
                messages_ingested: 0,
                failures: 0,
                last_message_at: null,
                last_heartbeat_at: null,
                last_error: null,
                started_at: null
            });
        });
    }

    setState(id, { configured, enabled, status, detail }) {
        const source = this.sources.get(id);
        if (!source) return;

        if (configured !== undefined) source.configured = configured;
        if (enabled !== undefined) source.enabled = enabled;
        if (detail !== undefined) source.detail = detail;
        if (status !== undefined) {
            source.status = status;
            if (status === STATUS.ACTIVE && !source.started_at) source.started_at = new Date().toISOString();
            if (status === STATUS.ACTIVE) source.last_heartbeat_at = new Date().toISOString();
        }
    }

    /** A source reporting it is alive, for paths that would otherwise fail silently. */
    heartbeat(id) {
        const source = this.sources.get(id);
        if (!source) return;
        source.last_heartbeat_at = new Date().toISOString();
        if (source.status === STATUS.STALLED) {
            source.status = STATUS.ACTIVE;
            source.detail = 'Recovered and polling again.';
        }
    }

    recordMessage(id) {
        const source = this.sources.get(id);
        if (!source) return;
        source.messages_ingested += 1;
        source.last_message_at = new Date().toISOString();
        source.last_heartbeat_at = new Date().toISOString();
    }

    recordFailure(id, error) {
        const source = this.sources.get(id);
        if (!source) return;
        source.failures += 1;
        source.last_error = { message: String(error && error.message ? error.message : error), at: new Date().toISOString() };
    }

    /**
     * Marks sources that should be reporting in but have gone quiet. Called on
     * read so the answer is current without a background timer.
     */
    evaluateStalled() {
        const now = Date.now();
        this.sources.forEach(source => {
            if (!source.expects_heartbeat || source.status !== STATUS.ACTIVE) return;
            const last = source.last_heartbeat_at ? new Date(source.last_heartbeat_at).getTime() : null;
            if (last === null) return;
            // Three missed intervals: long enough to avoid flapping on one slow poll.
            if (now - last > source.heartbeat_seconds * 3000) {
                source.status = STATUS.STALLED;
                source.detail = `No activity for ${Math.round((now - last) / 1000)}s; expected roughly every ${source.heartbeat_seconds}s. Mail arriving through this path may not be examined.`;
            }
        });
    }

    getCoverage() {
        this.evaluateStalled();
        const sources = Array.from(this.sources.values());

        const active = sources.filter(s => s.status === STATUS.ACTIVE);
        const stalled = sources.filter(s => s.status === STATUS.STALLED);
        const failed = sources.filter(s => s.status === STATUS.FAILED);
        const unwatched = sources.filter(s => s.status === STATUS.NOT_CONFIGURED || s.status === STATUS.DISABLED);

        const warnings = [];
        stalled.forEach(s => warnings.push(`${s.name} has stopped reporting in. Mail arriving this way may not be examined.`));
        failed.forEach(s => warnings.push(`${s.name} failed to start: ${s.last_error ? s.last_error.message : 'unknown error'}`));

        // A deployment where only the manual paths are live is not monitoring a
        // mailbox, and should not be described as though it were.
        const automatedActive = active.filter(s => !s.always_available);
        if (automatedActive.length === 0) {
            warnings.push('No automatic mail source is active. PhishLens is only analysing messages that are explicitly submitted to it, and is not monitoring any mailbox or gateway.');
        }

        return {
            monitoring_live_mail: automatedActive.length > 0,
            summary: {
                total_sources: sources.length,
                active: active.length,
                automatic_active: automatedActive.length,
                stalled: stalled.length,
                failed: failed.length,
                unwatched: unwatched.length
            },
            warnings,
            sources: sources.map(s => ({
                id: s.id,
                name: s.name,
                transport: s.transport,
                description: s.description,
                configured: s.configured,
                enabled: s.enabled,
                status: s.status,
                detail: s.detail,
                enable_hint: s.status === STATUS.NOT_CONFIGURED || s.status === STATUS.DISABLED ? s.enable_hint : undefined,
                messages_ingested: s.messages_ingested,
                failures: s.failures,
                last_message_at: s.last_message_at,
                last_heartbeat_at: s.last_heartbeat_at,
                last_error: s.last_error,
                started_at: s.started_at
            })),
            generated_at: new Date().toISOString()
        };
    }
}

module.exports = new IngestionRegistry();
module.exports.STATUS = STATUS;
