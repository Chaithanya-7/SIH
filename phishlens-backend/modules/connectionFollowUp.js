const networkObserver = require('./networkObserver');
const connectionWatchlist = require('./connectionWatchlist');
const connectionEvidence = require('./connectionEvidence');
const caseManager = require('./caseManager');
const evidenceFusion = require('./evidenceFusion');
const confidenceEngine = require('./confidenceEngine');
const auditLogger = require('./auditLogger');
const geoIntelAdapter = require('../adapters/geoIntelAdapter');
const ipClassifier = require('./ipClassifier');

/**
 * Asks, a few minutes after the warning, whether anybody went there anyway.
 *
 * This is the part that makes packet analysis worth having in a mail tool. Every
 * other stage reasons about a message, and a message is written by the sender:
 * it can claim anything, and it cannot say what happened next. A capture can.
 *
 * ## How it runs
 *
 * The network observer keeps a rolling memory of destinations this machine has
 * contacted. The watchlist holds the cases that came back high-risk or
 * suspicious, with the hosts and addresses those particular messages named. This
 * sweeps one against the other on a timer until each case's window closes.
 *
 * A match reopens the case: the connection is recorded as evidence, the
 * destination is located and added to the points the map already draws, the
 * evidence is fused again and the confidence recomputed, and the change is
 * written to the audit log. The case keeps its identity - this is the same
 * incident, learning something new about itself, not a second case.
 *
 * ## Two things it must never be read as saying
 *
 * **It does not identify a person.** The capture observes the machine, not the
 * browser, and not an account. On a shared machine more than one person uses
 * that interface. So a match is recorded as a connection observed from this
 * host, never as "the user clicked the link".
 *
 * **Silence proves nothing.** An entry whose window closes with no match is
 * recorded as unmatched and explicitly not as safe. The observer may have been
 * off, the resolver may be using DNS-over-HTTPS, the traffic may have gone
 * through a VPN, the link may have been opened on a phone. Each of those looks
 * exactly like nobody clicking, and treating them as the same thing would turn
 * a missing observation into a clean bill of health.
 */

/** How often the rolling memory is checked against the waiting cases. */
const SWEEP_INTERVAL_MS = 60 * 1000;

class ConnectionFollowUp {
    constructor() {
        this.timer = null;
        this.lastSweepAt = null;
        this.sweeping = false;
        this.matchesFound = 0;
        this.casesUpdated = 0;
        this.expiredUnmatched = 0;
    }

    start() {
        if (this.timer) return;
        this.timer = setInterval(() => { this.sweep(); }, SWEEP_INTERVAL_MS);
        if (this.timer.unref) this.timer.unref();
        console.log('[ConnectionFollowUp] Watching for connections to destinations named by flagged mail.');
    }

    stop() {
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
    }

    /**
     * One pass over the waiting cases.
     *
     * Runs even when the observer is not capturing, because expiry still has to
     * happen: a case whose window has closed must be marked unmatched rather
     * than sitting in the list forever.
     */
    async sweep() {
        if (this.sweeping) return { skipped: 'A sweep is already running.' };
        this.sweeping = true;

        try {
            const pending = connectionWatchlist.pending();
            const observing = networkObserver.isObserving();
            const observations = observing ? networkObserver.recent() : [];

            let matched = 0;
            for (const entry of pending) {
                if (!observing || !observations.length) continue;

                const result = connectionEvidence.correlate(observations, entry.indicators, {
                    receivedAt: entry.received_at,
                    windowMs: entry.window_ms
                });

                entry.checks += 1;
                if (!result.matched) continue;

                await this.recordConnection(entry, result);
                connectionWatchlist.remove(entry.case_id);
                matched += 1;
            }

            // Expiry last, so a case that matched on this very pass is not also
            // written off as unmatched in the same sweep.
            for (const expired of connectionWatchlist.expire()) {
                this.noteUnmatched(expired, observing);
                this.expiredUnmatched += 1;
            }
            connectionWatchlist.save();

            this.lastSweepAt = new Date().toISOString();
            this.matchesFound += matched;
            return { checked: pending.length, matched, observing };
        } catch (err) {
            console.error('[ConnectionFollowUp] Sweep failed:', err.message);
            return { error: err.message };
        } finally {
            this.sweeping = false;
        }
    }

    /**
     * Reopens a case that has been confirmed as contacted.
     *
     * The verdict is recomputed rather than simply raised. A connection is
     * strong evidence and it goes through the same fusion and the same caps as
     * everything else, so the number on the case stays something that can be
     * explained line by line.
     */
    async recordConnection(entry, result) {
        const existing = caseManager.getCase(entry.case_id);
        if (!existing) {
            console.warn(`[ConnectionFollowUp] Case ${entry.case_id} is gone; nothing to update.`);
            return null;
        }

        const first = result.matches[0];

        existing.connection_evidence = {
            status: 'OBSERVED',
            observed_at: first.at,
            delay_seconds: first.delay_seconds,
            matches: result.matches.slice(0, 20),
            window_minutes: Math.round(entry.window_ms / 60000),
            source: 'TSHARK_ROLLING_CAPTURE',
            // Said on the case itself, not only in the documentation.
            attribution_limit: 'The capture observes this machine, not a browser or an account. This records that traffic went to the destination, not who sent it.'
        };

        // Where the machine actually went, added to the points the map already
        // draws. A contacted destination is a different kind of point from a
        // relay in the headers - one is where the message came from, the other
        // is where somebody on this machine ended up - so it carries its own
        // role rather than being mixed in with them.
        const located = await this.locateDestinations(result.matches);
        if (located.length) {
            existing.infrastructure = existing.infrastructure || {};
            const points = existing.infrastructure.geo_points || [];
            const known = new Set(points.map(p => `${p.ip}:${p.role}`));
            for (const point of located) {
                if (!known.has(`${point.ip}:${point.role}`)) points.push(point);
            }
            existing.infrastructure.geo_points = points;
        }

        const before = existing.confidence?.threat ?? null;
        const beforeVerdict = existing.detection?.verdict || 'UNKNOWN';

        let updated = evidenceFusion.fuse(existing);
        updated = confidenceEngine.calculate(updated);
        caseManager.saveCase(updated);

        auditLogger.log({
            case_id: entry.case_id,
            event_type: 'CONNECTION_OBSERVED',
            source: 'NETWORK_OBSERVER',
            description: `Traffic from this machine reached ${first.observed_host || first.observed_address}`
                + `${first.delay_seconds !== null ? ` ${first.delay_seconds}s after the message arrived` : ''}`
                + `, a destination named by case ${entry.case_id}. Confidence ${before} -> ${updated.confidence?.threat}`
                + `, verdict ${beforeVerdict} -> ${updated.detection?.verdict}.`
        });

        this.casesUpdated += 1;
        console.log(`[ConnectionFollowUp] Case ${entry.case_id}: connection observed to ${first.observed_host || first.observed_address}.`);
        return updated;
    }

    /** Geolocates the addresses actually contacted, skipping anything not routable. */
    async locateDestinations(matches) {
        const points = [];
        const seen = new Set();

        for (const match of matches.slice(0, 6)) {
            const ip = match.observed_address;
            if (!ip || seen.has(ip)) continue;
            seen.add(ip);

            // A private, reserved or loopback address has no location to look
            // up, and asking would send an internal address to a public service
            // for an answer that cannot exist.
            if (!ipClassifier.isRoutable(ip)) continue;

            const geo = await geoIntelAdapter.lookupIp(ip);
            if (geo.status !== 'AVAILABLE' || geo.latitude === null || geo.longitude === null) continue;

            points.push({
                ip,
                role: 'CONTACTED',
                latitude: geo.latitude,
                longitude: geo.longitude,
                city: geo.city,
                country: geo.country,
                country_code: geo.country_code,
                asn: geo.asn,
                isp: geo.isp,
                observed_host: match.observed_host || null,
                port: match.port ?? null,
                protocol: match.protocol || null,
                observed_at: match.at || null
            });
        }

        return points;
    }

    /**
     * Records that a window closed without a match, and why that is not an
     * all-clear.
     */
    noteUnmatched(entry, wasObserving) {
        const existing = caseManager.getCase(entry.case_id);
        if (!existing) return;

        existing.connection_evidence = {
            status: wasObserving ? 'NOT_OBSERVED' : 'NOT_COLLECTED',
            window_minutes: Math.round(entry.window_ms / 60000),
            checks: entry.checks,
            detail: wasObserving
                ? 'No traffic from this machine reached the destinations this message named, in the window after it arrived. This is not evidence that the link was not followed: the link may have been opened on another device, the resolver may be using DNS-over-HTTPS, or the traffic may have left through a VPN. Each of those is indistinguishable from nobody clicking.'
                : 'Network observation was not running for this window, so no connection evidence was collected. Nothing at all is known about whether the destinations were reached.'
        };

        caseManager.saveCase(existing);
    }

    state() {
        return {
            running: this.timer !== null,
            sweep_interval_seconds: SWEEP_INTERVAL_MS / 1000,
            last_sweep_at: this.lastSweepAt,
            matches_found: this.matchesFound,
            cases_updated: this.casesUpdated,
            expired_unmatched: this.expiredUnmatched,
            observer: networkObserver.status(),
            watchlist: connectionWatchlist.state()
        };
    }
}

module.exports = new ConnectionFollowUp();
module.exports.ConnectionFollowUp = ConnectionFollowUp;
module.exports.SWEEP_INTERVAL_MS = SWEEP_INTERVAL_MS;
