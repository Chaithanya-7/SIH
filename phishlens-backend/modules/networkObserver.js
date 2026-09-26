const { spawn } = require('child_process');
const securityTools = require('./securityTools');
const connectionEvidence = require('./connectionEvidence');

/**
 * A continuously running TShark capture, kept as a short rolling memory of
 * where this machine has been going.
 *
 * ## Why a rolling capture rather than capturing on demand
 *
 * `connectionEvidence.capture()` already existed and runs TShark for a bounded
 * number of seconds. It cannot answer the question that matters, and the reason
 * is a matter of ordering rather than of duration.
 *
 * PhishLens analyses mail *as it arrives*, before anybody has opened it - that
 * is the whole point of watching the list rather than the open message. So at
 * the moment a case is scored, no link in it has been clicked yet. Correlating
 * a capture against the message at analysis time will therefore find nothing,
 * essentially always, and would have shipped as a feature that could never fire
 * once.
 *
 * The useful question is asked afterwards: *did this machine go there in the
 * half hour after the warning?* Answering it needs observations that continue to
 * accumulate after the case is closed, which is what this holds.
 *
 * ## What it keeps, and what it refuses to keep
 *
 * Only the fields `connectionEvidence` already defined: destination address,
 * port, the server name from a TLS ClientHello, and the DNS name that was asked
 * for. No payload, no request body, no message content - a capture taken for
 * this purpose cannot become a recording of somebody's correspondence, and that
 * is enforced by the capture filter rather than by intention.
 *
 * The memory is bounded twice, by age and by count. An observation older than
 * the correlation window can never match anything again, so keeping it would be
 * storing a record of somebody's browsing for no purpose.
 *
 * ## Why it does not start on its own
 *
 * Capturing needs a packet driver and administrator rights. A security tool that
 * quietly begins recording every destination a machine contacts, because it was
 * installed, would be doing something the person did not ask for. So this starts
 * only when switched on deliberately, and when it is off the pipeline records
 * that connection evidence was not collected rather than that no connection
 * happened.
 *
 * ## The rule this must never break
 *
 * No match is not evidence of no connection. A capture that was not running, a
 * resolver using DNS-over-HTTPS, a browser on a different machine, a VPN
 * carrying the traffic elsewhere - all produce silence, and none of them means
 * the link was not followed. Silence is reported as silence.
 */

/** Bounded twice. Age first, because an old observation cannot match anything. */
const MAX_OBSERVATIONS = 20000;
const MAX_AGE_MS = 45 * 60 * 1000;

/** How long to wait before restarting a capture that stopped unexpectedly. */
const RESTART_BASE_MS = 5000;
const RESTART_MAX_MS = 5 * 60 * 1000;

const STATE = {
    DISABLED: 'DISABLED',
    STARTING: 'STARTING',
    RUNNING: 'RUNNING',
    NOT_PERMITTED: 'NOT_PERMITTED',
    NO_CAPTURE_DRIVER: 'NO_CAPTURE_DRIVER',
    UNAVAILABLE: 'UNAVAILABLE',
    FAILED: 'FAILED',
    STOPPED: 'STOPPED'
};

class NetworkObserver {
    constructor(tools = securityTools, evidence = connectionEvidence) {
        this.securityTools = tools;
        this.evidence = evidence;

        this.state = STATE.DISABLED;
        this.detail = 'Network observation is switched off. Connection evidence is not being collected.';
        this.child = null;
        this.interfaceName = null;
        this.startedAt = null;
        this.restartAttempts = 0;
        this.restartTimer = null;
        this.stopping = false;

        /** Rolling memory, oldest first. */
        this.observations = [];
        this.totalSeen = 0;

        /** Partial line left over between chunks of stdout. */
        this.pending = '';
    }

    /**
     * Starts observing, or explains why it cannot.
     *
     * Every failure is reported as its own state rather than as a generic
     * error, because "no driver installed" and "not running as administrator"
     * are fixed by completely different actions and the difference is the only
     * useful thing in the message.
     */
    async start({ interfaceName = null } = {}) {
        if (this.child) return this.status();

        this.stopping = false;
        this.interfaceName = interfaceName;
        this.state = STATE.STARTING;

        const tool = await this.securityTools.detect('tshark');
        if (!tool.available) {
            this.state = STATE.UNAVAILABLE;
            this.detail = tool.reason || 'TShark was not found on this machine.';
            return this.status();
        }

        const args = [...tool.invocation.prefix];
        if (interfaceName) args.push('-i', interfaceName);
        args.push(
            // Line-buffered. Without this TShark blocks up its output and
            // nothing arrives until the buffer fills, which for a filter this
            // narrow can be a very long time - the observer would look alive
            // and hold nothing.
            '-l',
            '-T', 'fields',
            ...connectionEvidence.FIELDS.flatMap(f => ['-e', f]),
            '-Y', connectionEvidence.CAPTURE_FILTER,
            '-E', 'separator=/t'
        );

        try {
            this.child = spawn(tool.invocation.command, args, { windowsHide: true });
        } catch (err) {
            this.state = STATE.FAILED;
            this.detail = `The capture could not be started: ${err.message}`;
            this.child = null;
            return this.status();
        }

        this.startedAt = new Date().toISOString();
        this.state = STATE.RUNNING;
        this.detail = `Observing${interfaceName ? ` on ${interfaceName}` : ' on the default interface'}. Only destination addresses, ports, TLS server names and DNS questions are read.`;

        this.child.stdout.on('data', chunk => this.ingest(chunk));
        this.child.stderr.on('data', chunk => this.readStderr(String(chunk)));
        this.child.on('error', err => {
            this.state = STATE.FAILED;
            this.detail = `The capture process failed: ${err.message}`;
        });
        this.child.on('close', code => this.onClose(code));

        return this.status();
    }

    /**
     * TShark reports permission and driver problems on stderr and then exits,
     * so the exit code alone says only that it failed.
     */
    readStderr(text) {
        if (/permission|denied|not allowed|administrator|operation not permitted/i.test(text)) {
            this.state = STATE.NOT_PERMITTED;
            this.detail = 'Capturing requires administrator rights. PhishLens was not started with them and does not ask for them on its own.';
            return;
        }
        if (/no such (device|interface)|npcap|winpcap|no interfaces|couldn.t run/i.test(text)) {
            this.state = STATE.NO_CAPTURE_DRIVER;
            this.detail = 'No capture driver was found. On Windows this is Npcap, which the Wireshark installer offers.';
        }
    }

    /** Accumulates stdout and turns whole lines into observations. */
    ingest(chunk) {
        this.pending += String(chunk);

        const lines = this.pending.split(/\r?\n/);
        // The last element is either empty or a partial line still arriving.
        this.pending = lines.pop() || '';
        if (!lines.length) return;

        // Reuses the parser connectionEvidence already had, so there is one
        // place that knows what TShark's field output means.
        const parsed = this.evidence.parseFields(lines.join('\n'));
        if (!parsed.length) return;

        this.totalSeen += parsed.length;
        this.observations.push(...parsed);
        this.prune();
    }

    /** Bounded by age first, then by count. */
    prune() {
        const cutoff = Date.now() - MAX_AGE_MS;
        let drop = 0;
        while (drop < this.observations.length) {
            const at = Date.parse(this.observations[drop]?.at || '');
            if (Number.isFinite(at) && at < cutoff) drop++;
            else break;
        }
        if (drop) this.observations.splice(0, drop);

        if (this.observations.length > MAX_OBSERVATIONS) {
            this.observations.splice(0, this.observations.length - MAX_OBSERVATIONS);
        }
    }

    onClose(code) {
        this.child = null;

        if (this.stopping) {
            this.state = STATE.STOPPED;
            this.detail = 'Network observation was stopped.';
            return;
        }

        // A permission or driver problem is settled; restarting would fail the
        // same way every few seconds and fill the log with it.
        if (this.state === STATE.NOT_PERMITTED || this.state === STATE.NO_CAPTURE_DRIVER) return;

        this.state = STATE.FAILED;
        this.detail = `The capture stopped unexpectedly (exit ${code}). Retrying.`;

        this.restartAttempts += 1;
        const wait = Math.min(RESTART_BASE_MS * Math.pow(2, this.restartAttempts - 1), RESTART_MAX_MS);
        this.restartTimer = setTimeout(() => {
            this.restartTimer = null;
            this.start({ interfaceName: this.interfaceName });
        }, wait);
        if (this.restartTimer.unref) this.restartTimer.unref();
    }

    stop() {
        this.stopping = true;
        if (this.restartTimer) {
            clearTimeout(this.restartTimer);
            this.restartTimer = null;
        }
        if (this.child) {
            try { this.child.kill(); } catch (e) { /* already gone */ }
            this.child = null;
        }
        this.state = STATE.STOPPED;
        this.detail = 'Network observation was stopped.';
        return this.status();
    }

    /** Observations still inside the window, for correlation. */
    recent() {
        this.prune();
        return this.observations.slice();
    }

    /** Whether a correlation result may be trusted to mean anything. */
    isObserving() {
        return this.state === STATE.RUNNING;
    }

    status() {
        return {
            state: this.state,
            detail: this.detail,
            observing: this.isObserving(),
            interface: this.interfaceName,
            started_at: this.startedAt,
            observations_held: this.observations.length,
            observations_seen: this.totalSeen,
            window_minutes: Math.round(MAX_AGE_MS / 60000),
            // Said on every report, because it is the one conclusion somebody
            // will reach on their own and it is wrong. A capture that is not
            // running, a DNS-over-HTTPS resolver, a browser on another machine
            // or a VPN all produce silence.
            limitation: 'No match is not evidence that a link was not followed. Absent observation is absent observation.',
            // What is never collected, stated rather than implied.
            collects: 'Destination address, port, TLS server name, DNS question. No payload and no message content.'
        };
    }
}

module.exports = new NetworkObserver();
module.exports.NetworkObserver = NetworkObserver;
module.exports.STATE = STATE;
module.exports.MAX_AGE_MS = MAX_AGE_MS;
