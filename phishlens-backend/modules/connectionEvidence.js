const securityTools = require('./securityTools');

/**
 * Asks whether this machine actually went to the place a suspicious email
 * pointed at.
 *
 * ## The gap this fills
 *
 * Every other stage of IP intelligence works from the message. The message is
 * written by the sender, so it can say anything, and it cannot say what happened
 * next. Which address was contacted, on which port, whether the connection
 * succeeded, how many times it was tried - none of that is in an email header,
 * and it was recorded as missing rather than guessed at.
 *
 * TShark supplies exactly that, and it is the reason to reach for Wireshark
 * here. It changes the question from "this link looked dangerous" to "this link
 * looked dangerous and, four minutes later, this machine connected to it" -
 * which is the difference between a warning and a clicked link.
 *
 * ## What it cannot do, which is most of what people expect
 *
 * It cannot read mail. Every mail path worth watching is encrypted: webmail over
 * HTTPS, IMAP on 993, SMTP on 465 or 587. A capture of any of them is
 * ciphertext. Reading it would mean terminating TLS with a certificate authority
 * installed on this machine and intercepting the browser, which is an attack on
 * the person being protected, and this does not do it.
 *
 * What stays readable without breaking anything is the metadata: the server name
 * in a TLS ClientHello is sent before the handshake completes, and DNS questions
 * are plain unless the resolver is DoH. That is enough to know where a machine
 * went, and it is all that is used here.
 *
 * ## Consequences worth stating
 *
 * Capturing needs a packet driver and administrator rights, so this is off
 * unless deliberately turned on. It observes the whole machine, not one
 * application. And an absent answer is an absent answer: no evidence of a
 * connection is never reported as evidence of no connection, because a capture
 * that was not running cannot exonerate anybody.
 */

/**
 * The fields read out of each packet.
 *
 * Deliberately narrow. Everything here is addressing and timing, and no field
 * carries message content, so a capture taken for this purpose cannot become a
 * recording of somebody's correspondence.
 */
const FIELDS = [
    'frame.time_epoch',
    'ip.dst',
    'ipv6.dst',
    'tcp.dstport',
    'udp.dstport',
    // Present in a TLS ClientHello, before encryption begins.
    'tls.handshake.extensions_server_name',
    // The question, not the answer, so this is the name the machine asked for.
    'dns.qry.name'
];

/**
 * Only the packets that say where something is going.
 *
 * A ClientHello is handshake type 1. A DNS query has the response flag clear.
 * Filtering in TShark rather than in here means the packets that do not matter
 * are never handed over in the first place.
 */
const CAPTURE_FILTER = 'tls.handshake.type == 1 || dns.flags.response == 0';

/** A live capture runs for a bounded time and then stops on its own. */
const DEFAULT_CAPTURE_SECONDS = 30;

/** How long after an email arrives a connection is still plausibly a result of it. */
const DEFAULT_CORRELATION_WINDOW_MS = 30 * 60 * 1000;

class ConnectionEvidence {
    constructor(tools = securityTools) {
        this.securityTools = tools;
    }

    /** Is there anything here that can answer this kind of question at all? */
    async availability() {
        const tool = await this.securityTools.detect('tshark');
        if (!tool.available) {
            return {
                available: false,
                reason: tool.reason,
                detail: tool.detail,
                remedy: tool.install_hint,
                what_would_be_added: tool.purpose,
                // Repeated here because this is the field a caller is most likely
                // to render on its own.
                caveat: 'Without this, PhishLens can say a link was dangerous but not whether anybody followed it.'
            };
        }

        return {
            available: true,
            tool: tool.name,
            version: tool.version,
            limitation: tool.limitation
        };
    }

    /**
     * Reads a capture file and returns where this machine was going.
     *
     * Separate from live capture on purpose: reading a file needs no driver and
     * no privileges, so a capture taken elsewhere - or once, deliberately - can
     * be analysed on a machine that is not allowed to sniff anything.
     */
    async readCapture(capturePath) {
        const tool = await this.securityTools.detect('tshark');
        if (!tool.available) return { status: 'UNAVAILABLE', ...(await this.availability()) };

        const probe = await this.securityTools.run(
            tool.invocation.command,
            [...tool.invocation.prefix, '-r', capturePath, '-T', 'fields',
             ...FIELDS.flatMap(f => ['-e', f]), '-Y', CAPTURE_FILTER, '-E', 'separator=/t'],
            { timeout: 120000, maxBuffer: 64 * 1024 * 1024 }
        );

        if (!probe.ok) {
            return { status: 'FAILED', detail: `The capture could not be read: ${probe.error}` };
        }

        return { status: 'READ', observations: this.parseFields(probe.output) };
    }

    /**
     * Watches the network for a bounded period.
     *
     * Needs administrator rights and a packet driver, and says which of those is
     * missing rather than reporting an empty capture.
     */
    async capture({ interfaceName = null, seconds = DEFAULT_CAPTURE_SECONDS } = {}) {
        const tool = await this.securityTools.detect('tshark');
        if (!tool.available) return { status: 'UNAVAILABLE', ...(await this.availability()) };

        const args = [...tool.invocation.prefix];
        if (interfaceName) args.push('-i', interfaceName);
        args.push(
            '-a', `duration:${Math.max(1, Math.min(300, seconds))}`,
            '-T', 'fields',
            ...FIELDS.flatMap(f => ['-e', f]),
            '-Y', CAPTURE_FILTER,
            '-E', 'separator=/t'
        );

        const probe = await this.securityTools.run(tool.invocation.command, args, {
            // The capture stops itself; this is only the backstop for it not doing so.
            timeout: (seconds + 30) * 1000,
            maxBuffer: 64 * 1024 * 1024
        });

        if (!probe.ok) {
            // The common failures are worth telling apart, because one is a
            // permission problem and the other is a missing driver, and they are
            // fixed differently.
            const output = probe.output || '';
            if (/permission|denied|not allowed|administrator/i.test(output)) {
                return {
                    status: 'NOT_PERMITTED',
                    detail: 'Capturing requires administrator rights. PhishLens was not started with them, and does not ask for them on its own.'
                };
            }
            if (/no such (device|interface)|couldn.t run|npcap|winpcap|no interfaces/i.test(output)) {
                return {
                    status: 'NO_CAPTURE_DRIVER',
                    detail: 'No capture driver was found. On Windows this is Npcap, which the Wireshark installer offers.'
                };
            }
            return { status: 'FAILED', detail: `The capture did not run: ${probe.error}` };
        }

        return { status: 'CAPTURED', seconds, observations: this.parseFields(probe.output) };
    }

    /**
     * Turns TShark's tab-separated field output into where-this-went records.
     *
     * Kept a pure function of its input so it can be tested without a capture,
     * a driver, or administrator rights.
     */
    parseFields(output) {
        const observations = [];

        for (const line of String(output || '').split(/\r?\n/)) {
            if (!line.trim()) continue;
            const [epoch, ipv4, ipv6, tcpPort, udpPort, sni, dnsName] = line.split('\t');

            // A single packet can carry several values for one field; TShark
            // comma-separates them. The first is the one that was asked for.
            const host = (sni || dnsName || '').split(',')[0].trim() || null;
            const address = (ipv4 || ipv6 || '').split(',')[0].trim() || null;
            if (!host && !address) continue;

            observations.push({
                at: epoch ? new Date(Number(epoch) * 1000).toISOString() : null,
                host,
                address,
                port: Number((tcpPort || udpPort || '').split(',')[0]) || null,
                protocol: tcpPort ? 'TCP' : (udpPort ? 'UDP' : null),
                // Which of the two things was seen, because they mean different
                // things: a name was looked up, or a connection was begun to it.
                kind: sni ? 'TLS_CONNECTION' : 'DNS_QUERY'
            });
        }

        return observations;
    }

    /**
     * Lines up what a message pointed at with where the machine actually went.
     *
     * The window matters. A connection to a host an hour before the email
     * arrived is not a result of it, and treating any match as a match would
     * turn ordinary browsing into evidence of a click.
     */
    correlate(observations, indicators, { receivedAt, windowMs = DEFAULT_CORRELATION_WINDOW_MS } = {}) {
        const received = receivedAt ? new Date(receivedAt).getTime() : null;
        const wanted = new Map();

        for (const indicator of indicators || []) {
            const value = String(indicator || '').trim().toLowerCase();
            if (value) wanted.set(value, indicator);
        }

        const matches = [];

        for (const observation of observations || []) {
            const candidates = [observation.host, observation.address].filter(Boolean).map(v => v.toLowerCase());

            for (const candidate of candidates) {
                // A subdomain of a flagged host is the same destination for this
                // purpose, and is how a link is usually dressed up.
                const hit = wanted.has(candidate)
                    ? candidate
                    : [...wanted.keys()].find(w => candidate === w || candidate.endsWith(`.${w}`));
                if (!hit) continue;

                const at = observation.at ? new Date(observation.at).getTime() : null;
                if (received !== null && at !== null) {
                    // Before the email existed, or long after it stopped being
                    // the plausible cause, this is somebody browsing.
                    if (at < received || at - received > windowMs) continue;
                }

                matches.push({
                    indicator: wanted.get(hit),
                    observed_host: observation.host,
                    observed_address: observation.address,
                    port: observation.port,
                    protocol: observation.protocol,
                    kind: observation.kind,
                    at: observation.at,
                    delay_seconds: received !== null && at !== null ? Math.round((at - received) / 1000) : null
                });
                break;
            }
        }

        return {
            matched: matches.length > 0,
            matches,
            attempts: matches.length,
            // Stated rather than left to inference. An empty result here is the
            // most misreadable output this module produces.
            interpretation: matches.length
                ? 'This machine contacted a destination the message pointed at, after the message arrived.'
                : 'No connection to those destinations was seen in what was captured. This is not evidence that none happened: it only covers the period that was actually being watched.'
        };
    }
}

module.exports = new ConnectionEvidence();
module.exports.ConnectionEvidence = ConnectionEvidence;
module.exports.FIELDS = FIELDS;
module.exports.CAPTURE_FILTER = CAPTURE_FILTER;
