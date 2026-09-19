const fs = require('fs');
const path = require('path');

/**
 * Behavioural analysis branch.
 *
 * Detection rules and language analysis judge a message on its own contents.
 * This branch judges it against what this deployment has actually observed
 * before: who normally writes to this organisation, from where, and when.
 * That is how an impersonation of a known contact is caught even when the
 * message itself is clean, correctly authenticated, and carries no link or
 * attachment.
 *
 * Everything is derived from, and stored on, the local system. There is no
 * model download, no external service, and no shared baseline: the behavioural
 * picture belongs to whoever runs this installation.
 *
 * Baselines are built from messages that were NOT judged high risk. Learning
 * "normal" from traffic that already looks malicious would let an attacker who
 * sends enough mail define themselves as normal.
 */
class BehavioralAnalyzer {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/sender_baselines.json');
        /** address -> { first_seen, last_seen, message_count, clean_count, display_names[], origin_ips[], send_hours[] } */
        this.senders = new Map();
        /** normalized display name -> [addresses that have used it] */
        this.displayNames = new Map();
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.storageFile)) return;

            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '{}');
            (stored.senders || []).forEach(s => { if (s.address) this.senders.set(s.address, s); });
            (stored.display_names || []).forEach(d => {
                if (d.display_name) this.displayNames.set(d.display_name, d.addresses || []);
            });
            console.log(`[BehavioralAnalyzer] Loaded behavioural baselines for ${this.senders.size} sender(s).`);
        } catch (e) {
            console.error('[BehavioralAnalyzer] Baseline load error:', e.message);
        }
    }

    saveStorage() {
        try {
            const payload = {
                senders: Array.from(this.senders.values()),
                display_names: Array.from(this.displayNames.entries()).map(([display_name, addresses]) => ({ display_name, addresses })),
                updated_at: new Date().toISOString()
            };
            fs.writeFileSync(this.storageFile, JSON.stringify(payload, null, 2));
        } catch (e) {
            console.error('[BehavioralAnalyzer] Baseline save error:', e.message);
        }
    }

    normalizeDisplayName(name) {
        return (name || '').toLowerCase().replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
    }

    analyze(threatObject, parsedEmail) {
        console.log('[BehavioralAnalyzer] Comparing message against observed sender behaviour...');

        const address = (parsedEmail.from?.address || '').toLowerCase();
        const displayName = this.normalizeDisplayName(parsedEmail.from?.name);
        const baseline = address ? this.senders.get(address) : null;
        const signals = [];

        // 1. A display name that this deployment has previously seen used by a
        //    DIFFERENT address. This is the classic impersonation of a known
        //    colleague or supplier, and it is invisible to content analysis.
        if (displayName && displayName.length > 2) {
            const knownAddresses = (this.displayNames.get(displayName) || []).filter(a => a !== address);
            if (knownAddresses.length > 0) {
                signals.push({
                    type: 'DISPLAY_NAME_IMPERSONATION',
                    severity: 'HIGH',
                    confidence: 0.85,
                    explanation: `The display name "${parsedEmail.from.name}" has previously been used by ${knownAddresses.join(', ')}, but this message comes from ${address}. A familiar name arriving from an unfamiliar address is a common impersonation technique.`,
                    observed: { known_addresses: knownAddresses, this_address: address }
                });
            }
        }

        // 2. First contact from this sender. Weak on its own - most first
        //    contacts are legitimate - but meaningful combined with other signals.
        if (address && !baseline) {
            signals.push({
                type: 'FIRST_CONTACT_SENDER',
                severity: 'LOW',
                confidence: 0.40,
                explanation: `This deployment has not previously received a message from ${address}. First contact is normal on its own; it matters only alongside other indicators.`,
                observed: { this_address: address }
            });
        }

        // 3. A previously-known sender now arriving from sending infrastructure
        //    never before associated with them.
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip || null;
        if (baseline && originIp && Array.isArray(baseline.origin_ips) && baseline.origin_ips.length > 0) {
            if (!baseline.origin_ips.includes(originIp)) {
                signals.push({
                    type: 'SENDER_INFRASTRUCTURE_CHANGE',
                    severity: 'MEDIUM',
                    confidence: 0.60,
                    explanation: `Mail from ${address} has previously arrived from ${baseline.origin_ips.join(', ')}, but this message arrived from ${originIp}. Senders do legitimately change provider, so this is corroborating evidence rather than proof.`,
                    observed: { known_origins: baseline.origin_ips, this_origin: originIp }
                });
            }
        }

        // 4. Send time well outside this sender's established pattern.
        const sendHour = parsedEmail.date ? new Date(parsedEmail.date).getUTCHours() : null;
        if (baseline && sendHour !== null && Array.isArray(baseline.send_hours) && baseline.send_hours.length >= 5) {
            if (!baseline.send_hours.includes(sendHour)) {
                const known = Array.from(new Set(baseline.send_hours)).sort((a, b) => a - b);
                signals.push({
                    type: 'UNUSUAL_SEND_TIME',
                    severity: 'LOW',
                    confidence: 0.35,
                    explanation: `Mail from ${address} has previously arrived only in UTC hours ${known.join(', ')}; this message arrived at ${sendHour}:00 UTC.`,
                    observed: { known_hours: known, this_hour: sendHour }
                });
            }
        }

        threatObject.behavioral = {
            status: 'ANALYZED',
            engine: 'PHISHLENS_LOCAL_BEHAVIOURAL_BASELINE',
            known_sender: !!baseline,
            messages_seen_from_sender: baseline ? baseline.message_count : 0,
            signals,
            limitation: 'Behavioural baselines describe only what this installation has observed. A newly deployed system has little history, so these signals strengthen over time.'
        };

        return threatObject;
    }

    /**
     * Records the observation after the verdict is known. Only messages that
     * were not judged high risk contribute to the "normal" baseline.
     */
    recordObservation(threatObject, parsedEmail) {
        const address = (parsedEmail.from?.address || '').toLowerCase();
        if (!address) return;

        const isHighRisk = threatObject.detection?.verdict === 'HIGH_RISK';
        const displayName = this.normalizeDisplayName(parsedEmail.from?.name);
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip || null;
        const sendHour = parsedEmail.date ? new Date(parsedEmail.date).getUTCHours() : null;

        const baseline = this.senders.get(address) || {
            address,
            first_seen: new Date().toISOString(),
            last_seen: null,
            message_count: 0,
            clean_count: 0,
            display_names: [],
            origin_ips: [],
            send_hours: []
        };

        baseline.last_seen = new Date().toISOString();
        baseline.message_count += 1;

        if (!isHighRisk) {
            baseline.clean_count += 1;
            if (displayName && !baseline.display_names.includes(displayName)) {
                baseline.display_names.push(displayName);
            }
            if (originIp && !baseline.origin_ips.includes(originIp)) {
                baseline.origin_ips.push(originIp);
                if (baseline.origin_ips.length > 10) baseline.origin_ips.shift();
            }
            if (sendHour !== null) {
                baseline.send_hours.push(sendHour);
                if (baseline.send_hours.length > 50) baseline.send_hours.shift();
            }

            // The display-name index is what makes impersonation of a known
            // contact detectable, so only trusted observations may extend it.
            if (displayName && displayName.length > 2) {
                const addresses = this.displayNames.get(displayName) || [];
                if (!addresses.includes(address)) {
                    addresses.push(address);
                    this.displayNames.set(displayName, addresses);
                }
            }
        }

        this.senders.set(address, baseline);
        this.saveStorage();
    }

    getStats() {
        return {
            senders_tracked: this.senders.size,
            display_names_tracked: this.displayNames.size
        };
    }
}

module.exports = new BehavioralAnalyzer();
