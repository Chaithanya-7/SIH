const threatIntelStore = require('./threatIntelStore');
const rdapAdapter = require('../adapters/rdapAdapter');

/**
 * Applies threat intelligence to every indicator extracted from a message,
 * rather than only to the single origin IP.
 *
 * Two independent sources, both free and both honest about their limits:
 *
 *  1. The local open-feed indicator set (threatIntelStore). Matching happens
 *     entirely on this machine, so no indicator from the operator's mail is
 *     disclosed to a third party.
 *  2. Registration age via RDAP. Phishing infrastructure is typically days old;
 *     the organisation a message claims to come from usually is not.
 *
 * Absence from a feed is never treated as evidence of safety - it means only
 * that nothing is known, which is what "UNKNOWN" records.
 */
class ThreatIntelEnricher {
    /** Domains this deployment resolves age for; capped so one message cannot trigger dozens of lookups. */
    static MAX_AGE_LOOKUPS = 5;

    async enrich(threatObject) {
        console.log('[ThreatIntelEnricher] Matching indicators against local open-feed intelligence...');

        const iocs = threatObject.iocs || {};
        const matches = [];

        (iocs.urls || []).forEach(url => {
            const hit = threatIntelStore.lookupUrl(url);
            if (hit) matches.push({ indicator_type: 'URL', indicator: url, ...hit });
        });

        (iocs.domains || []).forEach(domain => {
            const hit = threatIntelStore.lookupDomain(domain);
            if (hit) matches.push({ indicator_type: 'DOMAIN', indicator: domain, ...hit });
        });

        (iocs.ips || []).forEach(ip => {
            const hit = threatIntelStore.lookupIp(ip);
            if (hit) matches.push({ indicator_type: 'IP', indicator: ip, ...hit });
        });

        const domainAges = await this.resolveDomainAges(threatObject, iocs);

        threatObject.threat_intelligence = {
            status: threatIntelStore.isSynced() ? 'MATCHED_AGAINST_LOCAL_FEEDS' : 'NO_FEED_DATA',
            feed_state: {
                synced: threatIntelStore.isSynced(),
                last_sync: threatIntelStore.getStatus().last_sync,
                age_hours: threatIntelStore.getStatus().age_hours,
                indicator_totals: threatIntelStore.counts()
            },
            matches,
            domain_ages: domainAges,
            limitation: threatIntelStore.isSynced()
                ? 'Feeds are a snapshot of known-bad indicators. An indicator that is absent is simply unknown, not established as safe.'
                : 'No indicator feed has been synchronised, so no feed matching was performed. This contributes no evidence either way.'
        };

        return threatObject;
    }

    /**
     * Ages the sender domain first - it is the one that matters most for
     * impersonation - then the domains actually linked in the message.
     */
    async resolveDomainAges(threatObject, iocs) {
        const senderDomain = (threatObject.message?.sender || '').match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/)?.[1];
        const ordered = [];
        if (senderDomain) ordered.push(senderDomain.toLowerCase());
        (iocs.domains || []).forEach(d => { if (!ordered.includes(d)) ordered.push(d); });

        const selected = ordered.slice(0, ThreatIntelEnricher.MAX_AGE_LOOKUPS);
        const results = await Promise.all(selected.map(async domain => {
            const age = await rdapAdapter.lookupDomainAge(domain);
            return {
                domain,
                is_sender_domain: domain === senderDomain,
                status: age.status,
                registered_at: age.registered_at || null,
                age_days: age.age_days === undefined ? null : age.age_days,
                reason: age.reason || null
            };
        }));

        return results;
    }
}

module.exports = new ThreatIntelEnricher();
