const dns = require('dns').promises;
const executiveGuard = require('./executiveGuard');

/**
 * Tells a domain owner how to stop their own domain being spoofed.
 *
 * Every other part of PhishLens reacts to a phishing message that has already
 * been sent. This is the one part that can stop the next one being deliverable
 * at all: a domain publishing DMARC p=reject cannot be spoofed outright, so the
 * attacker is pushed onto a lookalike domain, which the detection layer is far
 * better at catching than an exact impersonation.
 *
 * The advice is specific on purpose. "Consider hardening DMARC" is not
 * actionable; a DNS record an administrator can paste, with a named rollout
 * order and a reason per step, is.
 *
 * Sources: RFC 7489 (DMARC), RFC 7208 (SPF), RFC 6376 (DKIM).
 */

const SEVERITY = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', OK: 'OK' };

class DmarcAdvisor {
    constructor() {
        this.cache = new Map();
        this.cacheTtlMs = 6 * 60 * 60 * 1000;
    }

    async resolveTxt(name) {
        try {
            const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out')), 3000));
            const records = await Promise.race([dns.resolveTxt(name), timeout]);
            return records.map(chunks => chunks.join(''));
        } catch (e) {
            return null;
        }
    }

    parseDmarc(txt) {
        const tags = {};
        txt.split(';').forEach(part => {
            const [k, v] = part.split('=').map(s => (s || '').trim());
            if (k) tags[k.toLowerCase()] = v;
        });
        return tags;
    }

    /**
     * A domain's current published posture, and what is missing from it.
     */
    async assess(domain) {
        const key = String(domain || '').toLowerCase().trim();
        if (!key) throw new Error('A domain is required.');

        const cached = this.cache.get(key);
        if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached.result;

        const [dmarcRecords, spfRecords] = await Promise.all([
            this.resolveTxt(`_dmarc.${key}`),
            this.resolveTxt(key)
        ]);

        const dmarcTxt = (dmarcRecords || []).find(r => /^v=DMARC1/i.test(r)) || null;
        const spfTxt = (spfRecords || []).find(r => /^v=spf1/i.test(r)) || null;
        const findings = [];

        if (!dmarcTxt) {
            findings.push({
                control: 'DMARC',
                severity: SEVERITY.CRITICAL,
                finding: `${key} publishes no DMARC record.`,
                consequence: 'Anyone can send mail claiming to be from this domain and receiving servers have no instruction to reject it. This is the condition that makes exact-domain impersonation of your organisation possible.',
                recommendation: `Publish a DMARC record in monitoring mode first, so you can see who is sending as ${key} before you start rejecting anything.`,
                dns_record: { name: `_dmarc.${key}`, type: 'TXT', value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@${key}; fo=1` },
                reference: 'RFC 7489 §6.3'
            });
        } else {
            const tags = this.parseDmarc(dmarcTxt);
            const policy = (tags.p || '').toLowerCase();
            const pct = tags.pct ? parseInt(tags.pct, 10) : 100;

            if (policy === 'none') {
                findings.push({
                    control: 'DMARC',
                    severity: SEVERITY.HIGH,
                    finding: `${key} publishes DMARC p=none.`,
                    consequence: 'Receiving servers are told to take no action on mail that fails authentication, so a spoofed message from this domain still lands in the inbox. p=none reports the abuse but does not stop it.',
                    recommendation: 'Move to p=quarantine once your DMARC reports show your own legitimate senders passing, then to p=reject. Raise pct in stages rather than switching everything at once.',
                    dns_record: { name: `_dmarc.${key}`, type: 'TXT', value: `v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@${key}; fo=1` },
                    reference: 'RFC 7489 §6.3'
                });
            } else if (policy === 'quarantine') {
                findings.push({
                    control: 'DMARC',
                    severity: pct < 100 ? SEVERITY.MEDIUM : SEVERITY.LOW,
                    finding: `${key} publishes DMARC p=quarantine${pct < 100 ? ` at pct=${pct}` : ''}.`,
                    consequence: pct < 100
                        ? `Only ${pct}% of failing mail is quarantined; the remaining ${100 - pct}% is delivered normally, so an attacker simply has to try more than once.`
                        : 'Failing mail is quarantined rather than rejected, so it still reaches the recipient\'s spam folder where it can be retrieved.',
                    recommendation: pct < 100
                        ? 'Raise pct to 100 once reports show no legitimate senders failing, then move to p=reject.'
                        : 'Move to p=reject so spoofed mail is refused at the gateway rather than filed.',
                    dns_record: { name: `_dmarc.${key}`, type: 'TXT', value: `v=DMARC1; p=reject; rua=mailto:dmarc-reports@${key}; fo=1` },
                    reference: 'RFC 7489 §6.3'
                });
            } else if (policy === 'reject') {
                findings.push({
                    control: 'DMARC',
                    severity: SEVERITY.OK,
                    finding: `${key} publishes DMARC p=reject.`,
                    consequence: 'Mail that fails authentication while claiming this domain is refused. Exact-domain impersonation of this organisation is not deliverable.',
                    recommendation: 'No change needed. Keep reading the aggregate reports so a new legitimate sender is not silently broken by the policy.',
                    reference: 'RFC 7489 §6.3'
                });
            }

            if (!tags.rua) {
                findings.push({
                    control: 'DMARC_REPORTING',
                    severity: SEVERITY.MEDIUM,
                    finding: `${key} publishes DMARC without an rua= reporting address.`,
                    consequence: 'You receive no aggregate reports, so you cannot see who is sending as your domain, and tightening the policy becomes guesswork with a real chance of blocking your own mail.',
                    recommendation: `Add rua=mailto:dmarc-reports@${key} so you can see your sending sources before you tighten the policy.`,
                    reference: 'RFC 7489 §7.1'
                });
            }

            if ((tags.sp || '').toLowerCase() === 'none' && policy !== 'none') {
                findings.push({
                    control: 'DMARC_SUBDOMAIN',
                    severity: SEVERITY.HIGH,
                    finding: `${key} enforces a policy on itself but publishes sp=none for its subdomains.`,
                    consequence: 'An attacker spoofs any subdomain instead - mail.example.com, hr-example.com is not needed when accounts.example.com is unprotected and looks more legitimate than a lookalike.',
                    recommendation: 'Remove sp=none, or set sp to match the main policy, so subdomains inherit the enforcement.',
                    reference: 'RFC 7489 §6.3'
                });
            }
        }

        if (!spfTxt) {
            findings.push({
                control: 'SPF',
                severity: SEVERITY.HIGH,
                finding: `${key} publishes no SPF record.`,
                consequence: 'Receiving servers have no list of hosts allowed to send for this domain, so SPF cannot pass and DMARC then depends entirely on DKIM alignment.',
                recommendation: 'Publish an SPF record listing your genuine sending infrastructure and ending in -all once you are confident the list is complete.',
                dns_record: { name: key, type: 'TXT', value: 'v=spf1 include:<your-mail-provider> -all' },
                reference: 'RFC 7208 §3'
            });
        } else if (/\+all/i.test(spfTxt)) {
            findings.push({
                control: 'SPF',
                severity: SEVERITY.CRITICAL,
                finding: `${key} publishes SPF ending in +all.`,
                consequence: 'This declares that every host on the internet is authorised to send mail as this domain. It is worse than publishing nothing, because it makes forged mail pass SPF.',
                recommendation: 'Replace +all with -all (or ~all while you verify your sending sources).',
                reference: 'RFC 7208 §5.1'
            });
        } else if (/\?all/i.test(spfTxt)) {
            findings.push({
                control: 'SPF',
                severity: SEVERITY.MEDIUM,
                finding: `${key} publishes SPF ending in ?all (neutral).`,
                consequence: 'A neutral result is treated as no assertion at all, so SPF contributes nothing to stopping forged mail from this domain.',
                recommendation: 'Move to ~all, then -all once your sending sources are confirmed.',
                reference: 'RFC 7208 §5.1'
            });
        }

        const worst = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.OK]
            .find(level => findings.some(f => f.severity === level)) || SEVERITY.OK;

        const result = {
            domain: key,
            assessed_at: new Date().toISOString(),
            spoofable: worst === SEVERITY.CRITICAL || worst === SEVERITY.HIGH,
            severity: worst,
            published: { dmarc: dmarcTxt, spf: spfTxt },
            findings,
            summary: this.summarise(key, worst, findings)
        };

        this.cache.set(key, { at: Date.now(), result });
        return result;
    }

    summarise(domain, worst, findings) {
        if (worst === SEVERITY.OK) {
            return `${domain} is published correctly: mail forging this domain is rejected by receiving servers.`;
        }
        const critical = findings.filter(f => f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.HIGH).length;
        return `${domain} can currently be spoofed. ${critical} issue(s) need fixing before mail claiming to be from this domain is reliably refused, and each one below carries the record to publish.`;
    }

    /**
     * Every domain this deployment is responsible for, assessed together.
     *
     * These are the domains the operator told PhishLens they own, which is the
     * set whose spoofability is their problem to fix.
     */
    async assessOwnDomains() {
        const domains = executiveGuard.organizationDomains || [];
        if (domains.length === 0) {
            return {
                domains: [],
                note: 'No organisation domains are configured, so there is nothing to assess. Add them under executive protection and PhishLens will check what your own domains publish.'
            };
        }
        const assessments = await Promise.all(domains.map(d => this.assess(d).catch(e => ({ domain: d, error: e.message }))));
        return {
            domains: assessments,
            spoofable_count: assessments.filter(a => a.spoofable).length,
            note: 'Publishing a policy that rejects forged mail is the only control here that prevents a phishing message being delivered at all, rather than detecting it afterwards.'
        };
    }
}

module.exports = new DmarcAdvisor();
module.exports.SEVERITY = SEVERITY;
