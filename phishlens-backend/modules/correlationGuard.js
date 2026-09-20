/**
 * Guards campaign correlation against false links.
 *
 * The original audit flagged this as a real defect: a Google, Microsoft,
 * Cloudflare or shared-hosting IP, ASN or domain could tie unrelated messages
 * into one "campaign". Two strangers both phished from Gmail are not a campaign
 * - they share a provider, not an operator. A campaign view that merges
 * unrelated incidents is worse than no campaign view, because an analyst will
 * act on the grouping.
 *
 * The distinction that matters is how specific an indicator is:
 *
 *   High specificity - an attachment hash, an exact URL, an exact sender
 *   address. These are attacker-chosen. Sharing one is meaningful even across
 *   hundreds of messages, because a mass campaign genuinely does reuse them.
 *
 *   Low specificity - an ASN, a provider's outbound mail IP, a freemail sender
 *   domain, a multi-tenant hosting domain. These are shared by unrelated
 *   parties by design, so sharing one proves nothing on its own.
 *
 * Low-specificity indicators are suppressed both by a list of well-known
 * providers and by prevalence: anything showing up across many unrelated cases
 * in this deployment is infrastructure, whatever it is called. Prevalence is
 * deliberately NOT applied to high-specificity indicators, because suppressing
 * a widely-reused phishing URL would break exactly the case campaign
 * correlation exists to catch.
 */

const FREEMAIL_DOMAINS = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'aol.com',
    'icloud.com', 'me.com', 'protonmail.com', 'proton.me', 'mail.com',
    'gmx.com', 'gmx.net', 'zoho.com', 'yandex.com', 'rediffmail.com'
]);

/** Domains that host content or mail for anyone, so sharing one links strangers. */
const SHARED_PLATFORM_DOMAINS = new Set([
    'github.com', 'raw.githubusercontent.com', 'gitlab.com', 'bitbucket.org',
    'drive.google.com', 'docs.google.com', 'sites.google.com', 'storage.googleapis.com',
    'firebasestorage.googleapis.com', 'google.com', 'goo.gl', 'forms.gle',
    'dropbox.com', 'dl.dropboxusercontent.com', 'onedrive.live.com', '1drv.ms',
    'sharepoint.com', 'blob.core.windows.net', 'office.com', 'microsoft.com',
    'discord.com', 'cdn.discordapp.com', 'media.discordapp.net',
    's3.amazonaws.com', 'amazonaws.com', 'cloudfront.net', 'akamaihd.net',
    'mediafire.com', 'wetransfer.com', 'pastebin.com', 'archive.org',
    't.me', 'telegram.org', 'telegra.ph', 'bit.ly', 'tinyurl.com', 't.co',
    'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'youtube.com',
    'sendgrid.net', 'mailchimp.com', 'mailgun.org', 'amazonses.com'
]);

/** Provider networks whose address space is shared by unrelated customers. */
const PROVIDER_ASN_PATTERNS = [
    /google/i, /microsoft/i, /amazon/i, /aws/i, /cloudflare/i, /akamai/i,
    /digitalocean/i, /linode/i, /ovh/i, /hetzner/i, /godaddy/i, /namecheap/i,
    /fastly/i, /oracle/i, /alibaba/i, /tencent/i, /as15169/i, /as8075/i,
    /as16509/i, /as13335/i, /as14618/i, /as32934/i
];

/**
 * A low-specificity indicator seen across this many distinct cases is treated
 * as shared infrastructure. Set above any plausible number of genuinely
 * unrelated senders while staying below the size of a real mass campaign,
 * which is anyway correlated through its high-specificity indicators.
 */
const PREVALENCE_CASE_THRESHOLD = 8;

/**
 * Correlation factors grouped by what they actually evidence. Facts within one
 * group usually describe a single underlying observation - one attacker host
 * yields an IP, a domain and a URL - so they must not be summed as if they were
 * three independent proofs.
 */
const FACTOR_FAMILIES = {
    EXACT_HASH_MATCH: 'PAYLOAD',
    SHARED_URL: 'CONTENT',
    SEMANTIC_SIMILARITY: 'CONTENT',
    SHARED_SENDER_ADDRESS: 'IDENTITY',
    SHARED_IP: 'INFRASTRUCTURE',
    SHARED_DOMAIN_INFRASTRUCTURE: 'INFRASTRUCTURE',
    SHARED_ASN_PROVIDER: 'INFRASTRUCTURE',
    SHARED_EXECUTIVE_TARGET: 'TARGETING'
};

class CorrelationGuard {
    isFreemailDomain(domain) {
        return !!domain && FREEMAIL_DOMAINS.has(String(domain).toLowerCase());
    }

    isSharedPlatformDomain(domain) {
        return !!domain && SHARED_PLATFORM_DOMAINS.has(String(domain).toLowerCase());
    }

    isProviderAsn(asn) {
        if (!asn) return false;
        return PROVIDER_ASN_PATTERNS.some(pattern => pattern.test(String(asn)));
    }

    /**
     * Sending infrastructure belonging to a mail provider rather than to the
     * attacker. The forensic engine already identifies a provider egress hop;
     * that conclusion is reused here instead of being guessed at again.
     */
    isProviderSendingInfrastructure(threatObject) {
        const origin = threatObject.infrastructure?.origin;
        if (!origin) return false;
        const provider = String(origin.origin_provider || '');
        if (/google|microsoft|o365|outlook|amazon|sendgrid|mailchimp|mailgun/i.test(provider)) return true;
        return (origin.confidence_factors || []).some(f => f.factor === 'CLIENT_IP_OBSCURED_BY_PROVIDER' && f.status === 'SUPPORTED');
    }

    /**
     * Whether an indicator may be used to link cases into a campaign.
     * Returns { allowed, reason } so a suppressed link can be explained rather
     * than silently disappearing.
     */
    evaluateIndicator({ type, value, sharedCaseCount, threatObject }) {
        const lowered = String(value || '').toLowerCase();

        if (type === 'DOMAIN') {
            if (this.isFreemailDomain(lowered)) {
                return { allowed: false, reason: `${value} is a consumer mail provider used by unrelated senders, so sharing it does not indicate a shared operator.` };
            }
            if (this.isSharedPlatformDomain(lowered)) {
                return { allowed: false, reason: `${value} is a multi-tenant platform that hosts content for anyone, so sharing it does not indicate a shared operator.` };
            }
        }

        if (type === 'ASN') {
            if (this.isProviderAsn(lowered)) {
                return { allowed: false, reason: `${value} is a large hosting or cloud provider network shared by unrelated customers.` };
            }
        }

        if (type === 'IP' && this.isProviderSendingInfrastructure(threatObject)) {
            return { allowed: false, reason: `The observed sending address belongs to shared provider mail infrastructure, not to the sender's own network.` };
        }

        if (type === 'SENDER') {
            const senderDomain = lowered.split('@')[1];
            // The full address stays specific even on a consumer provider; only
            // the domain part is generic, and that is handled as a DOMAIN.
            if (!senderDomain) return { allowed: false, reason: 'Sender address could not be parsed.' };
        }

        // Prevalence only constrains low-specificity indicators. A phishing URL
        // or payload hash reused across many messages is a campaign, not noise.
        const lowSpecificity = type === 'DOMAIN' || type === 'ASN' || type === 'IP';
        if (lowSpecificity && sharedCaseCount >= PREVALENCE_CASE_THRESHOLD) {
            return {
                allowed: false,
                reason: `${value} appears across ${sharedCaseCount} unrelated cases in this deployment, which indicates shared infrastructure rather than one campaign.`
            };
        }

        return { allowed: true };
    }

    /**
     * Scores correlation from grouped factors. The strongest factor in each
     * family counts in full and further factors in that family at progressively
     * halved weight, so one attacker host observed as an IP, a domain and a URL
     * cannot masquerade as three independent confirmations.
     */
    scoreFactors(factors) {
        const grouped = new Map();
        factors.forEach(factor => {
            const family = FACTOR_FAMILIES[factor.factor] || 'OTHER';
            if (!grouped.has(family)) grouped.set(family, []);
            grouped.get(family).push(factor);
        });

        let total = 0;
        const breakdown = [];
        grouped.forEach((familyFactors, family) => {
            const sorted = familyFactors.sort((a, b) => b.weight - a.weight);
            const contribution = sorted.reduce((sum, factor, index) => sum + factor.weight / Math.pow(2, index), 0);
            total += contribution;
            breakdown.push({
                family,
                contribution: Number(contribution.toFixed(3)),
                strongest: sorted[0].factor,
                supporting_count: sorted.length - 1
            });
        });

        return {
            confidence: Number(Math.min(0.95, Math.max(0, total)).toFixed(2)),
            breakdown
        };
    }
}

module.exports = new CorrelationGuard();
module.exports.PREVALENCE_CASE_THRESHOLD = PREVALENCE_CASE_THRESHOLD;
