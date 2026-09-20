const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Protection for the people an attacker most wants to impersonate or reach.
 *
 * The previous implementation carried four hardcoded names and matched them
 * with substring tests, so a message to `marketing-director@partner.example`
 * counted as an attack on a "Director", and no deployment could describe its
 * own leadership. This replaces it with an operator-managed directory and
 * matching precise enough to act on.
 *
 * What it looks for, in order of how much it actually proves:
 *
 *   Display-name impersonation - a protected person's name presented from an
 *   address that is not theirs. This is the core of CEO fraud and is strong
 *   evidence on its own, because the message is asserting an identity it does
 *   not hold.
 *
 *   Lookalike sending domain - a domain that is not the organisation's but sits
 *   within a small edit distance of one, which is how an attacker makes a
 *   spoofed address survive a glance.
 *
 *   Reply redirection while impersonating - replies to the "executive" routed
 *   somewhere else entirely.
 *
 *   Targeting of a protected person, and how often they have been targeted
 *   before. Being a recipient is not itself suspicious, so this contributes
 *   context rather than accusation.
 */

const MAX_TARGETING_HISTORY = 500;

class ExecutiveGuard {
    constructor() {
        this.configFile = path.join(__dirname, '../data/executive_directory.json');
        this.historyFile = path.join(__dirname, '../data/executive_targeting.json');
        this.people = [];
        this.organizationDomains = [];
        /** person id -> [{ case_id, at }] */
        this.targetingHistory = new Map();
        this.load();
    }

    load() {
        try {
            const dataDir = path.dirname(this.configFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

            if (fs.existsSync(this.configFile)) {
                const stored = JSON.parse(fs.readFileSync(this.configFile, 'utf8') || '{}');
                this.people = (stored.protected_people || []).filter(p => p && p.email);
                this.organizationDomains = (stored.organization_domains || []).map(d => String(d).toLowerCase());
            }

            if (fs.existsSync(this.historyFile)) {
                const history = JSON.parse(fs.readFileSync(this.historyFile, 'utf8') || '[]');
                history.forEach(entry => {
                    if (entry.person_id) this.targetingHistory.set(entry.person_id, entry.events || []);
                });
            }

            console.log(`[ExecutiveGuard] Protecting ${this.people.length} person(s) across ${this.organizationDomains.length} organisation domain(s).`);
        } catch (e) {
            console.error('[ExecutiveGuard] Directory load error:', e.message);
        }
    }

    save() {
        try {
            fs.writeFileSync(this.configFile, JSON.stringify({
                protected_people: this.people,
                organization_domains: this.organizationDomains,
                updated_at: new Date().toISOString()
            }, null, 2));
        } catch (e) {
            console.error('[ExecutiveGuard] Directory save error:', e.message);
        }
    }

    saveHistory() {
        try {
            const payload = Array.from(this.targetingHistory.entries())
                .map(([person_id, events]) => ({ person_id, events: events.slice(-MAX_TARGETING_HISTORY) }));
            fs.writeFileSync(this.historyFile, JSON.stringify(payload));
        } catch (e) {
            console.error('[ExecutiveGuard] Targeting history save error:', e.message);
        }
    }

    // ---------- matching helpers ----------

    normalizeName(name) {
        return String(name || '')
            .toLowerCase()
            .replace(/[^a-z\s]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    domainOf(address) {
        const match = String(address || '').toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})$/);
        return match ? match[1] : null;
    }

    /**
     * Whether a display name denotes a protected person. Compares whole name
     * tokens rather than substrings, so "Director of Partnerships" does not
     * match a person named "Director" and an unrelated word cannot trip it.
     */
    nameDenotes(displayName, person) {
        const shown = this.normalizeName(displayName);
        if (!shown) return false;

        const candidates = [person.name, ...(person.aliases || [])]
            .map(n => this.normalizeName(n))
            .filter(Boolean);

        for (const candidate of candidates) {
            if (shown === candidate) return true;

            // "Desai, Anita" and "Anita Desai" denote the same person; a single
            // shared token such as a common surname alone does not.
            const shownTokens = new Set(shown.split(' ').filter(t => t.length > 1));
            const candidateTokens = candidate.split(' ').filter(t => t.length > 1);
            if (candidateTokens.length >= 2 && candidateTokens.every(t => shownTokens.has(t))) return true;
        }
        return false;
    }

    editDistance(a, b) {
        const rows = a.length + 1;
        const cols = b.length + 1;
        const dist = Array.from({ length: rows }, (_, i) => [i, ...Array(cols - 1).fill(0)]);
        for (let j = 0; j < cols; j++) dist[0][j] = j;

        for (let i = 1; i < rows; i++) {
            for (let j = 1; j < cols; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                dist[i][j] = Math.min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost);
            }
        }
        return dist[rows - 1][cols - 1];
    }

    /** A domain close enough to an organisation domain to pass a glance. */
    lookalikeOrganizationDomain(domain) {
        if (!domain || this.organizationDomains.includes(domain)) return null;

        for (const orgDomain of this.organizationDomains) {
            const distance = this.editDistance(domain, orgDomain);
            // Scaled to length: two edits in a short domain is a different
            // domain, while two in a long one is a convincing imitation.
            const threshold = orgDomain.length <= 10 ? 1 : 2;
            if (distance > 0 && distance <= threshold) {
                return { organization_domain: orgDomain, edit_distance: distance };
            }
        }
        return null;
    }

    // ---------- evaluation ----------

    evaluateTarget(threatObject, parsedEmail) {
        const senderAddress = (parsedEmail?.from?.address || this.extractAddress(threatObject.message?.sender) || '').toLowerCase();
        const senderDisplay = parsedEmail?.from?.name || this.extractDisplayName(threatObject.message?.sender);
        const replyToAddress = (parsedEmail?.replyTo || '').toLowerCase();
        const recipients = (threatObject.message?.recipient || '').toLowerCase().split(/[,;]/).map(r => this.extractAddress(r)).filter(Boolean);

        const findings = [];
        let impersonated = null;
        let targeted = null;

        // 1. A protected person's name presented from an address that is not theirs.
        for (const person of this.people) {
            if (!this.nameDenotes(senderDisplay, person)) continue;
            if (senderAddress && senderAddress === String(person.email).toLowerCase()) continue;

            impersonated = person;
            findings.push({
                type: 'EXECUTIVE_DISPLAY_NAME_IMPERSONATION',
                severity: 'CRITICAL',
                confidence: 0.9,
                person: { id: person.id, name: person.name, title: person.title },
                explanation: `The sender presents the name "${senderDisplay}", which denotes ${person.name}${person.title ? ` (${person.title})` : ''}, but the message was sent from ${senderAddress || 'an unknown address'} rather than ${person.email}.`
            });
            break;
        }

        // 2. A sending domain shaped to be mistaken for the organisation's.
        const senderDomain = this.domainOf(senderAddress);
        const lookalike = this.lookalikeOrganizationDomain(senderDomain);
        if (lookalike) {
            findings.push({
                type: 'LOOKALIKE_ORGANIZATION_DOMAIN',
                severity: 'HIGH',
                confidence: 0.8,
                explanation: `The sending domain ${senderDomain} differs from the organisation domain ${lookalike.organization_domain} by only ${lookalike.edit_distance} character(s), which is unlikely to be noticed at a glance.`
            });
        }

        // 3. Replies redirected while impersonating a protected person.
        if (impersonated && replyToAddress && replyToAddress !== senderAddress) {
            findings.push({
                type: 'EXECUTIVE_REPLY_REDIRECTION',
                severity: 'CRITICAL',
                confidence: 0.88,
                explanation: `A message impersonating ${impersonated.name} routes replies to ${replyToAddress}, so a reply would reach the sender rather than the person named.`
            });
        }

        // 4. Whether a protected person is the recipient, and how often they
        //    have been targeted before. Context, not accusation.
        for (const person of this.people) {
            if (!recipients.includes(String(person.email).toLowerCase())) continue;
            targeted = person;

            const history = this.targetingHistory.get(person.id) || [];
            const priorCases = history.filter(h => h.case_id !== threatObject.case_id).length;

            findings.push({
                type: 'PROTECTED_PERSON_TARGETED',
                severity: priorCases >= 3 ? 'HIGH' : 'MEDIUM',
                confidence: priorCases >= 3 ? 0.7 : 0.5,
                person: { id: person.id, name: person.name, title: person.title },
                explanation: priorCases > 0
                    ? `${person.name}${person.title ? ` (${person.title})` : ''} is a protected recipient and has been the target of ${priorCases} previous flagged message(s), indicating sustained interest.`
                    : `${person.name}${person.title ? ` (${person.title})` : ''} is a protected recipient. Receiving mail is not itself suspicious; this raises the impact of any other finding.`
            });
            break;
        }

        threatObject.executive_context = {
            status: this.people.length ? 'EVALUATED' : 'NO_DIRECTORY_CONFIGURED',
            is_impersonated: !!impersonated,
            is_targeted: !!targeted,
            impersonated_person: impersonated ? { id: impersonated.id, name: impersonated.name, title: impersonated.title } : null,
            targeted_executive: targeted ? { id: targeted.id, name: targeted.name, title: targeted.title } : null,
            findings,
            protected_people_configured: this.people.length,
            limitation: this.people.length
                ? 'Detection covers the people and domains configured in this deployment. Someone not listed is not protected, and a name match indicates a claimed identity rather than a proven one.'
                : 'No protected people have been configured, so executive impersonation and targeting cannot be detected. Add them through the executive directory.'
        };

        if (targeted) this.recordTargeting(targeted.id, threatObject.case_id);
        return threatObject;
    }

    recordTargeting(personId, caseId) {
        const history = this.targetingHistory.get(personId) || [];
        if (history.some(h => h.case_id === caseId)) return;
        history.push({ case_id: caseId, at: new Date().toISOString() });
        this.targetingHistory.set(personId, history.slice(-MAX_TARGETING_HISTORY));
        this.saveHistory();
    }

    extractAddress(value) {
        const match = String(value || '').match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
        return match ? match[0].toLowerCase() : null;
    }

    extractDisplayName(value) {
        const match = String(value || '').match(/^\s*"?([^"<]+?)"?\s*</);
        return match ? match[1].trim() : '';
    }

    // ---------- directory management ----------

    addPerson({ name, title, email, aliases }) {
        const errors = [];
        if (!name || String(name).trim().length < 2) errors.push('name is required');
        if (!email || !/^[\w.+-]+@[\w.-]+\.[a-z]{2,}$/i.test(email)) errors.push('a valid email address is required');
        if (this.people.some(p => String(p.email).toLowerCase() === String(email).toLowerCase())) {
            errors.push(`${email} is already protected`);
        }
        if (errors.length) return { ok: false, errors };

        const person = {
            id: `VIP-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
            name: String(name).trim(),
            title: title ? String(title).trim() : null,
            email: String(email).toLowerCase(),
            aliases: Array.isArray(aliases) ? aliases.filter(a => typeof a === 'string' && a.trim()) : [],
            added_at: new Date().toISOString()
        };
        this.people.push(person);
        this.save();
        return { ok: true, person };
    }

    removePerson(id) {
        const before = this.people.length;
        this.people = this.people.filter(p => p.id !== id);
        if (this.people.length === before) return { ok: false, errors: [`No protected person with id "${id}"`] };
        this.targetingHistory.delete(id);
        this.save();
        this.saveHistory();
        return { ok: true };
    }

    setOrganizationDomains(domains) {
        if (!Array.isArray(domains)) return { ok: false, errors: ['domains must be an array'] };
        const cleaned = domains
            .map(d => String(d).toLowerCase().trim())
            .filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
        this.organizationDomains = Array.from(new Set(cleaned));
        this.save();
        return { ok: true, organization_domains: this.organizationDomains };
    }

    getDirectory() {
        return {
            protected_people: this.people.map(p => ({
                ...p,
                times_targeted: (this.targetingHistory.get(p.id) || []).length
            })),
            organization_domains: this.organizationDomains,
            limitation: this.people.length
                ? 'Only the people listed here are protected against impersonation and targeting detection.'
                : 'No protected people are configured, so executive protection is inactive.'
        };
    }

    /** Retained for the existing dashboard view and /api/vips consumers. */
    getVipList() {
        return this.getDirectory().protected_people;
    }
}

module.exports = new ExecutiveGuard();
