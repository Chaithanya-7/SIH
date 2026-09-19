const fs = require('fs');
const path = require('path');

/**
 * Adaptive, real-time learning from confirmed verdicts.
 *
 * When a message is confirmed malicious, this engine breaks it into discrete
 * characteristics - the words it used, the domain and TLD it came from, the
 * hosts it linked to, the attachment types it carried, the rules it tripped,
 * the authentication state it arrived in - and records how often each of those
 * characteristics appears in malicious mail versus legitimate mail. Later
 * messages sharing those characteristics are scored accordingly. Learning is
 * immediate: there is no batch retraining step and no model to download.
 *
 * Deliberate design constraints:
 *
 *  - Explainable. Scoring is a log-odds sum over individual characteristics, so
 *    the engine can always state exactly which characteristics drove a score
 *    and how strongly. Nothing here is a black box.
 *  - Local. Everything is learned from, and stored on, this machine. No model
 *    is fetched, nothing is uploaded, and no external service is contacted.
 *  - Evidence, not verdict. It contributes one signal into evidence fusion
 *    alongside the deterministic rules; it never overrides them.
 *  - Honest when untrained. Below a minimum amount of labelled data it reports
 *    that it is not ready and contributes nothing, rather than emitting a
 *    confident-looking number derived from two examples.
 *
 * Analyst decisions are trusted more than the system's own high-confidence
 * detections, and the system only self-labels corroborated detections, so it
 * cannot spiral on its own mistakes.
 */

const STOPWORDS = new Set([
    'the', 'and', 'for', 'you', 'your', 'this', 'that', 'with', 'from', 'have',
    'has', 'are', 'was', 'were', 'will', 'would', 'can', 'could', 'should',
    'our', 'out', 'not', 'but', 'all', 'any', 'may', 'been', 'being', 'they',
    'their', 'them', 'there', 'here', 'what', 'when', 'which', 'who', 'how',
    'please', 'thanks', 'thank', 'regards', 'hello', 'dear', 'best', 'get',
    'about', 'into', 'more', 'than', 'then', 'also', 'just', 'like', 'over'
]);

/** A characteristic must be seen this many times before it may influence a score. */
const MIN_FEATURE_OBSERVATIONS = 3;
/** Minimum labelled examples of each class before the engine will score at all. */
const MIN_LABELS_PER_CLASS = 5;
/** Laplace smoothing constant. */
const ALPHA = 1;
/** Bound on how much one characteristic may push a score, to limit poisoning. */
const MAX_FEATURE_WEIGHT = 2.5;
const MAX_VOCABULARY = 20000;
const MAX_TOKENS_PER_MESSAGE = 150;

class AdaptiveLearning {
    constructor() {
        this.storageFile = path.join(__dirname, '../data/learned_model.json');
        /** feature -> { malicious: n, benign: n } */
        this.features = new Map();
        this.totals = { malicious: 0, benign: 0 };
        this.history = [];
        /** case_id -> { label, features } for the lesson currently applied from that case. */
        this.learnedCases = new Map();
        this.loadStorage();
    }

    loadStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            if (!fs.existsSync(this.storageFile)) return;

            const stored = JSON.parse(fs.readFileSync(this.storageFile, 'utf8') || '{}');
            (stored.features || []).forEach(f => {
                if (f.feature) this.features.set(f.feature, { malicious: f.malicious || 0, benign: f.benign || 0 });
            });
            this.totals = stored.totals || { malicious: 0, benign: 0 };
            this.history = stored.history || [];
            (stored.learned_cases || []).forEach(c => {
                if (c.case_id) this.learnedCases.set(c.case_id, { label: c.label, features: c.features || [] });
            });
            console.log(`[AdaptiveLearning] Loaded local model: ${this.features.size} characteristic(s) from ${this.totals.malicious} malicious and ${this.totals.benign} legitimate example(s).`);
        } catch (e) {
            console.error('[AdaptiveLearning] Model load error:', e.message);
        }
    }

    saveStorage() {
        try {
            const payload = {
                version: 'PHISHLENS_ADAPTIVE_V1',
                totals: this.totals,
                features: Array.from(this.features.entries()).map(([feature, counts]) => ({ feature, ...counts })),
                learned_cases: Array.from(this.learnedCases.entries()).map(([case_id, v]) => ({ case_id, label: v.label, features: v.features })),
                history: this.history.slice(-200),
                updated_at: new Date().toISOString()
            };
            fs.writeFileSync(this.storageFile, JSON.stringify(payload, null, 2));
        } catch (e) {
            console.error('[AdaptiveLearning] Model save error:', e.message);
        }
    }

    tokenize(text) {
        return (text || '')
            .toLowerCase()
            .replace(/https?:\/\/\S+/g, ' ')
            .replace(/[^a-z0-9\s]/g, ' ')
            .split(/\s+/)
            .filter(t => t.length >= 3 && t.length <= 24 && !STOPWORDS.has(t) && !/^\d+$/.test(t));
    }

    /**
     * Breaks a message into the discrete characteristics the engine learns over.
     * Structural and behavioural characteristics matter as much as wording -
     * attackers change wording far more easily than they change infrastructure.
     */
    extractFeatures(threatObject, parsedEmail) {
        const features = new Set();

        const subject = parsedEmail?.subject || threatObject.message?.subject || '';
        const body = parsedEmail?.textBody || '';
        this.tokenize(`${subject} ${body}`).slice(0, MAX_TOKENS_PER_MESSAGE)
            .forEach(t => features.add(`token:${t}`));

        const fromAddress = (parsedEmail?.from?.address || '').toLowerCase();
        const senderDomain = fromAddress.split('@')[1];
        if (senderDomain) {
            features.add(`sender_domain:${senderDomain}`);
            const tld = senderDomain.split('.').pop();
            if (tld) features.add(`sender_tld:${tld}`);
        }

        (threatObject.iocs?.urls || []).forEach(url => {
            try {
                const host = new URL(url).hostname.toLowerCase();
                features.add(`url_host:${host}`);
                const tld = host.split('.').pop();
                if (tld) features.add(`url_tld:${tld}`);
            } catch (e) { /* malformed URL contributes no host characteristic */ }
        });

        (threatObject.attachments || []).forEach(a => {
            if (a.extension) features.add(`attachment_ext:${a.extension}`);
            if (a.mime_type) features.add(`attachment_mime:${a.mime_type}`);
        });

        const auth = threatObject.forensics?.authentication || {};
        ['spf', 'dkim', 'dmarc'].forEach(mechanism => {
            if (auth[mechanism] && auth[mechanism] !== 'unknown') {
                features.add(`auth:${mechanism}=${auth[mechanism]}`);
            }
        });

        (threatObject.threat_intelligence?.matches || []).forEach(m => {
            features.add(`intel:${m.indicator_type}_${m.matched}`);
            if (m.feed) features.add(`intel_feed:${m.feed}`);
        });

        // Bucketed rather than exact, so the characteristic generalises to the
        // next freshly-registered domain instead of memorising this one.
        (threatObject.threat_intelligence?.domain_ages || []).forEach(d => {
            if (d.status !== 'AVAILABLE' || d.age_days === null) return;
            const bucket = d.age_days <= 7 ? '0-7d' : d.age_days <= 30 ? '8-30d' : d.age_days <= 365 ? '31-365d' : 'over-1y';
            features.add(`${d.is_sender_domain ? 'sender' : 'linked'}_domain_age:${bucket}`);
        });

        (threatObject.detection?.matched_rules || []).forEach(r => features.add(`rule:${r.id}`));
        (threatObject.nlp?.signals || []).forEach(s => features.add(`nlp:${s.type}`));
        (threatObject.behavioral?.signals || []).forEach(s => features.add(`behaviour:${s.type}`));

        if (threatObject.forensics?.return_path_mismatch) features.add('structure:return_path_mismatch');
        if (parsedEmail?.replyTo && parsedEmail.replyTo.split('@')[1] !== senderDomain) {
            features.add('structure:reply_to_domain_mismatch');
        }
        if (parsedEmail?.htmlBody && !parsedEmail?.textBody) features.add('structure:html_only');
        if ((threatObject.attachments || []).length > 0) features.add('structure:has_attachment');
        if ((threatObject.iocs?.urls || []).length > 0) features.add('structure:has_links');

        return Array.from(features);
    }

    /** Log-odds weight of one characteristic, bounded and smoothed. */
    featureWeight(feature) {
        const counts = this.features.get(feature);
        if (!counts) return 0;

        const observations = counts.malicious + counts.benign;
        if (observations < MIN_FEATURE_OBSERVATIONS) return 0;

        const vocabulary = Math.max(this.features.size, 1);
        const pMalicious = (counts.malicious + ALPHA) / (this.totals.malicious + ALPHA * vocabulary);
        const pBenign = (counts.benign + ALPHA) / (this.totals.benign + ALPHA * vocabulary);
        const weight = Math.log(pMalicious / pBenign);

        return Math.max(-MAX_FEATURE_WEIGHT, Math.min(MAX_FEATURE_WEIGHT, weight));
    }

    isReady() {
        return this.totals.malicious >= MIN_LABELS_PER_CLASS && this.totals.benign >= MIN_LABELS_PER_CLASS;
    }

    /**
     * Scores a message against everything learned so far and attaches an
     * explainable result to the ThreatObject.
     */
    score(threatObject, parsedEmail) {
        // Extracted regardless of readiness and stored on the case, so that an
        // analyst decision made days later can still teach the model without
        // the message body having been retained anywhere.
        const features = this.extractFeatures(threatObject, parsedEmail);
        threatObject.learning_features = features;

        if (!this.isReady()) {
            threatObject.adaptive = {
                status: 'INSUFFICIENT_TRAINING_DATA',
                engine: 'PHISHLENS_ADAPTIVE_V1',
                learned_from: { malicious: this.totals.malicious, legitimate: this.totals.benign },
                score: 0,
                contributions: [],
                limitation: `Adaptive learning needs at least ${MIN_LABELS_PER_CLASS} confirmed malicious and ${MIN_LABELS_PER_CLASS} confirmed legitimate messages before it will score anything. Until then it contributes no evidence.`
            };
            return threatObject;
        }

        const contributions = [];
        let logOdds = 0;

        features.forEach(feature => {
            const weight = this.featureWeight(feature);
            if (weight === 0) return;
            logOdds += weight;
            const counts = this.features.get(feature);
            contributions.push({
                characteristic: feature,
                weight: Number(weight.toFixed(3)),
                seen_in_malicious: counts.malicious,
                seen_in_legitimate: counts.benign
            });
        });

        contributions.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
        const probability = 1 / (1 + Math.exp(-logOdds));

        threatObject.adaptive = {
            status: 'SCORED',
            engine: 'PHISHLENS_ADAPTIVE_V1',
            learned_from: { malicious: this.totals.malicious, legitimate: this.totals.benign },
            score: Number(probability.toFixed(3)),
            matched_characteristics: contributions.length,
            contributions: contributions.slice(0, 12),
            limitation: 'This score reflects characteristics this installation has previously seen in confirmed mail. It is corroborating evidence and never establishes maliciousness on its own.'
        };

        return threatObject;
    }

    /**
     * Learns from a message whose true nature is known.
     *
     * @param {'malicious'|'benign'} label
     * @param {'ANALYST_CONFIRMED'|'ANALYST_RELEASED'|'HIGH_CONFIDENCE_DETECTION'|'USER_REPORTED'} source
     */
    learn(threatObject, parsedEmail, label, source) {
        if (label !== 'malicious' && label !== 'benign') return null;

        // A decision reached later replays the characteristics captured at
        // analysis time; only a live pipeline run has the parsed message.
        // An empty list means nothing was captured (e.g. a case analysed before
        // adaptive learning existed), so fall back to deriving what can still be
        // derived from the stored case itself.
        const features = parsedEmail
            ? this.extractFeatures(threatObject, parsedEmail)
            : (threatObject.learning_features?.length
                ? threatObject.learning_features
                : this.extractFeatures(threatObject, null));

        if (!features.length) return null;

        const caseId = threatObject.case_id;
        const previous = caseId ? this.learnedCases.get(caseId) : null;

        // One message must never count twice. A message can be self-labelled by
        // a high-confidence detection and then reviewed by an analyst, and
        // counting both would let a single message weigh as two examples.
        if (previous && previous.label === label) {
            return { label, source, characteristics_learned: 0, already_learned: true };
        }

        // An analyst overturning an earlier label means the earlier lesson was
        // wrong. Withdrawing it matters more than recording the new one: this is
        // where a false positive the system taught itself gets corrected instead
        // of entrenched.
        let withdrawn = 0;
        if (previous) {
            previous.features.forEach(feature => {
                const counts = this.features.get(feature);
                if (counts && counts[previous.label] > 0) counts[previous.label] -= 1;
            });
            if (this.totals[previous.label] > 0) this.totals[previous.label] -= 1;
            withdrawn = previous.features.length;
        }

        features.forEach(feature => {
            if (!this.features.has(feature)) {
                if (this.features.size >= MAX_VOCABULARY) return;
                this.features.set(feature, { malicious: 0, benign: 0 });
            }
            this.features.get(feature)[label] += 1;
        });

        this.totals[label] += 1;
        if (caseId) this.learnedCases.set(caseId, { label, features });

        this.history.push({
            case_id: caseId,
            label,
            source,
            characteristics_learned: features.length,
            corrected_previous_label: previous ? previous.label : null,
            learned_at: new Date().toISOString()
        });

        this.saveStorage();

        const correction = previous ? ` Corrected an earlier '${previous.label}' label and withdrew ${withdrawn} characteristic count(s).` : '';
        console.log(`[AdaptiveLearning] Learned ${features.length} characteristic(s) from ${caseId} as ${label} (${source}).${correction} Model now holds ${this.totals.malicious} malicious / ${this.totals.benign} legitimate example(s).`);

        return { label, source, characteristics_learned: features.length, corrected_previous_label: previous ? previous.label : null };
    }

    /**
     * Self-labelling of the system's own detections.
     *
     * Only corroborated detections qualify: a high score that rests on a single
     * evidence family is exactly the kind of call an analyst most often
     * overturns, and learning from it would entrench the mistake.
     */
    learnFromDetection(threatObject, parsedEmail) {
        const score = threatObject.confidence?.threat || 0;
        const families = new Set((threatObject.confidence?.contributions || []).map(c => c.family));

        if (threatObject.detection?.verdict === 'HIGH_RISK' && score >= 0.85 && families.size >= 3) {
            return this.learn(threatObject, parsedEmail, 'malicious', 'HIGH_CONFIDENCE_DETECTION');
        }
        return null;
    }

    getStats() {
        return {
            ready: this.isReady(),
            characteristics_known: this.features.size,
            learned_from: { malicious: this.totals.malicious, legitimate: this.totals.benign },
            minimum_required_per_class: MIN_LABELS_PER_CLASS,
            recent_learning_events: this.history.slice(-10).reverse()
        };
    }

    /**
     * The characteristics most strongly associated with malicious mail in this
     * deployment, for the analyst-facing "what has it learned" view.
     */
    getTopIndicators(limit = 25) {
        return Array.from(this.features.entries())
            .filter(([, c]) => c.malicious + c.benign >= MIN_FEATURE_OBSERVATIONS)
            .map(([feature, counts]) => ({
                characteristic: feature,
                weight: Number(this.featureWeight(feature).toFixed(3)),
                seen_in_malicious: counts.malicious,
                seen_in_legitimate: counts.benign
            }))
            .filter(f => f.weight > 0)
            .sort((a, b) => b.weight - a.weight)
            .slice(0, limit);
    }
}

module.exports = new AdaptiveLearning();
