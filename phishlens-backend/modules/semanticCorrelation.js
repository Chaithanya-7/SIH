const caseManager = require('./caseManager');
const adaptiveLearning = require('./adaptiveLearning');

/**
 * Links messages that say the same thing, regardless of where they came from.
 *
 * Infrastructure correlation misses a campaign that rotates senders, domains
 * and hosts between sends - which is precisely what a competent operator does.
 * What tends not to change is the lure itself: the wording that was written
 * once and reused.
 *
 * Similarity is computed over the token characteristics already captured on
 * each case for adaptive learning, so this needs no additional storage and, in
 * particular, no retained message bodies. Jaccard overlap on those token sets
 * is deliberately simple and inspectable: an analyst can be shown exactly which
 * shared wording produced the link.
 */

/** Below this, overlap is ordinary business-English coincidence rather than a shared lure. */
const SIMILARITY_THRESHOLD = 0.55;
/** Too few tokens to judge; short messages overlap by chance. */
const MIN_TOKENS = 8;
/** Bounds the comparison cost per message on a large case store. */
const MAX_CASES_COMPARED = 400;

class SemanticCorrelation {
    tokenSet(features) {
        return new Set(
            (features || [])
                .filter(f => typeof f === 'string' && f.startsWith('token:'))
                .map(f => f.slice(6))
        );
    }

    jaccard(a, b) {
        if (a.size === 0 || b.size === 0) return 0;
        let intersection = 0;
        const [smaller, larger] = a.size <= b.size ? [a, b] : [b, a];
        smaller.forEach(token => { if (larger.has(token)) intersection++; });
        const union = a.size + b.size - intersection;
        return union === 0 ? 0 : intersection / union;
    }

    sharedTerms(a, b, limit = 8) {
        const shared = [];
        a.forEach(token => { if (b.has(token) && shared.length < limit) shared.push(token); });
        return shared;
    }

    /**
     * Finds previously seen cases whose wording closely matches this one.
     * Returns matches with the shared terms that produced them, so the link is
     * explainable rather than asserted.
     */
    findSimilarCases(threatObject, parsedEmail) {
        // Tokenised from the message directly rather than from
        // threatObject.learning_features, which is not populated until after
        // correlation runs. Stored cases do carry those features, so the two
        // sides are compared using the same tokeniser.
        const current = parsedEmail
            ? new Set(adaptiveLearning.tokenize(`${parsedEmail.subject || ''} ${parsedEmail.textBody || ''}`))
            : this.tokenSet(threatObject.learning_features);

        if (current.size < MIN_TOKENS) {
            return { comparable: false, reason: 'Too little distinctive wording to compare reliably.', matches: [] };
        }

        const matches = [];
        const cases = caseManager.getAllCases();
        const recent = cases.slice(-MAX_CASES_COMPARED);

        for (const other of recent) {
            if (!other || other.case_id === threatObject.case_id) continue;
            const otherTokens = this.tokenSet(other.learning_features);
            if (otherTokens.size < MIN_TOKENS) continue;

            const score = this.jaccard(current, otherTokens);
            if (score >= SIMILARITY_THRESHOLD) {
                matches.push({
                    case_id: other.case_id,
                    similarity: Number(score.toFixed(2)),
                    shared_terms: this.sharedTerms(current, otherTokens),
                    subject: other.message?.subject || '(No Subject)'
                });
            }
        }

        matches.sort((a, b) => b.similarity - a.similarity);
        return {
            comparable: true,
            matches: matches.slice(0, 25),
            compared_against: recent.length,
            limitation: 'Wording similarity indicates a reused lure, not a confirmed common operator. Templated legitimate mail from different senders can also overlap.'
        };
    }
}

module.exports = new SemanticCorrelation();
module.exports.SIMILARITY_THRESHOLD = SIMILARITY_THRESHOLD;
