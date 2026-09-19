const dns = require('dns').promises;
const { dkimVerify } = require('mailauth');

/**
 * Independent, zero-cost email authentication analysis.
 *
 * Two distinct sources of truth are kept separate rather than merged into one
 * opaque pass/fail, per RFC 7208 (SPF), RFC 6376 (DKIM) and RFC 7489 (DMARC):
 *
 *  1. HEADER_CLAIMED  - the spf=/dkim=/dmarc= result already recorded by the
 *     receiving mail infrastructure (Gmail/Outlook/etc.) in the message's own
 *     Authentication-Results header (RFC 8601). This is authoritative for SPF
 *     because only the server that held the live SMTP connection knows the
 *     true connecting IP; PhishLens cannot re-derive that after delivery.
 *  2. INDEPENDENTLY_VERIFIED - for DKIM only, PhishLens re-verifies the
 *     cryptographic signature itself (message content + the signing domain's
 *     published DNS public key), which does not require live connection
 *     state and so can be checked accurately after the fact.
 *
 * A header claiming a result that our own independent check contradicts (for
 * example dkim=pass claimed but no valid signature actually verifies) is
 * itself a meaningful signal: a forged Authentication-Results header is a
 * known technique for tricking filters that trust the topmost header without
 * checking whether it was added at a trusted boundary.
 */
class AuthAnalyzer {
    parseAuthenticationResults(rawHeaderValue) {
        if (!rawHeaderValue) return { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', authserv_id: null };

        const authservMatch = rawHeaderValue.match(/^\s*([^;]+);/);
        const spfMatch = rawHeaderValue.match(/\bspf=([a-zA-Z]+)/i);
        const dkimMatch = rawHeaderValue.match(/\bdkim=([a-zA-Z]+)/i);
        const dmarcMatch = rawHeaderValue.match(/\bdmarc=([a-zA-Z]+)/i);

        return {
            spf: spfMatch ? spfMatch[1].toLowerCase() : 'unknown',
            dkim: dkimMatch ? dkimMatch[1].toLowerCase() : 'unknown',
            dmarc: dmarcMatch ? dmarcMatch[1].toLowerCase() : 'unknown',
            authserv_id: authservMatch ? authservMatch[1].trim() : null
        };
    }

    async verifyDkimIndependently(rawEmailString) {
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('DKIM verification timeout')), 4000)
            );
            const result = await Promise.race([
                dkimVerify(Buffer.from(rawEmailString || '', 'utf8')),
                timeoutPromise
            ]);

            const results = (result.results || []).map(r => ({
                result: r.status?.result || 'none',
                comment: r.status?.comment || null,
                signing_domain: r.signingDomain || null,
                selector: r.selector || null,
                algorithm: r.algo || null
            }));

            const overall = results.some(r => r.result === 'pass') ? 'pass'
                : results.some(r => r.result === 'fail') ? 'fail'
                : results.length > 0 ? results[0].result
                : 'none';

            return { status: 'AVAILABLE', overall, results };
        } catch (err) {
            return { status: 'UNAVAILABLE', overall: 'unknown', results: [], reason: err.message };
        }
    }

    async lookupDmarcPolicy(domain) {
        if (!domain) return { status: 'UNAVAILABLE', policy: null, reason: 'No domain provided' };
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('DMARC DNS lookup timeout')), 2500)
            );
            const records = await Promise.race([dns.resolveTxt(`_dmarc.${domain}`), timeoutPromise]);
            const txt = records.map(chunks => chunks.join('')).find(r => /^v=DMARC1/i.test(r));
            if (!txt) return { status: 'UNAVAILABLE', policy: null, reason: 'No DMARC TXT record published' };

            const policyMatch = txt.match(/\bp=([a-zA-Z]+)/i);
            const pctMatch = txt.match(/\bpct=(\d+)/i);
            return {
                status: 'AVAILABLE',
                policy: policyMatch ? policyMatch[1].toLowerCase() : null,
                percentage: pctMatch ? parseInt(pctMatch[1], 10) : 100,
                raw_record: txt
            };
        } catch (err) {
            return { status: 'UNAVAILABLE', policy: null, reason: err.message };
        }
    }

    async analyze(threatObject, parsedEmail, rawEmailString) {
        console.log('[AuthAnalyzer] Analyzing SPF/DKIM/DMARC authentication (header-claimed + independent DKIM verification)...');

        const authHeaders = parsedEmail?.authenticationResultsRaw || [];
        const claimed = this.parseAuthenticationResults(authHeaders[0]);

        const dkimIndependent = await this.verifyDkimIndependently(rawEmailString);

        const senderDomain = (parsedEmail?.from?.address || '').split('@')[1] || null;
        const dmarcPolicy = await this.lookupDmarcPolicy(senderDomain);

        let dkimHeaderMismatch = null;
        if (claimed.dkim !== 'unknown' && dkimIndependent.status === 'AVAILABLE') {
            if (claimed.dkim === 'pass' && dkimIndependent.overall !== 'pass') {
                dkimHeaderMismatch = `Authentication-Results header claims dkim=pass, but independent verification found: ${dkimIndependent.overall}`;
            } else if (claimed.dkim === 'none' && dkimIndependent.overall !== 'none') {
                dkimHeaderMismatch = `Authentication-Results header claims dkim=none, but a signature was independently found with result: ${dkimIndependent.overall}`;
            }
        }

        threatObject.forensics = threatObject.forensics || {};
        threatObject.forensics.authentication = {
            spf: claimed.spf,
            dkim: claimed.dkim,
            dmarc: claimed.dmarc,
            source: {
                spf: 'HEADER_CLAIMED',
                dkim: claimed.dkim !== 'unknown' ? 'HEADER_CLAIMED' : (dkimIndependent.status === 'AVAILABLE' ? 'INDEPENDENTLY_VERIFIED' : 'UNAVAILABLE'),
                dmarc: 'HEADER_CLAIMED'
            },
            authserv_id: claimed.authserv_id,
            all_authentication_results_headers: authHeaders,
            dkim_independent_verification: dkimIndependent,
            dkim_header_mismatch: dkimHeaderMismatch,
            dmarc_policy: dmarcPolicy,
            limitation: authHeaders.length === 0
                ? 'No Authentication-Results header was present on this message, so SPF/DMARC results are unknown. DKIM independent verification (if a DKIM-Signature header is present) is still authoritative regardless of this.'
                : 'SPF and DMARC results are trusted from the receiving mail server\'s own Authentication-Results header (PhishLens cannot re-derive SPF after delivery without the live connecting IP). DKIM is additionally re-verified independently by PhishLens.'
        };

        // If the header never claimed a DKIM result but we could independently verify one, use it as the primary dkim value.
        if (claimed.dkim === 'unknown' && dkimIndependent.status === 'AVAILABLE') {
            threatObject.forensics.authentication.dkim = dkimIndependent.overall;
        }

        return threatObject;
    }
}

module.exports = new AuthAnalyzer();
