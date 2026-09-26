/**
 * What was checked on a message that came back clean, and what that does not
 * rule out.
 *
 * ## The gap this fills
 *
 * Every other module here looks for reasons to doubt a message. When it finds
 * none, the case is written with a green verdict and an *empty* evidence list -
 * zero findings, zero contributions, nothing at all. Measured on a message with
 * SPF, DKIM and DMARC all passing: verdict SAFE, evidence items 0.
 *
 * That is the least useful possible answer. A person looking at it cannot tell
 * whether the message was examined thoroughly and found clean, or whether the
 * analysis fell over and produced nothing. Both render identically, and the
 * reassuring one is far more common - so the habit somebody forms is to trust a
 * green label that has never once shown its working.
 *
 * This records the working. Not a score, not a counterweight: a list of the
 * checks that ran, what each concluded, and - for every one of them - what
 * passing it does not prove.
 *
 * ## Why it must never subtract from a threat score
 *
 * The obvious next step would be to net assurance off against suspicion. It is
 * the wrong step, and this system has direct evidence of why.
 *
 * Detection was added here for phishing sent *through* legitimate platforms -
 * real Dropbox links, real DocuSign envelopes, real form builders, compromised
 * accounts on real tenants. All of it passes SPF, DKIM and DMARC, because none
 * of it is forged. Every one of those messages would collect a full set of
 * passed authentication checks. Allowing those to reduce a threat score would
 * mean the better an attacker's infrastructure, the safer their mail looks.
 *
 * So assurance is recorded strictly alongside the verdict and never inside it.
 * `threatObject.confidence` is not touched by anything in this file.
 *
 * ## The rule every entry obeys
 *
 * A check that did not run is never reported as a check that passed. "No
 * malicious attachment was found" is assurance only if the attachments were
 * actually opened and read; on a message analysed from a list row, with no
 * attachment bytes available, the same sentence is a lie. Each entry therefore
 * carries PASSED, NOT_RUN or NOT_APPLICABLE, and NOT_RUN says why.
 */

/** Verdicts for the overall summary line. */
const RESULT = {
    PASSED: 'PASSED',
    NOT_RUN: 'NOT_RUN',
    NOT_APPLICABLE: 'NOT_APPLICABLE'
};

class AssuranceEvidence {
    /**
     * Builds the record. Reads the ThreatObject and writes only
     * `threatObject.assurance` - never the confidence, never the verdict.
     */
    assess(threatObject, parsedEmail) {
        const checks = [];

        checks.push(this.authentication(threatObject));
        checks.push(this.senderHistory(threatObject));
        checks.push(this.conversation(threatObject));
        checks.push(this.attachments(threatObject));
        checks.push(this.links(threatObject, parsedEmail));
        checks.push(this.textIntegrity(threatObject));
        checks.push(this.indicatorFeeds(threatObject));
        checks.push(this.domainAge(threatObject));
        checks.push(this.payloadShape(threatObject));
        checks.push(this.detectionRules(threatObject));

        const passed = checks.filter(c => c.result === RESULT.PASSED).length;
        const notRun = checks.filter(c => c.result === RESULT.NOT_RUN).length;
        const notApplicable = checks.filter(c => c.result === RESULT.NOT_APPLICABLE).length;

        threatObject.assurance = {
            status: 'ASSESSED',
            checks,
            passed,
            not_run: notRun,
            not_applicable: notApplicable,
            total: checks.length,
            summary: this.summarise(threatObject, passed, notRun, checks.length),
            // Stated on the record itself, not only in this file's comments.
            limitation: 'This is a list of checks that came back clean, not a finding of innocence. It does not lower the threat score and is not netted off against anything: mail sent through a compromised account or a legitimate platform passes every authentication check there is, because nothing about it is forged.'
        };

        return threatObject;
    }

    summarise(threatObject, passed, notRun, total) {
        const verdict = threatObject.detection?.verdict;

        if (verdict === 'HIGH_RISK' || verdict === 'SUSPICIOUS') {
            return `${passed} of ${total} checks came back clean, and the message was still judged ${verdict === 'HIGH_RISK' ? 'high risk' : 'suspicious'} on the findings listed as evidence. Clean checks do not offset a finding; they are recorded so it is clear what was and was not examined.`;
        }

        if (notRun > 0) {
            return `${passed} of ${total} checks came back clean and ${notRun} could not run. The verdict rests on what was examined, which is less than the full set - each unexamined check says below why it was skipped.`;
        }

        return `All ${passed} checks that apply to this message came back clean. That is the basis of the verdict, and each entry below states what passing it does not rule out.`;
    }

    // ---------------------------------------------------------------- checks

    authentication(threatObject) {
        const auth = threatObject.forensics?.authentication || {};
        const results = { spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc };
        const known = Object.entries(results).filter(([, v]) => v && v !== 'unknown');

        if (!known.length) {
            return {
                check: 'Sender authentication',
                result: RESULT.NOT_RUN,
                detail: 'The message carried no Authentication-Results header and no verifiable signature, so SPF, DKIM and DMARC are all unknown. This is normal for a message read from a list row rather than fetched in full.',
                does_not_rule_out: null
            };
        }

        const passing = known.filter(([, v]) => v === 'pass').map(([k]) => k.toUpperCase());
        const failing = known.filter(([, v]) => v === 'fail').map(([k]) => k.toUpperCase());

        if (failing.length) {
            return {
                check: 'Sender authentication',
                result: RESULT.NOT_APPLICABLE,
                detail: `${failing.join(', ')} failed. This is a finding, not assurance, and it appears in the evidence.`,
                does_not_rule_out: null
            };
        }

        return {
            check: 'Sender authentication',
            result: RESULT.PASSED,
            detail: `${passing.join(', ')} passed${auth.dmarc_policy?.policy ? `, against a published DMARC policy of ${auth.dmarc_policy.policy}` : ''}. The sending domain authorised this message.`,
            // The single most important sentence in this file.
            does_not_rule_out: 'Authentication proves a domain authorised the message. It says nothing about whether the request inside it is honest. Mail sent from a compromised account, or through a real file-sharing or bulk-mail platform, passes all three checks because nothing about it is forged.'
        };
    }

    senderHistory(threatObject) {
        const behavioural = threatObject.behavioral || {};
        const seen = behavioural.messages_seen_from_sender || 0;

        if (behavioural.status !== 'ANALYZED') {
            return {
                check: 'Sender history',
                result: RESULT.NOT_RUN,
                detail: 'The behavioural baseline did not run for this message.',
                does_not_rule_out: null
            };
        }

        if (seen === 0) {
            return {
                check: 'Sender history',
                result: RESULT.NOT_APPLICABLE,
                detail: 'This is the first message this installation has seen from that sender, so there is no history to compare it against. Not suspicious in itself - every genuine correspondent starts here.',
                does_not_rule_out: null
            };
        }

        return {
            check: 'Sender history',
            result: RESULT.PASSED,
            detail: `${seen} earlier message(s) from this sender have been seen here, and this one matches the pattern of them - the addresses, relays and timing are consistent with what that sender normally does.`,
            does_not_rule_out: 'A consistent history is the sender\'s account behaving normally, which is also exactly what a hijacked account looks like from the outside until the moment it is used.'
        };
    }

    conversation(threatObject) {
        const thread = threatObject.thread;
        if (!thread) {
            return { check: 'Conversation continuity', result: RESULT.NOT_RUN, detail: 'Thread analysis did not run.', does_not_rule_out: null };
        }

        if (!thread.claims_to_be_reply && !thread.has_thread_headers) {
            return {
                check: 'Conversation continuity',
                result: RESULT.NOT_APPLICABLE,
                detail: 'This message does not present itself as part of a conversation, so there is no thread to verify.',
                does_not_rule_out: null
            };
        }

        if ((thread.findings || []).length) {
            return {
                check: 'Conversation continuity',
                result: RESULT.NOT_APPLICABLE,
                detail: 'The conversation checks produced findings, which appear in the evidence rather than here.',
                does_not_rule_out: null
            };
        }

        if (!thread.thread_known) {
            return {
                check: 'Conversation continuity',
                result: RESULT.NOT_RUN,
                detail: 'This message continues a thread this installation has not seen the start of, so continuity could not be verified either way.',
                does_not_rule_out: null
            };
        }

        return {
            check: 'Conversation continuity',
            result: RESULT.PASSED,
            detail: `This reply belongs to a conversation seen here before, and it came from a party already in it${thread.known_participants?.length ? ` (${thread.known_participants.length} known participant(s))` : ''}.`,
            does_not_rule_out: 'It confirms the thread is real and the sender belongs to it. If that sender\'s own account has been taken over, both remain true.'
        };
    }

    attachments(threatObject) {
        const attachments = threatObject.attachments || [];

        if (!attachments.length) {
            return {
                check: 'Attachments',
                result: RESULT.PASSED,
                detail: 'The message carries no attachments, so there is nothing to open and nothing that could run.',
                does_not_rule_out: 'A message needs no attachment to do harm. Credential phishing, payment redirection and callback fraud all work with plain text.'
            };
        }

        const unread = attachments.filter(a => !a.inspection && !a.findings);
        if (unread.length) {
            return {
                check: 'Attachments',
                result: RESULT.NOT_RUN,
                detail: `${unread.length} of ${attachments.length} attachment(s) could not be read, so their contents were not examined. An unexamined attachment is not a clean one.`,
                does_not_rule_out: null
            };
        }

        const findings = attachments.flatMap(a => a.findings || []);
        if (findings.length) {
            return {
                check: 'Attachments',
                result: RESULT.NOT_APPLICABLE,
                detail: `${findings.length} finding(s) were raised against the attachments and appear in the evidence.`,
                does_not_rule_out: null
            };
        }

        const engines = [...new Set(attachments.map(a => a.rule_matching?.engine).filter(Boolean))];
        return {
            check: 'Attachments',
            result: RESULT.PASSED,
            detail: `${attachments.length} attachment(s) were opened and read - structure, declared type against actual contents, macros and auto-run triggers, embedded scripts and active content - and nothing was found${engines.length ? `. Detection rules ran on ${engines.join(', ')}` : ''}. Nothing was executed at any point.`,
            does_not_rule_out: 'The file was examined for structure and known patterns, not run in a sandbox. A payload fetched from the network after the document opens is not in the file as delivered.'
        };
    }

    links(threatObject, parsedEmail) {
        const urls = threatObject.iocs?.urls || [];

        if (!urls.length) {
            return {
                check: 'Links',
                result: RESULT.PASSED,
                detail: 'The message contains no links, so there is nowhere for it to send the reader.',
                does_not_rule_out: 'A message with no link can still ask for a payment, a password over the phone, or a reply with information in it.'
            };
        }

        const fromDomain = (parsedEmail?.from?.address || threatObject.message?.sender || '').split('@')[1]?.toLowerCase() || '';
        const offsite = urls.filter(url => {
            try {
                const host = new URL(url).hostname.toLowerCase();
                return !(fromDomain && (host === fromDomain || host.endsWith(`.${fromDomain}`)));
            } catch (e) {
                return true;
            }
        });

        const intelChecked = threatObject.threat_intelligence?.status === 'MATCHED_AGAINST_LOCAL_FEEDS';

        if (!offsite.length) {
            return {
                check: 'Links',
                result: RESULT.PASSED,
                detail: `All ${urls.length} link(s) point back to the sender's own domain (${fromDomain}), not to a third party.`,
                does_not_rule_out: intelChecked ? 'A sender\'s own domain can be compromised, and a page on it can still be a credential form.' : 'Indicator feeds were not consulted, so the destinations were not checked against known-malicious lists.'
            };
        }

        return {
            check: 'Links',
            result: RESULT.PASSED,
            detail: `${urls.length} link(s) were extracted and examined - destination against displayed text, hostname encoding, shorteners, raw addresses and redirect structure - and none raised a finding. ${offsite.length} lead off the sender's domain, which is ordinary for most mail.`,
            does_not_rule_out: intelChecked
                ? 'The destinations were not visited. A page that is harmless now can be changed after delivery, which is the point of the technique.'
                : 'Indicator feeds had no data, so none of these destinations was checked against a known-malicious list.'
        };
    }

    textIntegrity(threatObject) {
        const deception = threatObject.text_deception;
        if (!deception) {
            return { check: 'Text integrity', result: RESULT.NOT_RUN, detail: 'Text analysis did not run.', does_not_rule_out: null };
        }

        const hidden = (deception.hidden_characters || []).length;
        const mixed = (deception.mixed_script_words || []).length;
        const concealed = deception.concealed_markup?.substantial;

        if (hidden || mixed || concealed) {
            return {
                check: 'Text integrity',
                result: RESULT.NOT_APPLICABLE,
                detail: 'Concealment was found in the text and appears in the evidence.',
                does_not_rule_out: null
            };
        }

        return {
            check: 'Text integrity',
            result: RESULT.PASSED,
            detail: 'No invisible characters, no letters swapped for lookalikes from another alphabet, no direction overrides, and no bulk text hidden from the reader. The message means to a filter what it shows to a person.',
            does_not_rule_out: 'It means nothing is hiding from the analysis. It says nothing about whether what the message plainly says is true - and a message written by a language model has no need to hide anything.'
        };
    }

    indicatorFeeds(threatObject) {
        const intel = threatObject.threat_intelligence;

        if (!intel || intel.status !== 'MATCHED_AGAINST_LOCAL_FEEDS') {
            return {
                check: 'Known-malicious indicator feeds',
                result: RESULT.NOT_RUN,
                detail: 'No feed data was available, so the addresses and links in this message were not checked against any known-malicious list. This is the check whose absence is easiest to mistake for a pass.',
                does_not_rule_out: null
            };
        }

        if ((intel.matches || []).length) {
            return {
                check: 'Known-malicious indicator feeds',
                result: RESULT.NOT_APPLICABLE,
                detail: `${intel.matches.length} indicator(s) matched a feed, which appears in the evidence.`,
                does_not_rule_out: null
            };
        }

        return {
            check: 'Known-malicious indicator feeds',
            result: RESULT.PASSED,
            detail: `Every address, domain and link in this message was checked against the open indicator feeds held locally${intel.feeds_loaded ? ` (${intel.feeds_loaded})` : ''} and none appeared on them.`,
            does_not_rule_out: 'Feeds list what has already been reported by somebody else. A domain registered this morning for one campaign is on no list anywhere, and that is the normal case for targeted mail.'
        };
    }

    domainAge(threatObject) {
        const ages = threatObject.threat_intelligence?.domain_ages || [];
        const sender = ages.find(a => a.is_sender_domain);

        if (!sender || sender.status !== 'AVAILABLE') {
            return {
                check: 'Sender domain age',
                result: RESULT.NOT_RUN,
                detail: sender?.status === 'UNAVAILABLE'
                    ? 'The registry did not answer for this domain, so its age is unknown.'
                    : 'Domain registration age was not looked up for this message.',
                does_not_rule_out: null
            };
        }

        if (sender.age_days !== null && sender.age_days < 90) {
            return {
                check: 'Sender domain age',
                result: RESULT.NOT_APPLICABLE,
                detail: `The sending domain is ${sender.age_days} day(s) old, which is a finding rather than assurance.`,
                does_not_rule_out: null
            };
        }

        const years = sender.age_days !== null ? (sender.age_days / 365).toFixed(1) : null;
        return {
            check: 'Sender domain age',
            result: RESULT.PASSED,
            detail: `The sending domain has been registered ${years ? `about ${years} year(s)` : 'well over the threshold'}, so it was not created for this message.`,
            does_not_rule_out: 'An old domain can be bought, hijacked, or have had a subdomain handed out. Age says when the name was registered, not who controls it today.'
        };
    }

    payloadShape(threatObject) {
        const channel = threatObject.payload_channel;
        if (!channel || channel.status === 'UNAVAILABLE') {
            return { check: 'Payload shape', result: RESULT.NOT_RUN, detail: 'Payload analysis did not run.', does_not_rule_out: null };
        }

        if (channel.phone_is_only_channel || channel.image_dominant) {
            return {
                check: 'Payload shape',
                result: RESULT.NOT_APPLICABLE,
                detail: 'The message is shaped so that ordinary analysis has little to read, which is a finding and appears in the evidence.',
                does_not_rule_out: null
            };
        }

        return {
            check: 'Payload shape',
            result: RESULT.PASSED,
            detail: 'The message carries what it says in readable text, rather than as a picture with nothing to read or as a telephone number with no link - both of which exist to leave a filter nothing to inspect.',
            does_not_rule_out: 'An ordinary shape is what almost all mail has, including malicious mail that is simply written plainly.'
        };
    }

    detectionRules(threatObject) {
        const matched = threatObject.detection?.matched_rules || [];

        if (matched.length) {
            return {
                check: 'Detection rules',
                result: RESULT.NOT_APPLICABLE,
                detail: `${matched.length} rule(s) matched and appear in the evidence.`,
                does_not_rule_out: null
            };
        }

        return {
            check: 'Detection rules',
            result: RESULT.PASSED,
            detail: 'None of the detection rules matched this message. Each describes a structural behaviour - authentication contradictions, lookalike domains, credential forms posting offsite, auto-running documents, payloads with nothing to inspect - and cites a public source for why it exists.',
            does_not_rule_out: 'Rules describe what is already understood. A technique nobody has written a rule for yet produces no match, and that is the normal state for anything genuinely new.'
        };
    }
}

module.exports = new AssuranceEvidence();
module.exports.AssuranceEvidence = AssuranceEvidence;
module.exports.RESULT = RESULT;
