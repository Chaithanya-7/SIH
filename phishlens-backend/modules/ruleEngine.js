/**
 * PhishLens native MQL / detection-rule engine.
 *
 * This is a structured, deterministic, explainable rule layer that runs
 * entirely locally against the email PhishLens has already parsed and
 * analyzed (headers, authentication, relay path, attachments, IOCs, and NLP
 * signals). It requires no external detection service and no paid API, so
 * detection keeps working even when an optional provider such as Sublime is
 * not configured or is unreachable.
 *
 * Every rule cites the public source/rationale behind it (MITRE ATT&CK,
 * APWG, CISA, FBI IC3, OWASP, or the relevant RFC), per the project
 * requirement that no detection rule be an unexplained "magic string". This
 * engine is one layer among several (see evidenceFusion.js): it is combined
 * with NLP, forensics, and infrastructure/threat-intel evidence rather than
 * being the sole detector.
 *
 * A rule's `test(ctx)` may return:
 *   - falsy                -> did not match
 *   - true                 -> matched, use the rule's static description
 *   - a string              -> matched, use this as the specific "why" for this email
 */

const FREEMAIL_DOMAINS = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'outlook.com',
    'hotmail.com', 'live.com', 'aol.com', 'icloud.com', 'protonmail.com',
    'mail.com', 'gmx.com', 'zoho.com', 'yandex.com'
]);

// Representative set of frequently-impersonated brand/service terms per APWG
// phishing trend reporting. Not exhaustive; intended as a seed list, not a
// claim of complete brand coverage.
const COMMONLY_IMPERSONATED_BRANDS = [
    'paypal', 'microsoft', 'office365', 'apple', 'amazon', 'netflix',
    'bank of america', 'bankofamerica', 'wells fargo', 'chase', 'hsbc',
    'dhl', 'fedex', 'ups', 'irs', 'docusign', 'adobe', 'google',
    'facebook', 'instagram', 'linkedin', 'coinbase', 'binance', 'dropbox'
];

// Executive/authority titles frequently used in the display name of CEO-fraud
// messages (FBI IC3 BEC guidance).
const EXECUTIVE_TITLE_TERMS = [
    'ceo', 'chief executive', 'cfo', 'chief financial', 'coo', 'chief operating',
    'president', 'chairman', 'managing director', 'vice president', 'head of'
];

const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy'
]);

const DANGEROUS_ATTACHMENT_EXTENSIONS = new Set([
    'exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'bat', 'cmd',
    'ps1', 'jar', 'msi', 'com', 'pif', 'cpl', 'hta'
]);

const MACRO_OFFICE_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm']);
const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'iso', 'img']);

function normalizeForTyposquat(domain) {
    return (domain || '')
        .toLowerCase()
        .replace(/rn/g, 'm')
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/5/g, 's')
        .replace(/@/g, 'a');
}

function domainOf(email) {
    const match = (email || '').match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/);
    return match ? match[1].toLowerCase() : null;
}

const RULES = [
    // ---------------------------------------------------------------
    // AUTHENTICATION / HEADER INTEGRITY  (family: AUTHENTICATION)
    // ---------------------------------------------------------------
    {
        id: 'MQL-AUTH-101',
        name: 'Reply-To domain differs from From domain',
        category: 'AUTH',
        severity: 'HIGH',
        confidence: 0.80,
        source: 'APWG eCrime Trends Report (BEC reply redirection pattern); OWASP Email Security Cheat Sheet',
        description: 'Replies to this message are routed to a different domain than the one it claims to be from, a common business-email-compromise redirection technique.',
        test: (ctx) => ctx.replyToDomain && ctx.fromDomain && ctx.replyToDomain !== ctx.fromDomain &&
            `Reply-To domain (${ctx.replyToDomain}) differs from the From domain (${ctx.fromDomain}).`
    },
    {
        id: 'MQL-AUTH-102',
        name: 'Authentication-Results header disagrees with independent DKIM verification',
        category: 'AUTH',
        severity: 'CRITICAL',
        confidence: 0.85,
        source: 'RFC 8601 §5 (Authentication-Results trust boundary); forged-header downstream-filter-evasion technique',
        description: 'The Authentication-Results header claims a DKIM outcome that PhishLens\' own independent signature verification does not confirm, which can indicate a forged authentication header inserted to mislead filters that trust it blindly.',
        test: (ctx) => !!ctx.auth.dkim_header_mismatch && ctx.auth.dkim_header_mismatch
    },
    {
        id: 'MQL-AUTH-103',
        name: 'Missing Message-ID header',
        category: 'AUTH',
        severity: 'LOW',
        confidence: 0.55,
        source: 'RFC 5322 §3.6.4 (Message-ID SHOULD be present)',
        description: 'The message has no Message-ID header. Legitimate mail systems almost always add one; its absence is common in scripted phishing tooling, though also occurs with some legitimate misconfigured senders.',
        test: (ctx) => !ctx.parsedEmail.messageId
    },
    {
        id: 'MQL-AUTH-104',
        name: 'Message fails DMARC despite sender domain publishing an enforcing policy',
        category: 'AUTH',
        severity: 'CRITICAL',
        confidence: 0.90,
        source: 'RFC 7489 §6.6.2 (DMARC policy enforcement)',
        description: 'The sender domain publishes a DMARC policy that asks receivers to reject or quarantine failing mail, and this message fails DMARC evaluation - it directly defies the domain owner\'s own stated policy.',
        test: (ctx) => {
            const policy = ctx.auth.dmarc_policy?.policy;
            return ctx.auth.dmarc === 'fail' && (policy === 'reject' || policy === 'quarantine') &&
                `Sender domain DMARC policy is p=${policy}, but this message failed DMARC.`;
        }
    },

    // ---------------------------------------------------------------
    // SENDER / DOMAIN IDENTITY  (family: IDENTITY)
    // ---------------------------------------------------------------
    {
        id: 'MQL-DOM-101',
        name: 'Brand-like display name sent from a free-mail domain',
        category: 'DOM',
        severity: 'HIGH',
        confidence: 0.75,
        source: 'APWG display-name spoofing pattern; FBI IC3 BEC public service announcements',
        description: 'The display name references a well-known organization, but the message was actually sent from a free consumer email domain, not that organization\'s own domain.',
        test: (ctx) => {
            if (!ctx.fromDomain || !FREEMAIL_DOMAINS.has(ctx.fromDomain)) return false;
            const nameLower = (ctx.parsedEmail.from.name || '').toLowerCase();
            const brand = COMMONLY_IMPERSONATED_BRANDS.find(b => nameLower.includes(b));
            return brand && `Display name "${ctx.parsedEmail.from.name}" references "${brand}" but the message was sent from the free-mail domain ${ctx.fromDomain}.`;
        }
    },
    {
        id: 'MQL-DOM-102',
        name: 'Brand-like display name with an unrelated sending domain',
        category: 'DOM',
        severity: 'HIGH',
        confidence: 0.70,
        source: 'APWG brand impersonation trend reporting',
        description: 'The display name references a well-known organization, but the sending domain does not contain that organization\'s name at all.',
        test: (ctx) => {
            if (!ctx.fromDomain || FREEMAIL_DOMAINS.has(ctx.fromDomain)) return false;
            const nameLower = (ctx.parsedEmail.from.name || '').toLowerCase();
            const brand = COMMONLY_IMPERSONATED_BRANDS.find(b => nameLower.includes(b));
            const brandToken = brand ? brand.replace(/[^a-z0-9]/g, '') : null;
            return brand && brandToken && !ctx.fromDomain.replace(/[^a-z0-9.]/g, '').includes(brandToken) &&
                `Display name "${ctx.parsedEmail.from.name}" references "${brand}" but the sending domain (${ctx.fromDomain}) is unrelated to it.`;
        }
    },
    {
        id: 'MQL-DOM-103',
        name: 'Sender domain resembles a known brand via character substitution',
        category: 'DOM',
        severity: 'HIGH',
        confidence: 0.65,
        source: 'APWG / CISA typosquatting and homograph-domain guidance',
        description: 'The sending domain matches a well-known brand name only after normalizing common look-alike character substitutions (0/o, 1/l, rn/m, etc.), suggesting a typosquatted domain.',
        test: (ctx) => {
            if (!ctx.fromDomain) return false;
            const normalized = normalizeForTyposquat(ctx.fromDomain);
            const brand = COMMONLY_IMPERSONATED_BRANDS.find(b => {
                const token = b.replace(/[^a-z0-9]/g, '');
                return token.length > 3 && normalized.includes(token) && !ctx.fromDomain.includes(token);
            });
            return brand && `Sending domain ${ctx.fromDomain} normalizes to resemble "${brand}" once look-alike character substitutions are undone.`;
        }
    },
    {
        id: 'MQL-DOM-104',
        name: 'Sender domain uses punycode (internationalized domain) encoding',
        category: 'DOM',
        severity: 'MEDIUM',
        confidence: 0.60,
        source: 'CISA / APWG IDN homograph attack guidance',
        description: 'The sending domain is encoded as punycode (xn--), which can be used to visually impersonate a Latin-script brand domain using look-alike Unicode characters.',
        test: (ctx) => ctx.fromDomain && ctx.fromDomain.includes('xn--')
    },

    // ---------------------------------------------------------------
    // URL RISK  (family: URL_RISK)
    // ---------------------------------------------------------------
    {
        id: 'MQL-URL-101',
        name: 'Link uses a raw IP address instead of a domain name',
        category: 'URL',
        severity: 'HIGH',
        confidence: 0.80,
        source: 'MITRE ATT&CK T1566.002 (Phishing: Spearphishing Link); CISA phishing indicator guidance',
        description: 'A link in this message points directly to an IP address rather than a registered domain name, a pattern rarely used by legitimate correspondence and commonly used to evade domain-reputation filtering.',
        test: (ctx) => {
            const ipUrl = ctx.urls.find(u => {
                try { return /^(\d{1,3}\.){3}\d{1,3}$/.test(new URL(u).hostname); } catch (e) { return false; }
            });
            return ipUrl && `Link points to a raw IP address: ${ipUrl}`;
        }
    },
    {
        id: 'MQL-URL-102',
        name: 'Link hostname uses punycode encoding',
        category: 'URL',
        severity: 'HIGH',
        confidence: 0.75,
        source: 'APWG / CISA IDN homograph attack guidance',
        description: 'A link hostname is encoded as punycode (xn--), which can render as a visually deceptive look-alike of a trusted brand domain.',
        test: (ctx) => {
            const puny = ctx.urls.find(u => {
                try { return new URL(u).hostname.includes('xn--'); } catch (e) { return false; }
            });
            return puny && `Link hostname uses punycode encoding: ${puny}`;
        }
    },
    {
        id: 'MQL-URL-103',
        name: 'Link uses a public URL-shortener domain',
        category: 'URL',
        severity: 'MEDIUM',
        confidence: 0.60,
        source: 'APWG phishing infrastructure reporting (shorteners used to obscure the true destination)',
        description: 'A link uses a public URL-shortening service, which hides the true destination domain from the recipient until the link is followed.',
        test: (ctx) => {
            const shortened = ctx.urls.find(u => {
                try { return URL_SHORTENERS.has(new URL(u).hostname.toLowerCase()); } catch (e) { return false; }
            });
            return shortened && `Link uses a URL-shortening service: ${shortened}`;
        }
    },
    {
        id: 'MQL-URL-104',
        name: 'Unusually high number of distinct links for a short message',
        category: 'URL',
        severity: 'LOW',
        confidence: 0.45,
        source: 'SANS Internet Storm Center phishing-pattern diaries',
        description: 'The message body contains an unusually large number of distinct links relative to its length, a pattern seen in mass phishing/spam templates.',
        test: (ctx) => {
            const bodyLength = (ctx.textBody || '').length;
            return ctx.urls.length >= 6 && bodyLength > 0 && bodyLength < 2000 &&
                `${ctx.urls.length} distinct links found in a ${bodyLength}-character message body.`;
        }
    },

    // ---------------------------------------------------------------
    // ATTACHMENT RISK  (family: ATTACHMENT_RISK)
    // ---------------------------------------------------------------
    {
        id: 'MQL-ATT-101',
        name: 'Executable-class attachment extension',
        category: 'ATT',
        severity: 'CRITICAL',
        confidence: 0.90,
        source: 'MITRE ATT&CK T1566.001 (Phishing: Spearphishing Attachment); CISA malware-delivery advisories',
        description: 'An attachment has an extension associated with directly executable or scriptable content, a leading malware-delivery vector.',
        test: (ctx) => {
            const dangerous = ctx.attachments.find(a => DANGEROUS_ATTACHMENT_EXTENSIONS.has((a.extension || '').toLowerCase()));
            return dangerous && `Attachment "${dangerous.file_name}" has executable-class extension .${dangerous.extension}`;
        }
    },
    {
        id: 'MQL-ATT-102',
        name: 'Macro-enabled Office document attachment',
        category: 'ATT',
        severity: 'HIGH',
        confidence: 0.80,
        source: 'MITRE ATT&CK T1204.002 (User Execution: Malicious File); CISA',
        description: 'An attachment is a macro-enabled Office document, a common vector for delivering malicious macro payloads.',
        test: (ctx) => {
            const macroDoc = ctx.attachments.find(a => MACRO_OFFICE_EXTENSIONS.has((a.extension || '').toLowerCase()));
            return macroDoc && `Attachment "${macroDoc.file_name}" is a macro-enabled Office document (.${macroDoc.extension})`;
        }
    },
    {
        id: 'MQL-ATT-103',
        name: 'Attachment filename uses a double extension',
        category: 'ATT',
        severity: 'HIGH',
        confidence: 0.75,
        source: 'APWG / CISA malware-delivery obfuscation reporting (e.g. invoice.pdf.exe)',
        description: 'An attachment filename has two extensions, a technique used to disguise an executable as a harmless document at a glance.',
        test: (ctx) => {
            const doubleExt = ctx.attachments.find(a => /\.[a-z0-9]{2,5}\.[a-z0-9]{2,5}$/i.test(a.file_name || ''));
            return doubleExt && `Attachment filename "${doubleExt.file_name}" uses a double extension.`;
        }
    },
    {
        id: 'MQL-ATT-104',
        name: 'Archive attachment',
        category: 'ATT',
        severity: 'MEDIUM',
        confidence: 0.55,
        source: 'CISA phishing advisories (archives used to smuggle payloads past content scanning)',
        description: 'An attachment is a compressed archive, commonly used to hide malicious file content from automated content scanning.',
        test: (ctx) => {
            const archive = ctx.attachments.find(a => ARCHIVE_EXTENSIONS.has((a.extension || '').toLowerCase()));
            return archive && `Attachment "${archive.file_name}" is an archive (.${archive.extension}).`;
        }
    },

    // ---------------------------------------------------------------
    // CONTENT / MULTI-SIGNAL NLP COMBINATIONS  (family: LANGUAGE)
    // ---------------------------------------------------------------
    {
        id: 'MQL-NLP-101',
        name: 'Credential-request language combined with a link call-to-action',
        category: 'NLP',
        severity: 'HIGH',
        confidence: 0.82,
        source: 'APWG phishing lure taxonomy (credential-harvesting composite pattern)',
        description: 'The message both asks for account/credential action and directs the recipient to a link, the classic credential-harvesting combination.',
        test: (ctx) => ctx.nlpSignalTypes.has('CREDENTIAL_REQUEST') && ctx.nlpSignalTypes.has('LINK_OR_ATTACHMENT_CALL_TO_ACTION')
    },
    {
        id: 'MQL-NLP-102',
        name: 'Financial-pressure language combined with urgency language',
        category: 'NLP',
        severity: 'CRITICAL',
        confidence: 0.85,
        source: 'FBI IC3 Business Email Compromise (BEC) public service announcements; APWG',
        description: 'The message combines a financial request (payment, transfer, gift card) with pressure to act quickly, the signature pattern of business email compromise.',
        test: (ctx) => ctx.nlpSignalTypes.has('FINANCIAL_PRESSURE') && ctx.nlpSignalTypes.has('URGENCY_PRESSURE')
    },
    {
        id: 'MQL-NLP-103',
        name: 'Executive-authority claim combined with a Reply-To domain mismatch',
        category: 'NLP',
        severity: 'CRITICAL',
        confidence: 0.85,
        source: 'FBI IC3 BEC guidance ("CEO fraud"); APWG',
        description: 'The message invokes executive/organizational authority while replies are silently redirected to a different domain, a hallmark of CEO-fraud business email compromise.',
        test: (ctx) => {
            const replyMismatch = ctx.replyToDomain && ctx.fromDomain && ctx.replyToDomain !== ctx.fromDomain;
            if (!replyMismatch) return false;

            // The executive claim is just as often in the sender's display name as in the
            // message body, so both are treated as the same authority-claim indicator.
            const displayName = (ctx.parsedEmail.from.name || '').toLowerCase();
            const titleInDisplayName = EXECUTIVE_TITLE_TERMS.find(t => displayName.includes(t));

            if (ctx.nlpSignalTypes.has('IMPERSONATION_LANGUAGE')) {
                return 'Message body invokes executive/organizational authority while replies are redirected to a different domain.';
            }
            return titleInDisplayName &&
                `Sender display name claims executive authority ("${ctx.parsedEmail.from.name}") while replies are redirected from ${ctx.fromDomain} to ${ctx.replyToDomain}.`;
        }
    },
    {
        id: 'MQL-NLP-104',
        name: 'Secrecy or confidentiality pressure language',
        category: 'NLP',
        severity: 'HIGH',
        confidence: 0.75,
        source: 'FBI IC3 BEC indicators (isolating the victim from independent verification)',
        description: 'The message asks the recipient to keep the request confidential or avoid discussing it with others, a technique used to prevent verification through a second channel.',
        test: (ctx) => ctx.nlpSignalTypes.has('SECRECY_PRESSURE')
    },

    // ---------------------------------------------------------------
    // BUSINESS EMAIL COMPROMISE COMPOSITE  (family: BEC_COMPOSITE)
    // ---------------------------------------------------------------
    {
        id: 'MQL-BEC-101',
        name: 'Multiple independent business-email-compromise indicators co-occur',
        category: 'BEC',
        severity: 'CRITICAL',
        confidence: 0.90,
        source: 'FBI IC3 Business Email Compromise public service announcements; APWG eCrime reporting',
        description: 'Several independent BEC indicators appear together in one message. BEC is typically sent from an attacker-controlled domain that passes SPF/DKIM/DMARC and carries no link or attachment, so it leaves no authentication or payload trace - the co-occurrence of these behavioural indicators is the evidence.',
        test: (ctx) => {
            const displayName = (ctx.parsedEmail.from.name || '').toLowerCase();
            const indicators = [];

            if (ctx.nlpSignalTypes.has('FINANCIAL_PRESSURE') || ctx.nlpSignalTypes.has('GIFT_CARD_REQUEST')) {
                indicators.push('a financial request');
            }
            if (ctx.nlpSignalTypes.has('URGENCY_PRESSURE')) {
                indicators.push('urgency pressure');
            }
            if (ctx.nlpSignalTypes.has('SECRECY_PRESSURE')) {
                indicators.push('a request for secrecy');
            }
            if (ctx.nlpSignalTypes.has('IMPERSONATION_LANGUAGE') || EXECUTIVE_TITLE_TERMS.some(t => displayName.includes(t))) {
                indicators.push('a claim of executive authority');
            }
            if (ctx.replyToDomain && ctx.fromDomain && ctx.replyToDomain !== ctx.fromDomain) {
                indicators.push('replies redirected to a different domain');
            }

            return indicators.length >= 3 &&
                `${indicators.length} independent BEC indicators co-occur in this message: ${indicators.join(', ')}.`;
        }
    },

    // ---------------------------------------------------------------
    // IMPERSONATION / ATTACHMENT-DELIVERY COMPOSITE  (family: IDENTITY)
    // ---------------------------------------------------------------
    {
        id: 'MQL-IMP-101',
        name: 'Attachment delivered alongside authentication failure',
        category: 'IMP',
        severity: 'HIGH',
        confidence: 0.75,
        source: 'MITRE ATT&CK T1566.001 (Phishing: Spearphishing Attachment); APWG',
        description: 'The message carries an attachment while failing SPF or DKIM, increasing the likelihood that the attachment did not originate from the claimed sender.',
        test: (ctx) => ctx.attachments.length > 0 && (ctx.auth.spf === 'fail' || ctx.auth.dkim === 'fail')
    }
];

class RuleEngine {
    buildContext(threatObject, parsedEmail) {
        const fromDomain = domainOf(parsedEmail.from?.address);
        const replyToDomain = parsedEmail.replyTo ? domainOf(parsedEmail.replyTo) : null;
        const nlpSignalTypes = new Set((threatObject.nlp?.signals || []).map(s => s.type));

        return {
            threatObject,
            parsedEmail,
            auth: threatObject.forensics?.authentication || {},
            fromDomain,
            replyToDomain,
            textBody: parsedEmail.textBody || '',
            urls: threatObject.iocs?.urls || [],
            attachments: threatObject.attachments || [],
            nlpSignalTypes
        };
    }

    evaluate(threatObject, parsedEmail) {
        console.log('[RuleEngine] Evaluating native MQL detection rules...');
        const ctx = this.buildContext(threatObject, parsedEmail);

        const matched = [];
        for (const rule of RULES) {
            let result;
            try {
                result = rule.test(ctx);
            } catch (err) {
                console.error(`[RuleEngine] Rule ${rule.id} threw during evaluation: ${err.message}`);
                continue;
            }
            if (!result) continue;

            matched.push({
                id: rule.id,
                name: rule.name,
                category: rule.category,
                severity: rule.severity,
                confidence: rule.confidence,
                source: rule.source,
                description: rule.description,
                matched_because: typeof result === 'string' ? result : rule.description
            });
        }

        threatObject.detection = threatObject.detection || {};
        threatObject.detection.matched_rules = matched;
        threatObject.detection.signals = matched.map(r => r.id);
        threatObject.detection.verification_status = 'PHISHLENS_NATIVE_MQL_VERIFIED';
        threatObject.detection.rule_engine = {
            engine: 'PHISHLENS_NATIVE_MQL_V1',
            rules_evaluated: RULES.length,
            rules_matched: matched.length
        };

        return threatObject;
    }
}

module.exports = new RuleEngine();
