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

const customDetectionConfig = require('./customDetectionConfig');

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
    // QR CODE  (family: URL_RISK)
    //
    // A QR code is a link that no amount of language analysis can see: it is
    // pixels in an attachment, and the recipient resolves it on a phone that is
    // usually outside whatever protection the organisation runs on desktops.
    // ---------------------------------------------------------------
    {
        id: 'MQL-QR-101',
        name: 'Attachment contains a QR code linking to an external address',
        category: 'QR',
        severity: 'MEDIUM',
        confidence: 0.55,
        mitre: ['T1566.001', 'T1566.002'],
        source: 'MITRE ATT&CK T1566.001/T1566.002 (Phishing: Spearphishing Attachment / Link)',
        description: 'An image attached to this message carries a QR code containing a web address. The link is not written anywhere in the message text, so it is invisible to filtering that reads only the body, and a recipient following it typically leaves the managed device to do so.',
        test: (ctx) => {
            const code = (ctx.qr.codes || []).find(c => c.payload_kind === 'url');
            return code && `QR code in "${code.filename}" resolves to ${code.payload}`;
        }
    },
    {
        id: 'MQL-QR-102',
        name: 'QR code is colour-inverted',
        category: 'QR',
        severity: 'MEDIUM',
        confidence: 0.45,
        mitre: ['T1566.001'],
        source: 'MITRE ATT&CK T1566.001 (Phishing: Spearphishing Attachment)',
        description: 'The QR code is light modules on a dark background. Ordinary documents very rarely contain an inverted code, while inverting one is a cheap way past a scanner that reads a single polarity.',
        test: (ctx) => {
            const inverted = (ctx.qr.codes || []).find(c => c.polarity === 'inverted');
            return inverted && `The QR code in "${inverted.filename}" is inverted, which is unusual in legitimate documents.`;
        }
    },
    {
        id: 'MQL-QR-103',
        name: 'QR code carries credentials or a payment address rather than a link',
        category: 'QR',
        severity: 'HIGH',
        confidence: 0.65,
        mitre: ['T1566.001'],
        source: 'MITRE ATT&CK T1566.001 (Phishing: Spearphishing Attachment)',
        description: 'The code encodes something other than a web address - network credentials, a payment address or a prepared message. Each of these acts on the recipient device the moment it is scanned, without any page for them to inspect first.',
        test: (ctx) => {
            const risky = (ctx.qr.codes || []).find(c => ['wifi_credentials', 'cryptocurrency_address', 'message_template'].includes(c.payload_kind));
            return risky && `QR code in "${risky.filename}" encodes ${risky.payload_kind.replace(/_/g, ' ')} rather than a link.`;
        }
    },
    {
        id: 'MQL-QR-104',
        name: 'Message body is empty and the payload is in an attachment',
        category: 'QR',
        severity: 'MEDIUM',
        confidence: 0.50,
        mitre: ['T1566.001'],
        source: 'MITRE ATT&CK T1566.001 (Phishing: Spearphishing Attachment)',
        description: 'There is effectively no message text, only an attachment. Nothing is written for a content classifier to object to, because nothing is written at all - the whole message is the attachment.',
        test: (ctx) => {
            const body = (ctx.textBody || '').replace(/\s+/g, ' ').trim();
            const attachments = (ctx.parsedEmail && ctx.parsedEmail.attachments) || [];
            if (attachments.length === 0 || body.length > 120) return false;
            return `The message body is ${body.length} character(s) long and carries ${attachments.length} attachment(s), so the payload is not in the text.`;
        }
    },

    // ---------------------------------------------------------------
    // AUTHENTICATION-FLOW ABUSE  (family: URL_RISK)
    //
    // These do not steal a password. They persuade somebody to complete a
    // genuine authentication on the attacker's behalf, so every link is to a
    // real provider domain and every reputation check on it comes back clean.
    // ---------------------------------------------------------------
    {
        id: 'MQL-AUTHFLOW-101',
        name: 'Message drives a device-code authorisation flow',
        category: 'AUTHFLOW',
        severity: 'HIGH',
        confidence: 0.70,
        mitre: ['T1566.002'],
        source: 'MITRE ATT&CK T1566.002 (Phishing: Spearphishing Link); RFC 8628 (OAuth 2.0 Device Authorization Grant)',
        description: 'The message points at a provider device-authorisation page and supplies a code to enter. The page is genuine, so no link or domain check will object to it; what the recipient authorises is a session for whoever generated the code.',
        test: (ctx) => {
            const DEVICE_ENDPOINTS = [
                'microsoft.com/devicelogin', 'login.microsoftonline.com/common/oauth2/deviceauth',
                'google.com/device', 'aka.ms/devicelogin', 'github.com/login/device',
                'amazon.com/code', 'okta.com/activate'
            ];
            const link = (ctx.urls || []).find(u => DEVICE_ENDPOINTS.some(e => String(u).toLowerCase().includes(e)));
            if (!link) return false;
            const codeInBody = /\b([A-Z0-9]{4}[- ]?[A-Z0-9]{4})\b/.test(ctx.textBody || '');
            return `Message links to a device-authorisation endpoint (${link})${codeInBody ? ' and supplies a code to enter' : ''}. Completing it grants a signed-in session to whoever issued the code.`;
        }
    },
    {
        id: 'MQL-AUTHFLOW-102',
        name: 'Link passes through a generic edge or tunnelling host',
        category: 'AUTHFLOW',
        severity: 'MEDIUM',
        confidence: 0.45,
        mitre: ['T1566.002'],
        source: 'MITRE ATT&CK T1566.002 (Phishing: Spearphishing Link)',
        description: 'A link resolves through a general-purpose edge, worker or tunnelling service. These are ordinary developer infrastructure, so this is weak on its own - it matters because it lets a page be served from reputable infrastructure that carries no reputation of the attacker own.',
        test: (ctx) => {
            const RELAYS = ['workers.dev', 'trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'loca.lt', 'r2.dev', 'pages.dev', 'vercel.app', 'netlify.app', 'glitch.me'];
            const hit = (ctx.urls || []).find(u => {
                try {
                    const h = new URL(u).hostname.toLowerCase();
                    return RELAYS.some(r => h === r || h.endsWith('.' + r));
                } catch (e) { return false; }
            });
            return hit && `Link is served through a generic hosting or tunnelling service: ${hit}`;
        }
    },

    // ---------------------------------------------------------------
    // FORWARDING CHAIN  (family: AUTHENTICATION)
    // ---------------------------------------------------------------
    {
        id: 'MQL-ARC-101',
        name: 'ARC forwarding chain is malformed',
        category: 'ARC',
        severity: 'MEDIUM',
        confidence: 0.50,
        mitre: ['T1566'],
        source: 'RFC 8617 (Authenticated Received Chain); MITRE ATT&CK T1566 (Phishing)',
        description: 'The message carries ARC headers that do not form a valid chain. A well-formed chain explains why authentication failed on genuinely forwarded mail; a broken one is either a misconfigured forwarder or an attempt to manufacture that excuse.',
        test: (ctx) => {
            if (ctx.arc.status !== 'BROKEN') return false;
            return `ARC chain over ${ctx.arc.hops} hop(s) is malformed: ${(ctx.arc.problems || []).join(' ')}`;
        }
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
    // THREAT INTELLIGENCE  (family: THREAT_INTEL)
    // Evaluated after the enrichment branches, since these rules reason over
    // indicator-feed matches and registration data rather than over the
    // message alone.
    // ---------------------------------------------------------------
    {
        id: 'MQL-INTEL-101',
        name: 'Link matches a known malicious URL in open threat intelligence',
        category: 'INTEL',
        stage: 'enrichment',
        severity: 'CRITICAL',
        confidence: 0.95,
        // Confirmatory rather than suggestive: a third party has directly
        // observed this exact resource being used for phishing or malware
        // delivery, and it is still listed. There is no benign reading of a
        // message linking to it, so this finding stands on its own.
        decisive: true,
        source: 'abuse.ch URLhaus / OpenPhish / ThreatFox open indicator feeds',
        description: 'A link in this message is itself listed in an open threat-intelligence feed as malicious or phishing.',
        test: (ctx) => {
            const hit = (ctx.intelMatches || []).find(m => m.indicator_type === 'URL' && m.matched === 'EXACT_URL');
            return hit && `The exact URL ${hit.indicator} is listed in the ${hit.feed} feed.`;
        }
    },
    {
        id: 'MQL-INTEL-102',
        name: 'Link points to a host known to serve malicious content',
        category: 'INTEL',
        stage: 'enrichment',
        severity: 'HIGH',
        confidence: 0.85,
        source: 'abuse.ch URLhaus / OpenPhish / ThreatFox open indicator feeds',
        description: 'A link points to a host that open threat intelligence has recorded serving malicious or phishing content, though at a different path. Multi-tenant platforms are excluded from this check.',
        test: (ctx) => {
            const hit = (ctx.intelMatches || []).find(m => m.indicator_type === 'URL' && (m.matched === 'URL_HOST' || m.matched === 'DOMAIN'));
            return hit && `The host ${hit.indicator} appears in the ${hit.feed} feed as serving malicious content.`;
        }
    },
    {
        id: 'MQL-INTEL-103',
        name: 'Message infrastructure matches a known malicious IP or netblock',
        category: 'INTEL',
        stage: 'enrichment',
        severity: 'HIGH',
        confidence: 0.85,
        source: 'abuse.ch Feodo Tracker (botnet C2) / Spamhaus DROP (hijacked netblocks)',
        description: 'An IP address associated with this message is listed as botnet command-and-control infrastructure, or falls inside a netblock published as hijacked or attacker-controlled.',
        test: (ctx) => {
            const hit = (ctx.intelMatches || []).find(m => m.indicator_type === 'IP');
            return hit && `${hit.indicator} matches ${hit.matched === 'NETBLOCK' ? 'netblock ' + hit.indicator : 'a listed address'} in the ${hit.feed} feed.`;
        }
    },
    {
        id: 'MQL-INTEL-104',
        name: 'Sender domain was registered very recently',
        category: 'INTEL',
        stage: 'enrichment',
        severity: 'HIGH',
        confidence: 0.80,
        source: 'RDAP registration data (RFC 9083); APWG / CISA guidance on newly-registered domains in phishing',
        description: 'The sender domain was registered within the last 30 days. Phishing infrastructure is typically registered shortly before use, whereas an organisation a message claims to represent has usually held its domain for years.',
        test: (ctx) => {
            const sender = (ctx.domainAges || []).find(d => d.is_sender_domain && d.status === 'AVAILABLE');
            return sender && sender.age_days !== null && sender.age_days <= 30 &&
                `Sender domain ${sender.domain} was registered ${sender.age_days} day(s) ago (${sender.registered_at}).`;
        }
    },
    {
        id: 'MQL-INTEL-105',
        name: 'Linked domain was registered very recently',
        category: 'INTEL',
        stage: 'enrichment',
        severity: 'MEDIUM',
        confidence: 0.65,
        source: 'RDAP registration data (RFC 9083); APWG / CISA guidance on newly-registered domains in phishing',
        description: 'A domain linked in this message was registered within the last 30 days, a common characteristic of phishing landing pages.',
        test: (ctx) => {
            const linked = (ctx.domainAges || []).find(d => !d.is_sender_domain && d.status === 'AVAILABLE' && d.age_days !== null && d.age_days <= 30);
            return linked && `Linked domain ${linked.domain} was registered ${linked.age_days} day(s) ago (${linked.registered_at}).`;
        }
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

/**
 * Pulls MITRE technique identifiers out of a rule's citation string.
 *
 * Rules written before techniques were emitted as data cite them in prose, and
 * rewriting thirty citations by hand to add a field would have been a chance to
 * introduce a typo in every one of them. A rule that declares `mitre: [...]`
 * explicitly always wins; this is the fallback for the rest.
 */
function mitreFromSource(source) {
    const found = String(source || '').match(/\bT1\d{3}(?:\.\d{3})?\b/g);
    return found ? Array.from(new Set(found)) : [];
}

/** Technique ids with the rules that attributed each, so attribution is checkable. */
function summariseTechniques(matchedRules) {
    const byTechnique = new Map();
    for (const rule of matchedRules) {
        for (const technique of (rule.mitre || [])) {
            if (!byTechnique.has(technique)) byTechnique.set(technique, []);
            byTechnique.get(technique).push(rule.id);
        }
    }
    return Array.from(byTechnique.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([technique, rules]) => ({
            technique,
            name: TECHNIQUE_NAMES[technique] || null,
            attributed_by: rules
        }));
}

/**
 * Names for the techniques these rules actually cite. Deliberately not a copy
 * of the whole ATT&CK catalogue: an unnamed technique is reported with its id
 * and a null name, which is honest, rather than carrying thousands of entries
 * that would drift out of date.
 */
const TECHNIQUE_NAMES = {
    'T1566': 'Phishing',
    'T1566.001': 'Phishing: Spearphishing Attachment',
    'T1566.002': 'Phishing: Spearphishing Link',
    'T1566.003': 'Phishing: Spearphishing via Service',
    'T1566.004': 'Phishing: Spearphishing Voice',
    'T1534': 'Internal Spearphishing',
    'T1598': 'Phishing for Information',
    'T1598.002': 'Phishing for Information: Spearphishing Attachment',
    'T1598.003': 'Phishing for Information: Spearphishing Link',
    'T1656': 'Impersonation',
    'T1204': 'User Execution',
    'T1204.001': 'User Execution: Malicious Link',
    'T1204.002': 'User Execution: Malicious File',
    'T1586': 'Compromise Accounts',
    'T1585': 'Establish Accounts',
    'T1583': 'Acquire Infrastructure',
    'T1583.001': 'Acquire Infrastructure: Domains'
};

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
            nlpSignalTypes,
            intelMatches: threatObject.threat_intelligence?.matches || [],
            domainAges: threatObject.threat_intelligence?.domain_ages || [],
            qr: threatObject.qr || { codes: [], codes_found: 0, not_scanned: [] },
            arc: threatObject.forensics?.arc || { status: 'ABSENT' }
        };
    }

    /** Flattened, documented view of a message for operator-defined rules. */
    buildCustomContext(threatObject, parsedEmail) {
        const senderAddress = (parsedEmail.from?.address || '').toLowerCase();
        const urls = threatObject.iocs?.urls || [];
        const senderAge = (threatObject.threat_intelligence?.domain_ages || [])
            .find(d => d.is_sender_domain && d.status === 'AVAILABLE');

        return {
            subject: parsedEmail.subject || '',
            body: parsedEmail.textBody || '',
            senderAddress,
            senderDomain: domainOf(senderAddress) || '',
            senderDisplayName: parsedEmail.from?.name || '',
            replyToDomain: parsedEmail.replyTo ? (domainOf(parsedEmail.replyTo) || '') : '',
            urls,
            urlHosts: urls.map(u => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return null; } }).filter(Boolean),
            attachmentNames: (threatObject.attachments || []).map(a => a.file_name),
            attachmentExtensions: (threatObject.attachments || []).map(a => (a.extension || '').toLowerCase()),
            auth: threatObject.forensics?.authentication || {},
            nlpSignals: (threatObject.nlp?.signals || []).map(s => s.type),
            matchedRuleIds: (threatObject.detection?.matched_rules || []).map(r => r.id),
            senderDomainAgeDays: senderAge ? senderAge.age_days : null
        };
    }

    /**
     * Operator-defined rules run in the enrichment stage so they can reason
     * over everything the built-in pipeline established, including which
     * built-in rules already fired. They produce evidence through exactly the
     * same path as built-in rules and cannot set a verdict directly.
     */
    evaluateCustomRules(threatObject, parsedEmail) {
        const custom = customDetectionConfig.rules;
        if (!custom.length) return [];

        const ctx = this.buildCustomContext(threatObject, parsedEmail);
        const matched = [];

        for (const rule of custom) {
            try {
                if (!customDetectionConfig.evaluate(rule.conditions, ctx)) continue;
                matched.push({
                    id: rule.id,
                    name: rule.name,
                    category: 'CUSTOM',
                    severity: rule.severity,
                    confidence: Number(rule.confidence),
                    source: `Operator-defined: ${rule.source}`,
                    description: rule.description || rule.name,
                    // Only honoured when the operator declared it explicitly on a
                    // CRITICAL rule; validation enforces that pairing.
                    decisive: rule.decisive === true && rule.severity === 'CRITICAL',
                    matched_because: rule.description || `Operator-defined rule ${rule.id} matched this message.`
                });
            } catch (err) {
                console.error(`[RuleEngine] Custom rule ${rule.id} failed to evaluate: ${err.message}`);
            }
        }

        return matched;
    }

    /**
     * Rules are evaluated in two stages.
     *
     * 'message' rules reason only over the message itself and run in the
     * detection layer, before any enrichment. 'enrichment' rules reason over
     * what the analysis branches produced - indicator-feed matches,
     * registration age - and so must run after them. Matches from both stages
     * accumulate onto the same case.
     */
    evaluate(threatObject, parsedEmail, stage = 'message') {
        console.log(`[RuleEngine] Evaluating native MQL detection rules (${stage} stage)...`);
        const ctx = this.buildContext(threatObject, parsedEmail);

        const applicable = RULES.filter(r => (r.stage || 'message') === stage);
        const matched = stage === 'enrichment' ? this.evaluateCustomRules(threatObject, parsedEmail) : [];
        for (const rule of applicable) {
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
                decisive: rule.decisive === true,
                mitre: rule.mitre || mitreFromSource(rule.source),
                matched_because: typeof result === 'string' ? result : rule.description
            });
        }

        threatObject.detection = threatObject.detection || {};

        // Later stages add to the case rather than replacing what an earlier
        // stage already established.
        const existing = stage === 'message' ? [] : (threatObject.detection.matched_rules || []);
        const combined = existing.concat(matched.filter(m => !existing.some(e => e.id === m.id)));

        threatObject.detection.matched_rules = combined;
        threatObject.detection.signals = combined.map(r => r.id);

        // Techniques as identifiers, not prose.
        //
        // Every rule already cited MITRE in its `source` string, which reads
        // well in a report and is useless to anything else: a SIEM cannot
        // correlate on a sentence, and neither can a second PhishLens
        // deployment. The same citations are emitted here as a sorted list of
        // technique ids, alongside the rules that produced each one so a reader
        // can see why a technique was attributed rather than having to trust it.
        threatObject.detection.attack_patterns = summariseTechniques(combined);
        threatObject.detection.verification_status = 'PHISHLENS_NATIVE_MQL_VERIFIED';
        threatObject.detection.rule_engine = {
            engine: 'PHISHLENS_NATIVE_MQL_V1',
            rules_evaluated: stage === 'message' ? applicable.length : RULES.length,
            rules_matched: combined.length,
            stages_run: stage === 'message' ? ['message'] : ((threatObject.detection.rule_engine?.stages_run || []).concat(stage))
        };

        return threatObject;
    }
}

module.exports = new RuleEngine();
