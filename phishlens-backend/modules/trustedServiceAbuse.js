/**
 * Phishing that arrives through services nobody can afford to block.
 *
 * ## The blind spot this exists to cover
 *
 * PhishLens weighs authentication heavily, and it is right to: a forged sender
 * is a hard fact. But the strongest evidence family in the system contributes
 * exactly nothing when the message authenticates correctly - and a large and
 * growing share of real phishing now does.
 *
 * It authenticates because it is genuinely sent by the service it claims to
 * come from. A real Dropbox share notification. A real DocuSign envelope. A
 * real Microsoft Forms response. A real mail from a compromised account on a
 * real tenant. SPF passes, DKIM verifies, DMARC aligns, the domain is decades
 * old with a spotless reputation, and none of that is a lie. The attacker did
 * not defeat the authentication; they signed up for the service and used it as
 * intended.
 *
 * The industry name for this is living off trusted sites. Microsoft's own
 * telemetry has authentication-passing phishing rising year on year, and
 * file-sharing lures now account for a double-digit share of credential
 * phishing. A detector built around "did this message lie about who sent it"
 * scores all of it at zero.
 *
 * ## What is still detectable
 *
 * The sending infrastructure is honest, so the sending infrastructure is not
 * where the lie is. Three things remain wrong, and all three are structural:
 *
 *   1. **A password is being requested through something that does not collect
 *      passwords.** No organisation on earth gathers credentials through a
 *      public form builder. A link to Google Forms, Microsoft Forms, Typeform
 *      or JotForm, in a message asking the reader to confirm their sign-in
 *      details, has no legitimate reading. This is the strongest signal here
 *      and very nearly false-positive-free.
 *
 *   2. **The brand in the message is not the platform that carried it.** A
 *      message that presents itself as a Microsoft security alert, delivered
 *      through a bulk-mail provider or a design tool, is not what it says it
 *      is - even though everything about the delivery authenticates. Real
 *      brands send their own transactional mail.
 *
 *   3. **A sharing notification that asks for a sign-in.** A genuine "someone
 *      shared a document with you" notice takes you to the document. One that
 *      first asks you to verify your identity to view it is the oldest shape
 *      in credential phishing wearing a legitimate envelope.
 *
 * ## What this cannot do, stated plainly
 *
 * It cannot tell a real Dropbox share from a malicious one by the sender,
 * because both are real. It does not follow links to find out - fetching an
 * attacker's URL from the machine being protected would confirm delivery, load
 * whatever is there, and hand over an address and a timestamp. So a share
 * notification with no other signal is reported as a fact and scored at
 * nothing. Only the combinations above become findings.
 */

/**
 * Services that are legitimate, widely used, and used by attackers precisely
 * because of it. Matched on the registrable part of the host, so a subdomain
 * belonging to the platform matches and a lookalike domain does not.
 */
const PLATFORMS = [
    // Collecting structured input from the public. Never a place for a password.
    { id: 'google_forms', name: 'Google Forms', category: 'FORM_BUILDER', hosts: ['docs.google.com'], pathHint: '/forms' },
    { id: 'microsoft_forms', name: 'Microsoft Forms', category: 'FORM_BUILDER', hosts: ['forms.office.com', 'forms.microsoft.com'] },
    { id: 'typeform', name: 'Typeform', category: 'FORM_BUILDER', hosts: ['typeform.com'] },
    { id: 'jotform', name: 'JotForm', category: 'FORM_BUILDER', hosts: ['jotform.com', 'jotform.co'] },
    { id: 'surveymonkey', name: 'SurveyMonkey', category: 'FORM_BUILDER', hosts: ['surveymonkey.com'] },
    { id: 'formstack', name: 'Formstack', category: 'FORM_BUILDER', hosts: ['formstack.com'] },
    { id: 'cognitoforms', name: 'Cognito Forms', category: 'FORM_BUILDER', hosts: ['cognitoforms.com'] },
    { id: 'zohoforms', name: 'Zoho Forms', category: 'FORM_BUILDER', hosts: ['zohopublic.com', 'forms.zohopublic.com'] },

    // Document delivery and signature.
    { id: 'dropbox', name: 'Dropbox', category: 'FILE_SHARING', hosts: ['dropbox.com', 'dropboxusercontent.com'] },
    { id: 'sharepoint', name: 'SharePoint / OneDrive', category: 'FILE_SHARING', hosts: ['sharepoint.com', 'onedrive.live.com', '1drv.ms'] },
    { id: 'gdrive', name: 'Google Drive', category: 'FILE_SHARING', hosts: ['drive.google.com'] },
    { id: 'box', name: 'Box', category: 'FILE_SHARING', hosts: ['box.com'] },
    { id: 'wetransfer', name: 'WeTransfer', category: 'FILE_SHARING', hosts: ['wetransfer.com', 'we.tl'] },
    { id: 'docusign', name: 'DocuSign', category: 'ESIGN', hosts: ['docusign.net', 'docusign.com'] },
    { id: 'adobesign', name: 'Adobe Acrobat Sign', category: 'ESIGN', hosts: ['adobesign.com', 'echosign.com', 'adobe.com'] },
    { id: 'dropboxsign', name: 'Dropbox Sign', category: 'ESIGN', hosts: ['hellosign.com', 'dropboxsign.com'] },
    { id: 'pandadoc', name: 'PandaDoc', category: 'ESIGN', hosts: ['pandadoc.com'] },
    { id: 'signnow', name: 'SignNow', category: 'ESIGN', hosts: ['signnow.com'] },

    // Publishing and collaboration, used to host the landing page itself.
    { id: 'canva', name: 'Canva', category: 'COLLABORATION', hosts: ['canva.com', 'canva.site'] },
    { id: 'notion', name: 'Notion', category: 'COLLABORATION', hosts: ['notion.so', 'notion.site'] },
    { id: 'smartsheet', name: 'Smartsheet', category: 'COLLABORATION', hosts: ['smartsheet.com'] },
    { id: 'airtable', name: 'Airtable', category: 'COLLABORATION', hosts: ['airtable.com'] },
    { id: 'atlassian', name: 'Atlassian', category: 'COLLABORATION', hosts: ['atlassian.net'] },
    { id: 'miro', name: 'Miro', category: 'COLLABORATION', hosts: ['miro.com'] },

    // Bulk senders. Legitimate brands do not route security alerts through these.
    { id: 'sendgrid', name: 'SendGrid', category: 'BULK_SENDER', hosts: ['sendgrid.net', 'sendgrid.com'] },
    { id: 'mailchimp', name: 'Mailchimp', category: 'BULK_SENDER', hosts: ['mailchimp.com', 'mandrillapp.com', 'rsgsv.net', 'mcsv.net'] },
    { id: 'brevo', name: 'Brevo / Sendinblue', category: 'BULK_SENDER', hosts: ['sendinblue.com', 'brevo.com'] },
    { id: 'mailgun', name: 'Mailgun', category: 'BULK_SENDER', hosts: ['mailgun.org', 'mailgun.net'] },
    { id: 'constantcontact', name: 'Constant Contact', category: 'BULK_SENDER', hosts: ['constantcontact.com', 'rs6.net'] },
    { id: 'hubspot', name: 'HubSpot', category: 'BULK_SENDER', hosts: ['hubspotemail.net', 'hs-sites.com'] },
    { id: 'klaviyo', name: 'Klaviyo', category: 'BULK_SENDER', hosts: ['klaviyomail.com'] }
];

/**
 * Brands whose name appearing in a message sets an expectation about who sent
 * it. Overlaps with the impersonation list in the rule engine by design - that
 * one asks "does the sender look like this brand", this one asks "does the
 * message claim to be this brand while arriving through somebody else".
 */
const BRAND_CLAIMS = [
    { brand: 'Microsoft', terms: ['microsoft', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure'], ownDomains: ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'sharepoint.com', 'onedrive.live.com', 'microsoftonline.com', 'azure.com'] },
    { brand: 'Google', terms: ['google', 'gmail', 'google drive', 'google workspace'], ownDomains: ['google.com', 'gmail.com', 'googlemail.com', 'drive.google.com', 'docs.google.com'] },
    { brand: 'Apple', terms: ['apple', 'icloud', 'apple id'], ownDomains: ['apple.com', 'icloud.com', 'me.com'] },
    { brand: 'PayPal', terms: ['paypal'], ownDomains: ['paypal.com', 'paypal.co.uk'] },
    { brand: 'Amazon', terms: ['amazon', 'aws', 'amazon web services'], ownDomains: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazonaws.com', 'amazonses.com'] },
    { brand: 'DocuSign', terms: ['docusign'], ownDomains: ['docusign.com', 'docusign.net'] },
    { brand: 'Adobe', terms: ['adobe', 'acrobat sign'], ownDomains: ['adobe.com', 'adobesign.com', 'echosign.com'] },
    { brand: 'Dropbox', terms: ['dropbox'], ownDomains: ['dropbox.com', 'dropboxmail.com', 'dropboxusercontent.com'] },
    { brand: 'Netflix', terms: ['netflix'], ownDomains: ['netflix.com'] },
    { brand: 'LinkedIn', terms: ['linkedin'], ownDomains: ['linkedin.com', 'linkedinmail.com'] },
    { brand: 'Coinbase', terms: ['coinbase'], ownDomains: ['coinbase.com'] },
    { brand: 'DHL', terms: ['dhl'], ownDomains: ['dhl.com', 'dhl.de'] },
    { brand: 'FedEx', terms: ['fedex'], ownDomains: ['fedex.com'] }
];

/** Language that means a password or sign-in is being asked for. */
const CREDENTIAL_TERMS = [
    'password', 'passcode', 'sign in', 'sign-in', 'signin', 'log in', 'log-in', 'login',
    'credential', 'username', 'user name', 'verify your identity', 'verify your account',
    'confirm your identity', 'confirm your account', 'authenticate', 'authentication code',
    'two-factor', 'two factor', 'mfa code', 'otp', 'one-time code', 'one time password',
    'security code', 'account verification', 're-enter your', 'reenter your'
];

/** Language typical of a document-sharing notification. */
const SHARING_TERMS = [
    'shared a', 'shared with you', 'has shared', 'sent you a document', 'sent you a file',
    'review and sign', 'please sign', 'signature requested', 'awaiting your signature',
    'view document', 'view file', 'access the document', 'download the file',
    'secure document', 'secure file', 'shared folder'
];

class TrustedServiceAbuse {
    /** The registrable-ish tail of a hostname, matched against a platform host. */
    matchPlatform(hostname, pathname) {
        if (!hostname) return null;
        const host = hostname.toLowerCase();

        for (const platform of PLATFORMS) {
            const hit = platform.hosts.some(h => host === h || host.endsWith(`.${h}`));
            if (!hit) continue;
            // docs.google.com is Docs, Sheets and Forms; only the forms path is
            // a form builder, and treating a shared spreadsheet as one would be
            // wrong in the direction that produces false alarms.
            if (platform.pathHint && !(pathname || '').toLowerCase().includes(platform.pathHint)) continue;
            return platform;
        }
        return null;
    }

    textOf(threatObject, parsedEmail) {
        const deception = threatObject.text_deception?.normalised;
        const subject = deception?.subject || threatObject.message?.subject || parsedEmail?.subject || '';
        let body = deception?.body || parsedEmail?.textBody || '';

        if (!body && parsedEmail?.htmlBody) {
            body = parsedEmail.htmlBody
                .replace(/<style[\s\S]*?<\/style>/gi, ' ')
                .replace(/<script[\s\S]*?<\/script>/gi, ' ')
                .replace(/<[^>]+>/g, ' ')
                .replace(/\s+/g, ' ');
        }

        return `${subject}\n${body}`.toLowerCase();
    }

    analyze(threatObject, parsedEmail) {
        try {
            const text = this.textOf(threatObject, parsedEmail);
            const fromDomain = (parsedEmail?.from?.address || '').split('@')[1]?.toLowerCase() || '';
            const auth = threatObject.forensics?.authentication || {};

            // Did this message actually authenticate? That is the precondition
            // for everything here being interesting rather than redundant - a
            // message that already failed DMARC is caught by the authentication
            // family and does not need a second, weaker accusation.
            const authenticated = auth.spf === 'pass' || auth.dkim === 'pass' || auth.dmarc === 'pass';

            // Which platform, if any, carried this message.
            const sendingPlatform = this.matchPlatform(fromDomain, '');

            // Which platforms the links point at.
            const linked = [];
            for (const url of (threatObject.iocs?.urls || [])) {
                let parsed;
                try { parsed = new URL(url); } catch (e) { continue; }
                const platform = this.matchPlatform(parsed.hostname, parsed.pathname);
                if (platform && !linked.some(l => l.id === platform.id)) {
                    linked.push({ ...platform, example_url: url });
                }
            }

            const formBuilderLinks = linked.filter(l => l.category === 'FORM_BUILDER');
            const asksForCredentials = CREDENTIAL_TERMS.some(t => text.includes(t));
            const looksLikeSharing = SHARING_TERMS.some(t => text.includes(t));

            // Brands the message names, and whether the sender is actually them.
            const claimed = [];
            for (const entry of BRAND_CLAIMS) {
                if (!entry.terms.some(t => text.includes(t))) continue;
                const isOwn = entry.ownDomains.some(d => fromDomain === d || fromDomain.endsWith(`.${d}`));
                claimed.push({ brand: entry.brand, sent_by_the_brand: isOwn });
            }

            // The mismatch that matters: the message speaks for a brand, and a
            // different legitimate platform delivered it. Only meaningful when
            // the delivery authenticated - otherwise it is ordinary spoofing
            // and the authentication family already has it.
            const impersonated = claimed.filter(c => !c.sent_by_the_brand);
            const brandPlatformMismatch = (authenticated && sendingPlatform && impersonated.length)
                ? { claimed: impersonated.map(c => c.brand), delivered_by: sendingPlatform.name, category: sendingPlatform.category }
                : null;

            threatObject.trusted_service = {
                authenticated,
                sending_platform: sendingPlatform
                    ? { id: sendingPlatform.id, name: sendingPlatform.name, category: sendingPlatform.category }
                    : null,
                linked_platforms: linked.map(l => ({ id: l.id, name: l.name, category: l.category, example_url: l.example_url })),
                form_builder_links: formBuilderLinks.map(l => ({ name: l.name, url: l.example_url })),
                credential_language_present: asksForCredentials,
                sharing_language_present: looksLikeSharing,
                brands_claimed: claimed,
                brand_platform_mismatch: brandPlatformMismatch,
                // A form builder collecting credentials. The one combination
                // here with no innocent reading.
                credentials_via_form_builder: formBuilderLinks.length > 0 && asksForCredentials,
                // A share notification that wants a sign-in before it will show
                // you the thing it says was shared.
                sharing_notice_requesting_signin: looksLikeSharing && asksForCredentials,
                summary: this.summarise(formBuilderLinks, asksForCredentials, looksLikeSharing, brandPlatformMismatch, sendingPlatform)
            };
        } catch (err) {
            console.error('[TrustedServiceAbuse] Analysis failed:', err.message);
            threatObject.trusted_service = {
                status: 'UNAVAILABLE',
                reason: err.message,
                credentials_via_form_builder: false,
                sharing_notice_requesting_signin: false,
                brand_platform_mismatch: null,
                linked_platforms: [],
                form_builder_links: []
            };
        }

        return threatObject;
    }

    summarise(formLinks, credentials, sharing, mismatch, sendingPlatform) {
        const parts = [];

        if (formLinks.length && credentials) {
            parts.push(`Sign-in details are being requested through ${formLinks[0].name}, which is a public form builder. Organisations do not collect passwords this way.`);
        }
        if (mismatch) {
            parts.push(`The message speaks for ${mismatch.claimed.join(', ')} but was delivered through ${mismatch.delivered_by}, and it authenticated correctly - the delivery is genuine, the identity it claims is not.`);
        }
        if (sharing && credentials) {
            parts.push('A document-sharing notice that asks the reader to confirm their identity before viewing the document.');
        }
        if (!parts.length && sendingPlatform) {
            parts.push(`Delivered through ${sendingPlatform.name}. Recorded as context only - nothing about that is suspicious on its own.`);
        }

        return parts.length ? parts.join(' ') : 'No trusted-service abuse pattern observed.';
    }
}

module.exports = new TrustedServiceAbuse();
