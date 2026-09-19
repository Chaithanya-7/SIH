class IOCExtractor {
    extract(threatObject) {
        console.log('[IOCExtractor] Extracting IOCs (IPs, domains, URLs, hashes)...');

        const rawDataModel = threatObject._raw_data_model || {};
        const ips = new Set();
        const domains = new Set();
        const urls = new Set();
        const hashes = new Set();

        (threatObject.attachments || []).forEach(attachment => {
            if (attachment.sha256) hashes.add(attachment.sha256);
        });

        // 1. Extract Origin & Relay IPs
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip;
        if (originIp && originIp !== 'UNAVAILABLE') {
            ips.add(originIp);
        }
        (threatObject.forensics?.smtp_relay || []).forEach(r => {
            if (r.ip && r.ip !== 'UNAVAILABLE' && r.is_public) ips.add(r.ip);
        });

        // 2. Extract Sender & Recipient Domains
        const senderEmail = threatObject.message?.sender || '';
        const senderMatch = senderEmail.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (senderMatch) domains.add(senderMatch[1].toLowerCase());

        const recipientEmail = threatObject.message?.recipient || '';
        const recipientMatch = recipientEmail.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (recipientMatch) domains.add(recipientMatch[1].toLowerCase());

        // 3. Extract URLs & Body Links
        const plainBody = rawDataModel.body?.plain?.raw || threatObject._raw_email_string || '';
        const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
        let match;
        while ((match = urlRegex.exec(plainBody)) !== null) {
            const cleanUrl = match[1].replace(/[.,;)]+$/, '');
            urls.add(cleanUrl);
            try {
                const parsedUrl = new URL(cleanUrl);
                if (parsedUrl.hostname) domains.add(parsedUrl.hostname.toLowerCase());
            } catch (e) {
                // Ignore malformed URL parsing
            }
        }

        threatObject.iocs = {
            ips: Array.from(ips),
            domains: Array.from(domains),
            urls: Array.from(urls),
            hashes: Array.from(hashes)
        };

        return threatObject;
    }
}

module.exports = new IOCExtractor();
