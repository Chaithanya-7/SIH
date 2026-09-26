const PDFDocument = require('pdfkit');

class PDFReportGenerator {
    generateReport(threatObject, resStream) {
        console.log(`[PDFReportGenerator] Generating Investigator-Ready Forensic PDF Report for Case ${threatObject.case_id}...`);

        const doc = new PDFDocument({ margin: 40, size: 'A4' });

        // Pipe to response stream
        doc.pipe(resStream);

        // Header & Title
        doc.fillColor('#1a1a2e')
           .fontSize(20)
           .text('SECUREMAIL AI — INVESTIGATOR-READY FORENSIC REPORT', { align: 'center' });

        doc.fontSize(10)
           .fillColor('#666666')
           .text('Chain-of-Custody & Forensic Evidence Provenance Export', { align: 'center' });
        doc.moveDown(1.5);

        // 1. Case Metadata Banner
        doc.rect(40, doc.y, 515, 65).fill('#f4f4f8').stroke('#cccccc');
        const startY = doc.y - 58;

        doc.fillColor('#000000').fontSize(10)
           .text(`Case ID: ${threatObject.case_id}`, 50, startY)
           .text(`Ingestion Timestamp: ${threatObject.timestamps?.ingested_at || new Date().toISOString()}`, 50, startY + 15)
           .text(`Original SHA-256 Hash: ${threatObject.message?.raw_hash || 'N/A'}`, 50, startY + 30);
        
        doc.moveDown(3);

        // 1. Detection Findings
        doc.fontSize(12).fillColor('#1a1a2e').text('1. Detection Findings', { underline: true });
        doc.moveDown(0.5);
        const verdictColor = threatObject.detection?.verdict === 'HIGH_RISK' ? '#d9534f' : '#f0ad4e';
        doc.fontSize(10).fillColor(verdictColor).text(`Detection Verdict: ${threatObject.detection?.verdict || 'UNKNOWN'}`);
        doc.fillColor('#333333').text(`Matched Rules: ${(threatObject.detection?.matched_rules || []).join(', ') || 'None'}`);
        doc.fillColor('#333333').text(`Detection Signals: ${(threatObject.detection?.signals || []).join(', ') || 'None'}`);
        doc.moveDown(1.2);

        // 2. Authentication Analysis
        doc.fontSize(12).fillColor('#1a1a2e').text('2. Authentication Analysis', { underline: true });
        doc.moveDown(0.5);
        const auth = threatObject.forensics?.authentication || {};
        doc.fontSize(10).fillColor('#333333')
           .text(`SPF Status: ${(auth.spf || 'unknown').toUpperCase()}`)
           .text(`DKIM Status: ${(auth.dkim || 'unknown').toUpperCase()}`)
           .text(`DMARC Status: ${(auth.dmarc || 'unknown').toUpperCase()}`);
        doc.moveDown(1.2);

        // 3. Header Forensics & Return-Path
        doc.fontSize(12).fillColor('#1a1a2e').text('3. Header Forensics', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor('#333333')
           .text(`Sender: ${threatObject.message?.sender}`)
           .text(`Recipient: ${threatObject.message?.recipient}`)
           .text(`Subject: ${threatObject.message?.subject}`)
           .text(`Return-Path Mismatch: ${threatObject.forensics?.return_path_mismatch ? 'YES (SUSPICIOUS)' : 'NO'}`);
        doc.moveDown(1.2);

        // 4. SMTP Relay Analysis
        doc.fontSize(12).fillColor('#1a1a2e').text('4. SMTP Relay Analysis', { underline: true });
        doc.moveDown(0.5);
        (threatObject.forensics?.smtp_relay || []).forEach((hop, idx) => {
            doc.fontSize(9).fillColor('#333333')
               .text(`Hop ${idx + 1}: ${hop.hostname} (${hop.ip}) | Role: ${hop.classification} | Trust: ${Math.round(hop.trust_level * 100)}%`);
        });
        doc.moveDown(1.2);

        // 5. Infrastructure Intelligence
        doc.fontSize(12).fillColor('#1a1a2e').text('5. Infrastructure Intelligence', { underline: true });
        doc.moveDown(0.5);
        const origin = threatObject.infrastructure?.origin || {};
        const geo = threatObject.infrastructure?.geolocation || {};
        doc.fontSize(10).fillColor('#333333')
           .text(`Probable Origin IP: ${origin.origin_ip || threatObject.infrastructure?.origin_ip || 'UNAVAILABLE'}`)
           .text(`Infrastructure Type: ${origin.origin_type || 'PROBABLE_SENDING_INFRASTRUCTURE'}`)
           .text(`Provider / Host: ${origin.origin_provider || 'External Mail Infrastructure'}`)
           .text(`Country / City: ${geo.country || 'Unavailable'}, ${geo.city || ''}`)
           .text(`ASN / ISP: ${geo.asn || 'N/A'} / ${geo.isp || 'N/A'}`);
        if (origin.limitation) {
            doc.fontSize(9).fillColor('#d9534f').text(`Limitation Note: ${origin.limitation}`);
        }
        doc.moveDown(1.2);

        // 6. IOC Analysis
        doc.fontSize(12).fillColor('#1a1a2e').text('6. IOC Analysis', { underline: true });
        doc.moveDown(0.5);
        const iocs = threatObject.iocs || {};
        doc.fontSize(9).fillColor('#333333')
           .text(`IPs: ${(iocs.ips || []).join(', ') || 'None'}`)
           .text(`Domains: ${(iocs.domains || []).join(', ') || 'None'}`)
           .text(`URLs: ${(iocs.urls || []).join(', ') || 'None'}`);
        doc.moveDown(1.2);

        // 7. Evidence Fusion
        doc.fontSize(12).fillColor('#1a1a2e').text('7. Evidence Fusion', { underline: true });
        doc.moveDown(0.5);
        (threatObject.evidence || []).forEach((ev, idx) => {
            doc.fontSize(9).fillColor('#000000').text(`${idx + 1}. [${ev.severity}] ${ev.finding} (${ev.source})`);
            doc.fontSize(8).fillColor('#555555').text(`   ${ev.explanation}`);
        });
        doc.moveDown(1.2);

        // 8. Campaign Correlation
        doc.fontSize(12).fillColor('#1a1a2e').text('8. Campaign Correlation', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(9).fillColor('#333333')
           .text(`Correlations Found: ${(threatObject.correlations || []).length}`)
           .text(`Campaign Association Score: ${((threatObject.confidence?.campaign_association || 0) * 100).toFixed(0)}%`);
        doc.moveDown(1.2);

        // 9. Confidence Assessment
        doc.fontSize(12).fillColor('#1a1a2e').text('9. Confidence Assessment', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(9).fillColor('#333333')
           .text(`Threat Confidence: ${((threatObject.confidence?.threat || 0) * 100).toFixed(0)}%`)
           .text(`Infrastructure-Origin Confidence: ${((threatObject.confidence?.infrastructure_origin || 0) * 100).toFixed(0)}%`)
           .text(`Actor Attribution: ${threatObject.confidence?.actor_attribution || 'INSUFFICIENT EVIDENCE'}`);
        doc.moveDown(1.2);

        // 10. Remediation History
        doc.fontSize(12).fillColor('#1a1a2e').text('10. Remediation History', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(9).fillColor('#333333')
           .text(`Remediation Status: ${threatObject.remediation?.status}`)
           .text(`Policy Matched: ${threatObject.remediation?.policy_matched || 'None'}`);
        doc.moveDown(1.2);

        // 11. Audit Trail
        doc.fontSize(12).fillColor('#1a1a2e').text('11. Audit Trail', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(8).fillColor('#666666')
           .text(`Generated automatically by SecureMail AI Platform. Chain-of-Custody SHA-256: ${threatObject.message?.raw_hash}`);

        doc.end();
    }
}

module.exports = new PDFReportGenerator();
