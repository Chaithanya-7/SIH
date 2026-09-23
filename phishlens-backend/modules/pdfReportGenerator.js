const PDFDocument = require('pdfkit');
const auditLogger = require('./auditLogger');
const remediationEngine = require('./remediationEngine');

/**
 * Investigator-complete forensic report.
 *
 * The report is written to be defensible rather than impressive: every
 * conclusion is accompanied by the evidence behind it, every detection rule
 * carries the public source it was derived from, and every limitation is
 * printed next to the finding it limits rather than buried at the end. A
 * reader who disagrees with the verdict should be able to see exactly which
 * observations produced it.
 *
 * Evidence is kept visually separate from conclusions, and anything the system
 * could not determine is stated as unavailable rather than omitted, so absence
 * is never mistaken for a negative result.
 */

const COLORS = {
    heading: '#1a1a2e',
    body: '#333333',
    muted: '#666666',
    caution: '#b45309',
    critical: '#b91c1c',
    safe: '#15803d',
    rule: '#1e3a8a'
};

class PDFReportGenerator {
    generateReport(threatObject, resStream) {
        const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true });
        doc.pipe(resStream);

        this.renderTitle(doc, threatObject);
        // Before the disposition, not after it. A qualification printed below
        // the verdict is read after the verdict has already been believed.
        this.renderAnalysisMode(doc, threatObject);
        this.renderDisposition(doc, threatObject);
        this.renderCaseInformation(doc, threatObject);
        this.renderMessageMetadata(doc, threatObject);
        this.renderAuthentication(doc, threatObject);
        this.renderRelayPath(doc, threatObject);
        this.renderInfrastructure(doc, threatObject);
        this.renderThreatIntelligence(doc, threatObject);
        this.renderIndicators(doc, threatObject);
        this.renderAttachments(doc, threatObject);
        this.renderLanguageFindings(doc, threatObject);
        this.renderRuleMatches(doc, threatObject);
        this.renderBehaviouralFindings(doc, threatObject);
        this.renderLearnedPattern(doc, threatObject);
        this.renderEvidence(doc, threatObject);
        this.renderRiskAssessment(doc, threatObject);
        this.renderCampaign(doc, threatObject);
        this.renderRemediation(doc, threatObject);
        this.renderTimeline(doc, threatObject);
        this.renderAnalystNotes(doc, threatObject);
        this.renderDisclaimer(doc, threatObject);

        this.paginate(doc, threatObject);
        doc.end();
    }

    // ---------- layout helpers ----------

    /** Starts a section, moving to a new page rather than orphaning the heading. */
    section(doc, title) {
        this.ensureSpace(doc, 70);
        doc.moveDown(0.8);
        doc.fontSize(12).fillColor(COLORS.heading).font('Helvetica-Bold').text(title);
        doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).strokeColor('#cccccc').lineWidth(0.5).stroke();
        doc.moveDown(0.5);
        doc.font('Helvetica');
    }

    ensureSpace(doc, needed) {
        const remaining = doc.page.height - doc.page.margins.bottom - doc.y;
        if (remaining < needed) doc.addPage();
    }

    kv(doc, label, value) {
        this.ensureSpace(doc, 22);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text(`${label}: `, { continued: true });
        doc.font('Helvetica').text(this.safe(value));
    }

    body(doc, text, color = COLORS.body, size = 9) {
        this.ensureSpace(doc, 26);
        doc.fontSize(size).fillColor(color).font('Helvetica').text(this.safe(text), { align: 'left' });
    }

    /**
     * States, at the top, when a verdict rests on less than a live one does.
     *
     * A backlog scan reads mail that arrived long ago. The checks that describe
     * infrastructure could only describe it as it is now - domain age inverts,
     * indicator feeds have delisted what was listed, addresses have changed
     * hands - so they are not run rather than run and recorded as having found
     * nothing.
     *
     * The backend already refuses to score a check it could not honestly
     * perform. This is the other half: a report that renders a historical SAFE
     * identically to a live one hands the reader the same reassurance on less
     * evidence, and a forensic report is exactly the document somebody quotes
     * later without re-reading the case.
     */
    renderAnalysisMode(doc, threatObject) {
        const mode = threatObject.analysis_mode;
        if (!mode || mode.mode !== 'HISTORICAL') return;

        this.section(doc, 'Analysed after the fact');

        if (mode.age_description) this.kv(doc, 'Message age', mode.age_description);
        this.body(doc, mode.verdict_caveat, COLORS.body);

        const skipped = mode.checks_not_applicable || [];
        if (skipped.length) {
            doc.moveDown(0.3);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
                .text(`Checks not performed (${skipped.length})`);
            doc.font('Helvetica');

            for (const entry of skipped) {
                this.ensureSpace(doc, 34);
                doc.fontSize(8.5).fillColor(COLORS.body).font('Helvetica-Bold')
                    .text(`  ${entry.check.replace(/_/g, ' ')}`);
                // The reason, every time. "Not applicable" with nothing after it
                // is the same dead end as a silent skip.
                doc.fontSize(8).fillColor(COLORS.muted).font('Helvetica')
                    .text(`  ${this.safe(entry.reason)}`, { indent: 6 });
            }
        }

        if (mode.remediation) {
            doc.moveDown(0.3);
            this.body(doc, mode.remediation, COLORS.muted, 8.5);
        }
    }

    /** A limitation printed next to the finding it qualifies, not hidden at the end. */
    limitation(doc, text) {
        if (!text) return;
        this.ensureSpace(doc, 26);
        doc.fontSize(8).fillColor(COLORS.muted).font('Helvetica-Oblique').text(`Limitation: ${this.safe(text)}`);
        doc.font('Helvetica');
    }

    none(doc, text) {
        doc.fontSize(9).fillColor(COLORS.muted).font('Helvetica-Oblique').text(this.safe(text));
        doc.font('Helvetica');
    }

    safe(value) {
        if (value === null || value === undefined || value === '') return 'Not available';
        if (Array.isArray(value)) return value.length ? value.join(', ') : 'None';
        return String(value);
    }

    verdictColor(verdict) {
        if (verdict === 'HIGH_RISK') return COLORS.critical;
        if (verdict === 'SUSPICIOUS') return COLORS.caution;
        if (verdict === 'SAFE') return COLORS.safe;
        return COLORS.muted;
    }

    // ---------- sections ----------

    renderTitle(doc, threatObject) {
        doc.fontSize(20).fillColor(COLORS.heading).font('Helvetica-Bold')
            .text('PhishLens Forensic Analysis Report', { align: 'center' });
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor(COLORS.muted).font('Helvetica')
            .text(`Case ${this.safe(threatObject.case_id)}  ·  Generated ${new Date().toISOString()}`, { align: 'center' });
        doc.moveDown(1);
    }

    /**
     * The conclusion and what to do about it, stated first. Everything that
     * follows is the evidence a reader needs to check that conclusion.
     */
    renderDisposition(doc, threatObject) {
        const verdict = threatObject.detection?.verdict || 'UNKNOWN';
        const score = Math.round((threatObject.confidence?.threat || 0) * 100);

        this.ensureSpace(doc, 120);
        doc.rect(50, doc.y, 495, 58).fillAndStroke('#f8fafc', '#cbd5e1');
        const top = doc.y + 10;
        doc.fontSize(14).fillColor(this.verdictColor(verdict)).font('Helvetica-Bold')
            .text(`DISPOSITION: ${verdict.replace('_', ' ')}`, 62, top);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica')
            .text(`Assessed threat confidence: ${score}%   ·   Review status: ${this.safe(threatObject.review?.status)}   ·   Mailbox state: ${this.safe(threatObject.mailbox?.status)}`, 62, top + 20);
        doc.fontSize(9).fillColor(COLORS.body)
            .text(`Recommended action: ${this.recommendedAction(threatObject)}`, 62, top + 34);
        doc.y = top + 62;
        doc.moveDown(0.5);
    }

    recommendedAction(threatObject) {
        const verdict = threatObject.detection?.verdict;
        const policy = threatObject.remediation?.policy_matched;
        if (policy) return `${policy} (policy-driven)`;
        if (verdict === 'HIGH_RISK') return 'Quarantine and notify the recipient; confirm through analyst review before release.';
        if (verdict === 'SUSPICIOUS') return 'Hold for analyst review; warn the recipient before delivery.';
        if (verdict === 'SAFE') return 'No action required.';
        return 'Insufficient assessment to recommend an action.';
    }

    renderCaseInformation(doc, threatObject) {
        this.section(doc, '1. Case Information');
        this.kv(doc, 'Case identifier', threatObject.case_id);
        this.kv(doc, 'Ingested at', threatObject.timestamps?.ingested_at);
        this.kv(doc, 'Organisation', threatObject.org_id || 'Not assigned');
        this.kv(doc, 'Detection engine', threatObject.detection?.provider);
        this.kv(doc, 'Verification status', threatObject.detection?.verification_status);
        const external = threatObject.detection?.external_provider_result;
        if (external?.attempted) {
            this.kv(doc, 'External provider cross-check', `${external.provider} — ${external.status}`);
            this.limitation(doc, external.note);
        }
    }

    renderMessageMetadata(doc, threatObject) {
        this.section(doc, '2. Message Metadata');
        this.kv(doc, 'Sender', threatObject.message?.sender);
        this.kv(doc, 'Recipient', threatObject.message?.recipient);
        this.kv(doc, 'Subject', threatObject.message?.subject);
        this.kv(doc, 'Delivered at', threatObject.message?.delivered_at);
        this.kv(doc, 'Raw message SHA-256', threatObject.message?.raw_hash);
        this.body(doc, 'The SHA-256 above is the chain-of-custody reference for the exact bytes analysed. The message body itself is deliberately not retained.', COLORS.muted, 8);
    }

    renderAuthentication(doc, threatObject) {
        const auth = threatObject.forensics?.authentication || {};
        this.section(doc, '3. Authentication Results (SPF / DKIM / DMARC)');
        this.kv(doc, 'SPF', `${this.safe(auth.spf)}${auth.source?.spf ? ` (${auth.source.spf})` : ''}`);
        this.kv(doc, 'DKIM', `${this.safe(auth.dkim)}${auth.source?.dkim ? ` (${auth.source.dkim})` : ''}`);
        this.kv(doc, 'DMARC', `${this.safe(auth.dmarc)}${auth.source?.dmarc ? ` (${auth.source.dmarc})` : ''}`);
        if (auth.authserv_id) this.kv(doc, 'Reported by', auth.authserv_id);

        const dkim = auth.dkim_independent_verification;
        if (dkim) {
            this.kv(doc, 'Independent DKIM verification', `${this.safe(dkim.overall)} (${this.safe(dkim.status)})`);
            (dkim.results || []).forEach(r => {
                this.body(doc, `  · ${this.safe(r.signing_domain)} selector ${this.safe(r.selector)}: ${this.safe(r.result)}${r.comment ? ` — ${r.comment}` : ''}`);
            });
        }
        if (auth.dkim_header_mismatch) {
            this.body(doc, `Discrepancy: ${auth.dkim_header_mismatch}`, COLORS.critical);
        }

        const policy = auth.dmarc_policy;
        if (policy) {
            this.kv(doc, 'Published DMARC policy', policy.status === 'AVAILABLE' ? `p=${policy.policy} (pct=${policy.percentage})` : `Unavailable — ${this.safe(policy.reason)}`);
        }
        this.limitation(doc, auth.limitation);
        this.body(doc, 'An authentication failure is not by itself proof of malice: legitimate forwarding and mailing lists routinely break SPF and DKIM. It is weighed alongside the other findings below.', COLORS.muted, 8);
    }

    renderRelayPath(doc, threatObject) {
        this.section(doc, '4. Relay Path Reconstruction');
        const relays = threatObject.forensics?.smtp_relay || [];
        this.kv(doc, 'Return-Path mismatch', threatObject.forensics?.return_path_mismatch ? 'Yes' : 'No');
        if (!relays.length) return this.none(doc, 'No relay hops could be reconstructed from the message headers.');

        relays.forEach(hop => {
            this.ensureSpace(doc, 34);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
                .text(`Hop ${hop.hop_index}: ${this.safe(hop.hostname)} [${this.safe(hop.ip)}]`);
            doc.font('Helvetica').fontSize(8).fillColor(COLORS.muted)
                .text(`   ${this.safe(hop.classification)} · trust ${hop.trust_level} · ${this.safe(hop.trust_explanation)}`);
        });
        this.body(doc, 'Received headers are attacker-visible and can be forged below the first trusted boundary. Hops are classified by role rather than assumed truthful.', COLORS.muted, 8);
    }

    renderInfrastructure(doc, threatObject) {
        const infra = threatObject.infrastructure || {};
        const origin = infra.origin || {};
        this.section(doc, '5. Infrastructure and Geolocation');
        this.kv(doc, 'Selected origin IP', infra.origin_ip || 'Not determined');
        this.kv(doc, 'Origin provider', origin.origin_provider);
        this.kv(doc, 'Selection basis', origin.selection_reason);
        this.kv(doc, 'Origin confidence', origin.origin_confidence !== undefined ? `${Math.round((origin.origin_confidence || 0) * 100)}%` : null);
        this.kv(doc, 'ASN', infra.asn);
        this.kv(doc, 'ISP', infra.isp);

        const geo = infra.geolocation;
        if (geo && geo.status === 'AVAILABLE') {
            this.kv(doc, 'Observed location', `${this.safe(geo.city)}, ${this.safe(geo.country)}`);
        } else {
            this.kv(doc, 'Observed location', 'Unavailable');
        }
        this.body(doc, 'This describes where the observed sending infrastructure sits. It is not the location of the person who sent the message, and must not be reported as such.', COLORS.caution, 8);
        this.limitation(doc, origin.limitation);
    }

    renderThreatIntelligence(doc, threatObject) {
        const intel = threatObject.threat_intelligence || {};
        this.section(doc, '6. Threat Intelligence');

        const feed = intel.feed_state || {};
        this.kv(doc, 'Feed state', feed.synced ? `Synced${feed.age_hours !== null && feed.age_hours !== undefined ? ` ${feed.age_hours}h ago` : ''}` : 'No feed data synchronised');
        if (feed.indicator_totals) {
            this.kv(doc, 'Indicators held locally', `${feed.indicator_totals.urls || 0} URLs, ${feed.indicator_totals.domains || 0} domains, ${feed.indicator_totals.ips || 0} IPs, ${feed.indicator_totals.netblocks || 0} netblocks`);
        }

        const matches = intel.matches || [];
        doc.moveDown(0.3);
        if (!matches.length) {
            this.none(doc, 'No indicator from this message matched a known-bad list.');
        } else {
            matches.forEach(m => {
                this.ensureSpace(doc, 30);
                doc.fontSize(9).fillColor(COLORS.critical).font('Helvetica-Bold')
                    .text(`${this.safe(m.indicator_type)} match (${this.safe(m.matched)}) — feed: ${this.safe(m.feed)}`);
                doc.font('Helvetica').fontSize(8).fillColor(COLORS.body).text(`   ${this.safe(m.indicator)}`);
            });
        }

        const ages = intel.domain_ages || [];
        if (ages.length) {
            doc.moveDown(0.3);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Domain registration age');
            doc.font('Helvetica');
            ages.forEach(a => {
                const detail = a.status === 'AVAILABLE'
                    ? `${a.age_days} days (registered ${a.registered_at})`
                    : `Unavailable — ${this.safe(a.reason)}`;
                this.body(doc, `  · ${this.safe(a.domain)}${a.is_sender_domain ? ' (sender domain)' : ''}: ${detail}`);
            });
        }
        this.limitation(doc, intel.limitation);
    }

    renderIndicators(doc, threatObject) {
        const iocs = threatObject.iocs || {};
        this.section(doc, '7. Indicators of Compromise');
        this.kv(doc, 'IP addresses', iocs.ips);
        this.kv(doc, 'Domains', iocs.domains);
        this.kv(doc, 'Attachment hashes', iocs.hashes);
        doc.moveDown(0.2);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('URLs');
        doc.font('Helvetica');
        const urls = iocs.urls || [];
        if (!urls.length) return this.none(doc, 'No URLs were present in the message body.');
        urls.forEach(u => this.body(doc, `  · ${u}`, COLORS.body, 8));
    }

    renderAttachments(doc, threatObject) {
        const attachments = threatObject.attachments || [];
        this.section(doc, '8. Attachment Analysis');
        if (!attachments.length) return this.none(doc, 'The message carried no attachments.');

        attachments.forEach(a => {
            this.ensureSpace(doc, 46);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text(this.safe(a.file_name));
            doc.font('Helvetica').fontSize(8).fillColor(COLORS.body)
                .text(`   Type: ${this.safe(a.mime_type)} · Extension: ${this.safe(a.extension)} · Size: ${this.safe(a.size_bytes)} bytes`)
                .text(`   SHA-256: ${this.safe(a.sha256)}`);
            doc.fillColor(COLORS.muted).text(`   ${this.safe(a.limitation)}`);
        });
    }

    renderLanguageFindings(doc, threatObject) {
        const nlp = threatObject.nlp || {};
        const signals = nlp.signals || [];
        this.section(doc, '9. Language and Social-Engineering Findings');
        this.kv(doc, 'Analysis engine', nlp.engine);
        this.kv(doc, 'Aggregate language score', `${Math.round((nlp.score || 0) * 100)}%`);
        doc.moveDown(0.3);

        if (!signals.length) {
            this.none(doc, 'No social-engineering language patterns were identified.');
        } else {
            signals.forEach(s => {
                this.ensureSpace(doc, 46);
                doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
                    .text(`${s.type.replace(/_/g, ' ')} — ${s.severity} (${Math.round(s.confidence * 100)}%)`);
                doc.font('Helvetica').fontSize(8).fillColor(COLORS.body)
                    .text(`   Matched wording: ${this.safe(s.matched_terms)}`)
                    .text(`   ${this.safe(s.explanation)}`);
                if (s.source) doc.fillColor(COLORS.muted).text(`   Source: ${s.source}`);
            });
        }
        this.limitation(doc, nlp.limitation);
    }

    /**
     * Each rule is printed with the public source it derives from, so a reader
     * can audit why the rule exists rather than taking the match on trust.
     */
    renderRuleMatches(doc, threatObject) {
        const rules = threatObject.detection?.matched_rules || [];
        const engine = threatObject.detection?.rule_engine;
        this.section(doc, '10. Detection Rule Matches');
        if (engine) {
            this.kv(doc, 'Rule engine', `${engine.engine} — ${engine.rules_matched} of ${engine.rules_evaluated} rules matched`);
        }
        doc.moveDown(0.3);

        if (!rules.length) return this.none(doc, 'No detection rules matched this message.');

        rules.forEach(rule => {
            this.ensureSpace(doc, 58);
            doc.fontSize(9).fillColor(COLORS.rule).font('Helvetica-Bold')
                .text(`${this.safe(rule.id)} — ${this.safe(rule.name)}`);
            doc.font('Helvetica').fontSize(8).fillColor(COLORS.body)
                .text(`   Severity: ${this.safe(rule.severity)} · Confidence: ${Math.round((rule.confidence || 0) * 100)}%${rule.decisive ? ' · DECISIVE' : ''}`)
                .text(`   Why it matched: ${this.safe(rule.matched_because)}`);
            doc.fillColor(COLORS.muted).text(`   Rule source: ${this.safe(rule.source)}`);
        });

        this.renderTechniques(doc, threatObject);
        this.renderQrFindings(doc, threatObject);
        this.renderArcChain(doc, threatObject);
    }

    /**
     * Techniques as identifiers, with the rules that attributed each.
     *
     * A reader who disagrees with an attribution needs to see what produced it;
     * a bare list of technique numbers is an assertion, not evidence.
     */
    renderTechniques(doc, threatObject) {
        const patterns = threatObject.detection?.attack_patterns || [];
        if (!patterns.length) return;

        doc.moveDown(0.4);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Attack techniques (MITRE ATT&CK)');
        doc.font('Helvetica').fontSize(8);
        patterns.forEach(pattern => {
            this.ensureSpace(doc, 22);
            doc.fillColor(COLORS.body).text(`   ${this.safe(pattern.technique)}  ${this.safe(pattern.name || 'name not held locally')}`);
            doc.fillColor(COLORS.muted).text(`      attributed by: ${this.safe((pattern.attributed_by || []).join(', '))}`);
        });
    }

    /**
     * The decoded destination, in full.
     *
     * A QR code is the one finding a reader cannot check for themselves by
     * looking at the message - the link is not written anywhere in it - so the
     * report has to carry the whole URL rather than a summary of it.
     */
    renderQrFindings(doc, threatObject) {
        const qr = threatObject.qr;
        if (!qr || (!qr.codes_found && !(qr.not_scanned || []).length)) return;

        doc.moveDown(0.4);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('QR codes decoded from attachments');
        doc.font('Helvetica').fontSize(8);

        (qr.codes || []).forEach(code => {
            this.ensureSpace(doc, 40);
            doc.fillColor(COLORS.body)
                .text(`   ${this.safe(code.filename)} (${this.safe(code.dimensions)}, ${this.safe(code.payload_kind)}${code.polarity === 'inverted' ? ', inverted' : ''})`);
            doc.fillColor(COLORS.rule).text(`      ${this.safe(code.payload)}`);
        });

        (qr.not_scanned || []).forEach(item => {
            this.ensureSpace(doc, 26);
            doc.fillColor(COLORS.muted).text(`   ${this.safe(item.filename)} — not scanned: ${this.safe(item.reason)}`);
        });

        if (!qr.codes_found) {
            doc.fillColor(COLORS.muted).text('   No QR code was decoded from this message.');
        }
    }

    /** The chain, and an explicit statement that a valid one is not reassurance. */
    renderArcChain(doc, threatObject) {
        const arc = threatObject.forensics?.arc;
        if (!arc || arc.status === 'ABSENT') return;

        doc.moveDown(0.4);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
            .text(`Forwarding chain (ARC, RFC 8617) — ${this.safe(arc.status)}`);
        doc.font('Helvetica').fontSize(8).fillColor(COLORS.body).text(`   ${this.safe(arc.explanation)}`);

        (arc.intermediaries || []).forEach(hop => {
            this.ensureSpace(doc, 20);
            const seen = hop.authentication_seen
                ? ` — recorded spf=${hop.authentication_seen.spf || 'n/a'}, dkim=${hop.authentication_seen.dkim || 'n/a'}`
                : '';
            doc.fillColor(COLORS.muted).text(`   i=${hop.instance} ${this.safe(hop.signing_domain || 'unnamed')}${this.safe(seen)}`);
        });

        doc.fillColor(COLORS.caution).text(`   ${this.safe(arc.risk_note)}`);
    }

    renderBehaviouralFindings(doc, threatObject) {
        const behavioural = threatObject.behavioral || {};
        const signals = behavioural.signals || [];
        this.section(doc, '11. Behavioural Findings');
        this.kv(doc, 'Sender previously observed', behavioural.known_sender ? 'Yes' : 'No (first contact)');
        this.kv(doc, 'Messages previously seen from sender', behavioural.messages_seen_from_sender ?? 0);
        doc.moveDown(0.3);

        if (!signals.length) {
            this.none(doc, 'No behavioural deviation was identified against observed sender history.');
        } else {
            signals.forEach(s => {
                this.ensureSpace(doc, 40);
                doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
                    .text(`${s.type.replace(/_/g, ' ')} — ${s.severity} (${Math.round(s.confidence * 100)}%)`);
                doc.font('Helvetica').fontSize(8).fillColor(COLORS.body).text(`   ${this.safe(s.explanation)}`);
            });
        }
        this.limitation(doc, behavioural.limitation);
    }

    renderLearnedPattern(doc, threatObject) {
        const adaptive = threatObject.adaptive || {};
        this.section(doc, '12. Learned-Pattern Assessment');

        if (adaptive.status !== 'SCORED') {
            this.none(doc, this.safe(adaptive.limitation || 'Adaptive learning did not score this message.'));
            return;
        }

        this.kv(doc, 'Similarity to previously confirmed mail', `${Math.round((adaptive.score || 0) * 100)}%`);
        this.kv(doc, 'Learned from', `${adaptive.learned_from?.malicious || 0} confirmed malicious, ${adaptive.learned_from?.legitimate || 0} confirmed legitimate`);
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Contributing characteristics');
        doc.font('Helvetica');
        (adaptive.contributions || []).slice(0, 12).forEach(c => {
            this.body(doc, `  · ${c.characteristic}  (weight ${c.weight}; seen in ${c.seen_in_malicious} malicious / ${c.seen_in_legitimate} legitimate)`, COLORS.body, 8);
        });
        this.limitation(doc, adaptive.limitation);
    }

    renderEvidence(doc, threatObject) {
        const evidence = threatObject.evidence || [];
        this.section(doc, '13. Evidence Register');
        if (!evidence.length) return this.none(doc, 'No evidence items were recorded for this case.');

        evidence.forEach((ev, idx) => {
            this.ensureSpace(doc, 50);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold')
                .text(`${idx + 1}. [${this.safe(ev.severity)}] ${this.safe(ev.finding)}`);
            doc.font('Helvetica').fontSize(8).fillColor(COLORS.body)
                .text(`   ${this.safe(ev.explanation)}`);
            doc.fillColor(COLORS.muted)
                .text(`   Source: ${this.safe(ev.source)} · Provenance: ${this.safe(ev.provenance?.source_type)} ${this.safe(ev.provenance?.source_reference)} · Recorded ${this.safe(ev.timestamp)}`);
        });
    }

    renderRiskAssessment(doc, threatObject) {
        const confidence = threatObject.confidence || {};
        this.section(doc, '14. Risk Assessment');
        this.kv(doc, 'Threat confidence', `${Math.round((confidence.threat || 0) * 100)}%`);
        this.kv(doc, 'Infrastructure-origin confidence', `${Math.round((confidence.infrastructure_origin || 0) * 100)}%`);
        this.kv(doc, 'Campaign-association confidence', `${Math.round((confidence.campaign_association || 0) * 100)}%`);
        this.kv(doc, 'Actor attribution', confidence.actor_attribution);
        this.kv(doc, 'Scoring model', confidence.scoring_version);

        doc.moveDown(0.3);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('How the score was reached');
        doc.font('Helvetica');
        const contributions = confidence.contributions || [];
        if (!contributions.length) {
            this.none(doc, 'No scoring contributions were recorded.');
        } else {
            contributions.forEach(c => {
                this.ensureSpace(doc, 34);
                doc.fontSize(8).fillColor(COLORS.body)
                    .text(`  · ${this.safe(c.family)}: +${c.contribution} — ${this.safe(c.representative_finding)}`);
                if (c.explanation) doc.fillColor(COLORS.muted).text(`     ${c.explanation}`);
            });
        }
        this.body(doc, 'Correlated findings within one family are not counted as independent proof: the strongest contributes in full and further findings at reducing weight.', COLORS.muted, 8);
    }

    renderCampaign(doc, threatObject) {
        const campaign = threatObject.campaign_association || {};
        this.section(doc, '15. Campaign Relationships');
        this.kv(doc, 'Association status', campaign.status);
        this.kv(doc, 'Association confidence', `${Math.round((campaign.confidence || 0) * 100)}%`);
        this.kv(doc, 'Related cases', campaign.related_cases);

        const factors = campaign.factors || [];
        doc.moveDown(0.3);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Why these cases are linked');
        doc.font('Helvetica');
        if (!factors.length) {
            this.none(doc, 'No correlating factor linked this message to another case.');
        } else {
            factors.forEach(f => this.body(doc, `  · ${this.safe(f.factor)}: ${this.safe(f.evidence)}`, COLORS.body, 8));
        }

        // Recording what was deliberately NOT linked is part of a defensible
        // report: it shows the grouping was reasoned about, not merely absent.
        const suppressed = campaign.suppressed_factors || [];
        if (suppressed.length) {
            doc.moveDown(0.3);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Links deliberately not made');
            doc.font('Helvetica');
            suppressed.forEach(s => this.body(doc, `  · ${this.safe(s.indicator)}: ${this.safe(s.reason)}`, COLORS.body, 8));
        }

        const semantic = campaign.semantic_matches || [];
        if (semantic.length) {
            doc.moveDown(0.3);
            doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Messages reusing the same wording');
            doc.font('Helvetica');
            semantic.forEach(m => this.body(doc, `  · ${m.case_id}: ${Math.round(m.similarity * 100)}% similar — shared terms: ${this.safe(m.shared_terms)}`, COLORS.body, 8));
        }
        this.limitation(doc, campaign.limitation);
    }

    renderRemediation(doc, threatObject) {
        this.section(doc, '16. Response and Remediation');
        this.kv(doc, 'Remediation status', threatObject.remediation?.status);
        this.kv(doc, 'Policy matched', threatObject.remediation?.policy_matched || 'None');
        this.kv(doc, 'Provider action state', threatObject.provider_action?.status);

        // The three facts a reader of this report most needs and is least able
        // to infer: whether this installation acts on mail at all, where the
        // message physically is now, and - if nothing was done - which control
        // decided that. A report that states a status without them invites the
        // reader to assume the message was contained.
        this.kv(doc, 'Response mode', (threatObject.remediation?.mode || threatObject.remediation?.capability?.mode || 'unknown').toUpperCase());
        this.kv(doc, 'Message location now', threatObject.mailbox?.status === 'QUARANTINED'
            ? 'Quarantined - removed from the inbox'
            : threatObject.mailbox?.status === 'RELEASED'
                ? 'Restored to the inbox'
                : 'Still in the recipient inbox');
        if (threatObject.remediation?.blocked_by) {
            this.kv(doc, 'Held back by', threatObject.remediation.blocked_by);
        }
        if (threatObject.remediation?.detail) {
            this.body(doc, threatObject.remediation.detail, COLORS.muted, 8);
        }
        if (threatObject.remediation?.warning) {
            doc.moveDown(0.2);
            this.kv(doc, 'Recipient warned', threatObject.remediation.warning.recipient_visible
                ? 'Yes - the warning is visible to the recipient'
                : 'No - the warning is recorded on this case only');
        }

        let actions = [];
        try {
            actions = (remediationEngine.getAllActions() || []).filter(a => a.case_id === threatObject.case_id);
        } catch (e) {
            actions = [];
        }

        doc.moveDown(0.3);
        doc.fontSize(9).fillColor(COLORS.body).font('Helvetica-Bold').text('Action history');
        doc.font('Helvetica');
        if (!actions.length) {
            this.none(doc, 'No remediation action has been recorded against this case.');
        } else {
            actions.forEach(a => {
                this.ensureSpace(doc, 40);
                doc.fontSize(8).fillColor(COLORS.body)
                    .text(`  · ${this.safe(a.action_type)} — ${this.safe(a.status)} (requested by ${this.safe(a.requested_by)} at ${this.safe(a.requested_at)})`);
                if (a.provider_result) {
                    doc.fillColor(COLORS.muted).text(`     Provider result: ${this.safe(a.provider_result.status)}${a.provider_result.message ? ` — ${a.provider_result.message}` : ''}`);
                }
                if (a.failure_reason) doc.fillColor(COLORS.critical).text(`     Failure: ${a.failure_reason}`);
            });
        }
        this.body(doc, 'An action is only reported as confirmed where the mail provider acknowledged it. Simulated actions are labelled as such and must not be read as containment.', COLORS.caution, 8);
    }

    renderTimeline(doc, threatObject) {
        this.section(doc, '17. Case Timeline');
        let events = [];
        try {
            events = (auditLogger.getAllEvents() || []).filter(e => e.case_id === threatObject.case_id);
        } catch (e) {
            events = [];
        }

        if (!events.length) {
            this.none(doc, 'No audit events are retained for this case. The audit log is capped, so older events may have been rotated out.');
            return;
        }

        events.forEach(e => {
            this.ensureSpace(doc, 30);
            doc.fontSize(8).fillColor(COLORS.body)
                .text(`  · ${this.safe(e.timestamp)} — ${this.safe(e.event_type)} (${this.safe(e.source)})`);
            if (e.description) doc.fillColor(COLORS.muted).text(`     ${e.description}`);
        });
    }

    renderAnalystNotes(doc, threatObject) {
        const context = threatObject.containment_context || {};
        this.section(doc, '18. Analyst Decision and Notes');
        this.kv(doc, 'Review status', threatObject.review?.status);
        this.kv(doc, 'Decision reason', context.decision_reason || 'No analyst decision has been recorded.');
        this.kv(doc, 'Analyst note', context.admin_note || 'None recorded.');
        this.kv(doc, 'Contained at', context.contained_at || 'Not contained');
        this.kv(doc, 'Released at', context.released_at || 'Not released');
    }

    renderDisclaimer(doc, threatObject) {
        this.section(doc, '19. Scope and Limitations');
        this.body(doc, 'This report records what PhishLens observed and the reasoning applied to those observations. It is an analytical product, not a legal determination of intent or identity.', COLORS.body, 8);
        doc.moveDown(0.2);
        [
            'Actor attribution is reported as INSUFFICIENT EVIDENCE unless independent attribution intelligence exists. Infrastructure ownership does not identify a person.',
            'Geolocation describes observed sending infrastructure, not the physical location of a sender.',
            'Authentication results reflect checks performed by the receiving mail infrastructure at delivery time, except DKIM, which PhishLens re-verifies independently.',
            'Threat-intelligence feeds are point-in-time snapshots. An indicator absent from them is unknown, not established as safe.',
            'Attachments were analysed by metadata and cryptographic hash only. No attachment was opened, executed, or detonated.',
            'The raw message body is not retained; the SHA-256 recorded above is the reference to the analysed bytes.'
        ].forEach(line => this.body(doc, `  · ${line}`, COLORS.muted, 8));

        doc.moveDown(0.4);
        this.body(doc, `Chain-of-custody SHA-256: ${this.safe(threatObject.message?.raw_hash)}`, COLORS.body, 8);
        this.body(doc, `Report generated by PhishLens at ${new Date().toISOString()}.`, COLORS.muted, 8);
    }

    /** Page numbers added after layout, when the total page count is known. */
    paginate(doc, threatObject) {
        const range = doc.bufferedPageRange();
        for (let i = range.start; i < range.start + range.count; i++) {
            doc.switchToPage(i);

            // Writing inside the bottom margin makes PDFKit start a new page,
            // which would append one blank page per footer and leave the totals
            // wrong. Suspending the margin for the write keeps the footer on the
            // page it belongs to.
            const bottomMargin = doc.page.margins.bottom;
            doc.page.margins.bottom = 0;

            doc.fontSize(7).fillColor(COLORS.muted).font('Helvetica')
                .text(
                    `PhishLens forensic report · Case ${this.safe(threatObject.case_id)} · Page ${i - range.start + 1} of ${range.count}`,
                    50,
                    doc.page.height - 35,
                    { width: 495, align: 'center', lineBreak: false }
                );

            doc.page.margins.bottom = bottomMargin;
        }
    }
}

module.exports = new PDFReportGenerator();
