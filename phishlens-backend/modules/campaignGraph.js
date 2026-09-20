const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const GraphNode = require('../models/GraphNode');
const GraphEdge = require('../models/GraphEdge');
const ipUtils = require('../utils/ipUtils');
const correlationGuard = require('./correlationGuard');
const semanticCorrelation = require('./semanticCorrelation');
const { dataFile } = require('./dataPaths');
const crypto = require('crypto');

class CampaignGraph {
    constructor() {
        const dbPath = dataFile('knowledge_graph.sqlite');
        this.db = new sqlite3.Database(dbPath, (err) => {
            if (err) console.error('[CampaignGraph] SQLite connection error:', err.message);
            else console.log('[CampaignGraph] Connected to persistent SQLite Knowledge Graph.');
        });
        this.initTables();
    }

    initTables() {
        this.db.serialize(() => {
            // Nodes Table
            this.db.run(`CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                type TEXT,
                label TEXT,
                properties TEXT,
                first_seen TEXT,
                last_seen TEXT
            )`);

            // Edges Table
            this.db.run(`CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                source TEXT,
                target TEXT,
                relationship TEXT,
                confidence REAL,
                case_id TEXT,
                timestamp TEXT
            )`);

            // Campaigns Table
            this.db.run(`CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                status TEXT,
                first_seen TEXT,
                last_seen TEXT,
                case_ids TEXT,
                ips TEXT,
                domains TEXT,
                urls TEXT,
                targets TEXT,
                executives_targeted TEXT,
                association_confidence REAL
            )`);
        });
    }

    async processThreatObject(threatObject, parsedEmail) {
        console.log(`[CampaignGraph] Processing persistent graph & cross-case correlation for Case ${threatObject.case_id}...`);

        const caseId = threatObject.case_id;
        const sender = threatObject.message.sender || '';
        const recipient = threatObject.message.recipient || '';
        const originIp = threatObject.infrastructure?.origin_ip || threatObject.infrastructure?.origin?.origin_ip || null;
        const asn = threatObject.infrastructure?.asn !== 'UNAVAILABLE' ? threatObject.infrastructure?.asn : null;
        const iocs = threatObject.iocs || {};
        const domains = iocs.domains || [];
        const urls = iocs.urls || [];
        const hashes = iocs.hashes || [];
        const execContext = threatObject.executive_context || {};
        const isExecutiveAttack = execContext.is_targeted || execContext.is_impersonated;
        const targetedExec = execContext.targeted_executive?.name || (isExecutiveAttack ? recipient : null);

        // Extract sender domain & recipient domain
        const senderMatch = sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        const senderDomain = senderMatch ? senderMatch[1].toLowerCase() : null;

        const recipientMatch = recipient.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        const recipientDomain = recipientMatch ? recipientMatch[1].toLowerCase() : null;

        // Filter out target recipient domain from infrastructure domain correlation
        const infraDomains = domains.filter(d => d.toLowerCase() !== recipientDomain);

        const now = new Date().toISOString();

        // 1. Create / Update Case Node
        const caseNodeId = `case:${caseId}`;
        await this.upsertNode(new GraphNode({
            id: caseNodeId,
            type: 'CASE',
            label: caseId,
            properties: { subject: threatObject.message.subject, verdict: threatObject.detection.verdict },
            first_seen: threatObject.timestamps?.ingested_at || now,
            last_seen: now
        }));

        // 2. Create Sender Node & Link
        if (sender) {
            const senderNodeId = `sender:${sender.toLowerCase()}`;
            await this.upsertNode(new GraphNode({ id: senderNodeId, type: 'SENDER', label: sender, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: senderNodeId, relationship: 'SENT_BY', case_id: caseId, timestamp: now }));
        }

        // 3. Create Recipient Node & Link
        if (recipient) {
            const recipNodeId = `recipient:${recipient.toLowerCase()}`;
            await this.upsertNode(new GraphNode({ id: recipNodeId, type: 'RECIPIENT', label: recipient, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: recipNodeId, relationship: 'SENT_TO', case_id: caseId, timestamp: now }));
        }

        // 4. Create Executive Node & Link (Only for verified executive attacks)
        if (targetedExec && isExecutiveAttack) {
            const execNodeId = `executive:${targetedExec.toLowerCase()}`;
            await this.upsertNode(new GraphNode({ id: execNodeId, type: 'EXECUTIVE', label: targetedExec, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: execNodeId, relationship: 'TARGETS', case_id: caseId, timestamp: now }));
        }

        // 5. Create Origin IP Node & Link (Only routable public IPs)
        const isRoutableIp = originIp && !ipUtils.isNonPublicIP(originIp);
        if (isRoutableIp) {
            const ipNodeId = `ip:${originIp}`;
            await this.upsertNode(new GraphNode({ id: ipNodeId, type: 'IP', label: originIp, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: ipNodeId, relationship: 'HOSTED_ON', case_id: caseId, timestamp: now }));
        }

        // 6. Create ASN Node & Link
        if (asn) {
            const asnNodeId = `asn:${asn}`;
            await this.upsertNode(new GraphNode({ id: asnNodeId, type: 'ASN', label: asn, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: asnNodeId, relationship: 'SHARES_INFRASTRUCTURE', case_id: caseId, timestamp: now }));
        }

        // 7. Create Infrastructure Domain Nodes & Links
        for (const dom of infraDomains) {
            const domNodeId = `domain:${dom.toLowerCase()}`;
            await this.upsertNode(new GraphNode({ id: domNodeId, type: 'DOMAIN', label: dom, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: domNodeId, relationship: 'RESOLVES_TO', case_id: caseId, timestamp: now }));
        }

        // 8. Create URL Nodes & Links
        for (const u of urls) {
            const urlNodeId = `url:${u}`;
            await this.upsertNode(new GraphNode({ id: urlNodeId, type: 'URL', label: u, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: urlNodeId, relationship: 'CONTAINS', case_id: caseId, timestamp: now }));
        }

        // 9. Create Payload Hash Nodes & Links
        for (const h of hashes) {
            const hashNodeId = `hash:${h}`;
            await this.upsertNode(new GraphNode({ id: hashNodeId, type: 'HASH', label: h, first_seen: now, last_seen: now }));
            await this.addEdge(new GraphEdge({ source: caseNodeId, target: hashNodeId, relationship: 'CONTAINS', case_id: caseId, timestamp: now }));
        }

        // ==================== CROSS-CASE AUTOMATIC CORRELATION ====================
        const correlationFactors = [];
        /** Links that were deliberately not made, kept so the absence is explainable. */
        const suppressedFactors = [];
        const relatedCaseSet = new Set();

        // A. Shared Payload Hash (Weight: +0.30 - Very Strong Evidence)
        for (const h of hashes) {
            const sharedCases = await this.findCasesSharingNode(`hash:${h}`, caseId);
            if (sharedCases.length > 0) {
                sharedCases.forEach(c => relatedCaseSet.add(c));
                correlationFactors.push({
                    factor: 'EXACT_HASH_MATCH',
                    status: 'SUPPORTED',
                    weight: 0.30,
                    evidence: `Attachment SHA-256 payload hash (${h.substring(0, 12)}...) matches cases: ${sharedCases.join(', ')}`
                });
            }
        }

        // B. Shared Public Routable IP (Weight: +0.25 - Strong Evidence)
        if (isRoutableIp) {
            const sharedIpCases = await this.findCasesSharingNode(`ip:${originIp}`, caseId);
            if (sharedIpCases.length > 0) {
                const verdict = correlationGuard.evaluateIndicator({
                    type: 'IP', value: originIp, sharedCaseCount: sharedIpCases.length, threatObject
                });
                if (verdict.allowed) {
                    sharedIpCases.forEach(c => relatedCaseSet.add(c));
                    correlationFactors.push({
                        factor: 'SHARED_IP',
                        status: 'SUPPORTED',
                        weight: 0.25,
                        evidence: `Probable origin IP ${originIp} appears in cases: ${sharedIpCases.join(', ')}`
                    });
                } else {
                    suppressedFactors.push({ factor: 'SHARED_IP', indicator: originIp, reason: verdict.reason });
                }
            }
        }

        // C. Shared Domain Infrastructure (Weight: +0.25 - Strong Evidence)
        for (const dom of infraDomains) {
            const sharedDomCases = await this.findCasesSharingNode(`domain:${dom.toLowerCase()}`, caseId);
            if (sharedDomCases.length > 0) {
                const verdict = correlationGuard.evaluateIndicator({
                    type: 'DOMAIN', value: dom, sharedCaseCount: sharedDomCases.length, threatObject
                });
                if (verdict.allowed) {
                    sharedDomCases.forEach(c => relatedCaseSet.add(c));
                    correlationFactors.push({
                        factor: 'SHARED_DOMAIN_INFRASTRUCTURE',
                        status: 'SUPPORTED',
                        weight: 0.25,
                        evidence: `Domain ${dom} is shared with cases: ${sharedDomCases.join(', ')}`
                    });
                } else {
                    suppressedFactors.push({ factor: 'SHARED_DOMAIN_INFRASTRUCTURE', indicator: dom, reason: verdict.reason });
                }
            }
        }

        // D. Shared Phishing URL (Weight: +0.25 - Strong Evidence)
        for (const u of urls) {
            const sharedUrlCases = await this.findCasesSharingNode(`url:${u}`, caseId);
            if (sharedUrlCases.length > 0) {
                sharedUrlCases.forEach(c => relatedCaseSet.add(c));
                correlationFactors.push({
                    factor: 'SHARED_URL',
                    status: 'SUPPORTED',
                    weight: 0.25,
                    evidence: `Identical URL (${u}) detected in cases: ${sharedUrlCases.join(', ')}`
                });
            }
        }

        // E. Shared Sender Address (Weight: +0.20 - Medium Evidence)
        if (sender) {
            const sharedSenderCases = await this.findCasesSharingNode(`sender:${sender.toLowerCase()}`, caseId);
            if (sharedSenderCases.length > 0) {
                sharedSenderCases.forEach(c => relatedCaseSet.add(c));
                correlationFactors.push({
                    factor: 'SHARED_SENDER_ADDRESS',
                    status: 'SUPPORTED',
                    weight: 0.20,
                    evidence: `Sender address ${sender} observed in cases: ${sharedSenderCases.join(', ')}`
                });
            }
        }

        // F. Shared Executive VIP Target (Weight: +0.15 - Supporting Evidence)
        if (targetedExec && isExecutiveAttack) {
            const sharedExecCases = await this.findCasesSharingNode(`executive:${targetedExec.toLowerCase()}`, caseId);
            if (sharedExecCases.length > 0) {
                sharedExecCases.forEach(c => relatedCaseSet.add(c));
                correlationFactors.push({
                    factor: 'SHARED_EXECUTIVE_TARGET',
                    status: 'SUPPORTED',
                    weight: 0.15,
                    evidence: `Targeted VIP executive (${targetedExec}) also targeted in cases: ${sharedExecCases.join(', ')}`
                });
            }
        }

        // G. Shared ASN Provider (Weight: +0.05 - Weak Supporting Evidence)
        if (asn && relatedCaseSet.size > 0) {
            const sharedAsnCases = await this.findCasesSharingNode(`asn:${asn}`, caseId);
            if (sharedAsnCases.length > 0) {
                const verdict = correlationGuard.evaluateIndicator({
                    type: 'ASN', value: asn, sharedCaseCount: sharedAsnCases.length, threatObject
                });
                if (verdict.allowed) {
                    correlationFactors.push({
                        factor: 'SHARED_ASN_PROVIDER',
                        status: 'SUPPORTED',
                        weight: 0.05,
                        evidence: `ASN ${asn} shared across correlated threat cluster`
                    });
                } else {
                    suppressedFactors.push({ factor: 'SHARED_ASN_PROVIDER', indicator: asn, reason: verdict.reason });
                }
            }
        }

        // H. Shared wording. Catches a campaign that rotates its senders, domains
        //    and hosts between sends but reuses the lure it wrote once.
        const semantic = semanticCorrelation.findSimilarCases(threatObject, parsedEmail);

        // Every related case is recorded as an id, but only the strongest few
        // become factors. In a mass campaign a message can resemble hundreds of
        // others, and writing one factor and one evidence item for each grows
        // storage with the square of the campaign size while adding nothing to
        // the score, since only the strongest in a family is counted in full.
        const SEMANTIC_FACTOR_LIMIT = 5;
        semantic.matches.forEach(match => relatedCaseSet.add(match.case_id));

        semantic.matches.slice(0, SEMANTIC_FACTOR_LIMIT).forEach(match => {
            correlationFactors.push({
                factor: 'SEMANTIC_SIMILARITY',
                status: 'SUPPORTED',
                // Near-identical wording is far more specific than partial
                // overlap, which ordinary business correspondence produces.
                weight: match.similarity >= 0.9 ? 0.30 : match.similarity >= 0.8 ? 0.25 : 0.15,
                evidence: `Message wording is ${Math.round(match.similarity * 100)}% similar to case ${match.case_id} (shared terms: ${match.shared_terms.join(', ')})`
            });
        });

        const undisclosedSimilar = Math.max(0, semantic.matches.length - SEMANTIC_FACTOR_LIMIT);

        // Grouped rather than summed: one attacker host seen as an IP, a domain
        // and a URL is a single observation, not three independent proofs.
        const scored = correlationGuard.scoreFactors(correlationFactors);
        const finalConfidence = scored.confidence;
        const relatedCases = Array.from(relatedCaseSet);

        let campaignStatus = 'UNASSOCIATED';
        if (finalConfidence >= 0.70) campaignStatus = 'HIGHLY_LIKELY_ASSOCIATED';
        else if (finalConfidence >= 0.40) campaignStatus = 'LIKELY_ASSOCIATED';
        else if (finalConfidence > 0) campaignStatus = 'POSSIBLY_ASSOCIATED';

        // Structure Campaign Correlation Object on threatObject
        threatObject.campaign_association = {
            confidence: finalConfidence,
            status: campaignStatus,
            related_cases: relatedCases,
            factors: correlationFactors,
            scoring: scored.breakdown,
            // Shown rather than hidden: an analyst asking why two obviously
            // similar cases were not linked deserves the reason.
            suppressed_factors: suppressedFactors,
            semantic_matches: semantic.matches.slice(0, 5),
            additional_similar_cases: undisclosedSimilar,
            limitation: 'Shared infrastructure supports campaign association but does not establish actor identity. Indicators shared by unrelated parties, such as consumer mail providers and multi-tenant hosting, are deliberately excluded from correlation.'
        };

        threatObject.confidence.campaign_association = finalConfidence;

        // Mandatory Directive: Actor attribution MUST remain INSUFFICIENT EVIDENCE unless independent attribution intelligence exists!
        threatObject.confidence.actor_attribution = 'INSUFFICIENT EVIDENCE';

        // ==================== PERSISTENT CAMPAIGN MANAGER ====================
        if (relatedCases.length > 0) {
            const existingCampaign = await this.findExistingCampaignForCases([caseId, ...relatedCases]);
            let campaignRecord = null;

            if (existingCampaign) {
                // Update existing persistent campaign
                campaignRecord = await this.updateCampaign(existingCampaign.campaign_id, {
                    case_id: caseId,
                    origin_ip: isRoutableIp ? originIp : null,
                    domains: infraDomains,
                    urls,
                    target: recipient,
                    executive: isExecutiveAttack ? targetedExec : null,
                    confidence: Math.max(existingCampaign.association_confidence, finalConfidence)
                });
            } else {
                // Create new persistent campaign
                campaignRecord = await this.createCampaign({
                    case_ids: [caseId, ...relatedCases],
                    ips: isRoutableIp ? [originIp] : [],
                    domains: infraDomains,
                    urls,
                    targets: recipient ? [recipient] : [],
                    executives_targeted: isExecutiveAttack && targetedExec ? [targetedExec] : [],
                    association_confidence: finalConfidence
                }).catch(e => {
                    console.error(`[CampaignGraph] Campaign creation failed for case ${caseId}: ${e.message}`);
                    return null;
                });
            }

            // updateCampaign resolves null when its row has gone or the query
            // errored, and the next line dereferences campaignRecord - so a
            // storage problem in an enrichment step used to take the whole
            // detection down with it. The verdict, the evidence and the
            // remediation decision are all still valid without a campaign
            // association, so the message stays protected and the absence is
            // recorded rather than thrown.
            if (!campaignRecord) {
                threatObject.campaign = null;
                threatObject.campaign_association = {
                    ...(threatObject.campaign_association || {}),
                    status: 'UNAVAILABLE',
                    reason: 'Related cases were found, but the campaign record could not be stored or read. The detection result is unaffected; only the campaign link is missing.'
                };
                return threatObject;
            }

            threatObject.campaign = campaignRecord;

            // Link Case to Campaign Node in Knowledge Graph
            const campaignNodeId = `campaign:${campaignRecord.campaign_id}`;
            await this.upsertNode(new GraphNode({
                id: campaignNodeId,
                type: 'CAMPAIGN',
                label: campaignRecord.campaign_id,
                properties: { status: campaignRecord.status, confidence: campaignRecord.association_confidence },
                first_seen: campaignRecord.first_seen,
                last_seen: campaignRecord.last_seen
            }));

            await this.addEdge(new GraphEdge({
                source: caseNodeId,
                target: campaignNodeId,
                relationship: 'PART_OF_CAMPAIGN',
                confidence: finalConfidence,
                case_id: caseId,
                timestamp: now
            }));
        }

        return threatObject;
    }

    upsertNode(node) {
        return new Promise((resolve) => {
            const propsStr = JSON.stringify(node.properties || {});
            this.db.run(
                `INSERT INTO nodes (id, type, label, properties, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET last_seen = ?`,
                [node.id, node.type, node.label, propsStr, node.first_seen, node.last_seen, node.last_seen],
                () => resolve()
            );
        });
    }

    addEdge(edge) {
        return new Promise((resolve) => {
            const edgeId = `${edge.source}->${edge.target}:${edge.relationship}`;
            this.db.run(
                `INSERT OR IGNORE INTO edges (id, source, target, relationship, confidence, case_id, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [edgeId, edge.source, edge.target, edge.relationship, edge.confidence, edge.case_id, edge.timestamp],
                () => resolve()
            );
        });
    }

    findCasesSharingNode(nodeId, currentCaseId) {
        return new Promise((resolve) => {
            this.db.all(
                `SELECT DISTINCT case_id FROM edges WHERE (target = ? OR source = ?) AND case_id != ?`,
                [nodeId, nodeId, currentCaseId],
                (err, rows) => {
                    if (err || !rows) return resolve([]);
                    resolve(rows.map(r => r.case_id).filter(Boolean));
                }
            );
        });
    }

    findExistingCampaignForCases(caseIds) {
        return new Promise((resolve) => {
            this.db.all(`SELECT * FROM campaigns`, (err, rows) => {
                if (err || !rows) return resolve(null);
                for (const row of rows) {
                    let existingCaseIds = [];
                    try { existingCaseIds = JSON.parse(row.case_ids || '[]'); } catch (e) {}
                    if (caseIds.some(id => existingCaseIds.includes(id))) {
                        return resolve({
                            ...row,
                            case_ids: existingCaseIds,
                            ips: JSON.parse(row.ips || '[]'),
                            domains: JSON.parse(row.domains || '[]'),
                            urls: JSON.parse(row.urls || '[]'),
                            targets: JSON.parse(row.targets || '[]'),
                            executives_targeted: JSON.parse(row.executives_targeted || '[]')
                        });
                    }
                }
                resolve(null);
            });
        });
    }

    /**
     * A campaign identifier has to be unique or the graph merges unrelated
     * attacks.
     *
     * The previous form drew from 900 possible values, which gives roughly an
     * even chance of a collision by the thirty-fifth campaign and near-certainty
     * by the hundredth. campaign_id is the table's PRIMARY KEY, so a collision
     * fails the INSERT - and the callback below discarded its error, resolving
     * as though the write had succeeded. The case would then be filed under a
     * campaign belonging to somebody else's attack, and every later update
     * would pour its indicators into that one.
     */
    createCampaign(data) {
        return new Promise((resolve, reject) => {
            const campaignId = `CMP-${new Date().getFullYear()}-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
            const now = new Date().toISOString();

            const campaign = {
                campaign_id: campaignId,
                status: 'ACTIVE',
                first_seen: now,
                last_seen: now,
                case_ids: data.case_ids || [],
                ips: data.ips || [],
                domains: data.domains || [],
                urls: data.urls || [],
                targets: data.targets || [],
                executives_targeted: data.executives_targeted || [],
                association_confidence: data.association_confidence || 0.50
            };

            this.db.run(
                `INSERT INTO campaigns (campaign_id, status, first_seen, last_seen, case_ids, ips, domains, urls, targets, executives_targeted, association_confidence)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    campaign.campaign_id,
                    campaign.status,
                    campaign.first_seen,
                    campaign.last_seen,
                    JSON.stringify(campaign.case_ids),
                    JSON.stringify(campaign.ips),
                    JSON.stringify(campaign.domains),
                    JSON.stringify(campaign.urls),
                    JSON.stringify(campaign.targets),
                    JSON.stringify(campaign.executives_targeted),
                    campaign.association_confidence
                ],
                (err) => {
                    if (err) {
                        // Reported rather than swallowed. A campaign that was
                        // not stored must not be returned as though it had been.
                        console.error(`[CampaignGraph] Could not store campaign ${campaignId}: ${err.message}`);
                        return reject(new Error(`Campaign ${campaignId} could not be stored: ${err.message}`));
                    }
                    resolve(campaign);
                }
            );
        });
    }

    updateCampaign(campaignId, newData) {
        return new Promise((resolve) => {
            this.db.get(`SELECT * FROM campaigns WHERE campaign_id = ?`, [campaignId], (err, row) => {
                if (err || !row) return resolve(null);

                const now = new Date().toISOString();
                const caseIds = Array.from(new Set([...JSON.parse(row.case_ids || '[]'), newData.case_id]));
                const ips = Array.from(new Set([...JSON.parse(row.ips || '[]'), ...(newData.origin_ip ? [newData.origin_ip] : [])]));
                const domains = Array.from(new Set([...JSON.parse(row.domains || '[]'), ...(newData.domains || [])]));
                const urls = Array.from(new Set([...JSON.parse(row.urls || '[]'), ...(newData.urls || [])]));
                const targets = Array.from(new Set([...JSON.parse(row.targets || '[]'), ...(newData.target ? [newData.target] : [])]));
                const execs = Array.from(new Set([...JSON.parse(row.executives_targeted || '[]'), ...(newData.executive ? [newData.executive] : [])]));
                const maxConf = Math.max(parseFloat(row.association_confidence || 0), newData.confidence || 0);

                this.db.run(
                    `UPDATE campaigns SET last_seen = ?, case_ids = ?, ips = ?, domains = ?, urls = ?, targets = ?, executives_targeted = ?, association_confidence = ? WHERE campaign_id = ?`,
                    [now, JSON.stringify(caseIds), JSON.stringify(ips), JSON.stringify(domains), JSON.stringify(urls), JSON.stringify(targets), JSON.stringify(execs), maxConf, campaignId],
                    () => resolve({
                        campaign_id: campaignId,
                        status: row.status,
                        first_seen: row.first_seen,
                        last_seen: now,
                        case_ids: caseIds,
                        ips,
                        domains,
                        urls,
                        targets,
                        executives_targeted: execs,
                        association_confidence: maxConf
                    })
                );
            });
        });
    }

    getGraphData() {
        return new Promise((resolve) => {
            this.db.all(`SELECT * FROM nodes LIMIT 200`, (err, nodes) => {
                this.db.all(`SELECT * FROM edges LIMIT 200`, (err2, edges) => {
                    resolve({ nodes: nodes || [], edges: edges || [] });
                });
            });
        });
    }
}

module.exports = new CampaignGraph();
