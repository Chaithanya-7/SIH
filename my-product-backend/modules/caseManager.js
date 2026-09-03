const fs = require('fs');
const path = require('path');
const executiveGuard = require('./executiveGuard');
const policyEngine = require('./policyEngine');

class CaseManager {
    constructor() {
        this.cases = new Map();
        this.storageFile = path.join(__dirname, '../data/cases.json');
        this.initStorage();
    }

    initStorage() {
        try {
            const dataDir = path.dirname(this.storageFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            if (fs.existsSync(this.storageFile)) {
                const raw = fs.readFileSync(this.storageFile, 'utf8');
                const list = JSON.parse(raw || '[]');
                
                list.forEach(c => {
                    // Enrich with P1 Executive Guard if missing
                    if (!c.executive_context) {
                        try {
                            executiveGuard.evaluateTarget(c);
                        } catch (err) {
                            c.executive_context = { is_targeted: false, is_impersonated: false, matched_vip: null };
                        }
                    }

                    // Enrich with P1 Policy & Remediation Status if PENDING or missing
                    if (!c.remediation || c.remediation.status === 'PENDING') {
                        try {
                            const policyDecision = policyEngine.evaluate(c);
                            if (policyDecision.actions.includes('QUARANTINE')) {
                                c.remediation = c.remediation || {};
                                c.remediation.status = 'QUARANTINED';
                                c.remediation.policy_matched = policyDecision.policy_id;
                                c.remediation.executed_actions = [
                                    { action: 'QUARANTINE', timestamp: c.timestamps?.ingested_at || new Date().toISOString(), status: 'EXECUTED' }
                                ];
                            }
                        } catch (err) {
                            // Keep existing
                        }
                    }

                    this.cases.set(c.case_id, c);
                });
                console.log(`[CaseManager] Loaded and enriched ${this.cases.size} persistent case(s) from disk.`);
                this.persistToDisk();
            }
        } catch (e) {
            console.error('[CaseManager] Error initializing storage:', e.message);
        }
    }

    saveCase(threatObject) {
        console.log(`[CaseManager] Saving case ${threatObject.case_id} to persistent store...`);
        this.cases.set(threatObject.case_id, threatObject);
        this.persistToDisk();
        return threatObject;
    }

    getCase(caseId) {
        return this.cases.get(caseId) || null;
    }

    getAllCases() {
        return Array.from(this.cases.values());
    }

    persistToDisk() {
        try {
            const list = Array.from(this.cases.values());
            fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
        } catch (e) {
            console.error('[CaseManager] Error persisting cases to disk:', e.message);
        }
    }
}

module.exports = new CaseManager();

