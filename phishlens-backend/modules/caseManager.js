const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
                    // Preserving loaded case data without mutating historical remediation states
                    if (!c.executive_context) {
                        c.executive_context = { is_targeted: false, is_impersonated: false, matched_vip: null };
                    }
                    this.cases.set(c.case_id, c);
                });
                console.log(`[CaseManager] Loaded ${this.cases.size} persistent case(s) from disk without mutating historical states.`);
            }
        } catch (e) {
            console.error('[CaseManager] Error initializing storage:', e.message);
        }
    }

    generateUniqueCaseId() {
        const year = new Date().getFullYear();
        let caseId = '';
        let attempts = 0;
        do {
            const suffix = crypto.randomBytes(3).toString('hex').toUpperCase();
            caseId = `SM-${year}-${suffix}`;
            attempts++;
        } while (this.cases.has(caseId) && attempts < 100);
        return caseId;
    }

    saveCase(threatObject) {
        if (!threatObject.case_id || (this.cases.has(threatObject.case_id) && this.cases.get(threatObject.case_id).message?.raw_hash !== threatObject.message?.raw_hash)) {
            const newCaseId = this.generateUniqueCaseId();
            console.log(`[CaseManager] Assigning collision-safe Case ID: ${newCaseId} (previous: ${threatObject.case_id || 'NONE'})`);
            threatObject.case_id = newCaseId;
        }

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
            const tmpFile = `${this.storageFile}.tmp`;
            fs.writeFileSync(tmpFile, JSON.stringify(list, null, 2), 'utf8');
            try {
                fs.renameSync(tmpFile, this.storageFile);
            } catch (renameErr) {
                fs.writeFileSync(this.storageFile, JSON.stringify(list, null, 2), 'utf8');
                if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
            }
        } catch (e) {
            console.error('[CaseManager] Error persisting cases to disk:', e.message);
        }
    }
}

module.exports = new CaseManager();

