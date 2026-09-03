const fs = require('fs');
const path = require('path');
const AuditEvent = require('../models/AuditEvent');

class AuditLogger {
    constructor() {
        this.logFile = path.join(__dirname, '../data/audit_log.json');
        this.events = [];
        this.initStorage();
    }

    initStorage() {
        try {
            const dataDir = path.dirname(this.logFile);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            if (fs.existsSync(this.logFile)) {
                const raw = fs.readFileSync(this.logFile, 'utf8');
                this.events = JSON.parse(raw || '[]');
            }
        } catch (e) {
            console.error('[AuditLogger] Storage init error:', e.message);
        }
    }

    log(eventData) {
        const auditEvent = new AuditEvent(eventData);
        console.log(`[AuditLogger] [${auditEvent.timestamp}] [${auditEvent.case_id}] ${auditEvent.event_type}: ${auditEvent.description}`);
        this.events.unshift(auditEvent);
        if (this.events.length > 500) this.events.pop();
        this.persistToDisk();
        return auditEvent;
    }

    getEventsForCase(caseId) {
        return this.events.filter(e => e.case_id === caseId);
    }

    getAllEvents() {
        return this.events;
    }

    persistToDisk() {
        try {
            fs.writeFileSync(this.logFile, JSON.stringify(this.events, null, 2), 'utf8');
        } catch (e) {
            console.error('[AuditLogger] Persistence error:', e.message);
        }
    }
}

module.exports = new AuditLogger();
