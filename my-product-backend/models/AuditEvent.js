class AuditEvent {
    constructor(data = {}) {
        this.event_id = data.event_id || `AUD-${Math.floor(10000 + Math.random() * 90000)}`;
        this.case_id = data.case_id || 'GENERAL';
        this.event_type = data.event_type || 'SYSTEM_EVENT';
        this.source = data.source || 'SECUREMAIL_ENGINE';
        this.description = data.description || '';
        this.confidence = data.confidence !== undefined ? data.confidence : 1.0;
        this.previous_state = data.previous_state || null;
        this.resulting_state = data.resulting_state || null;
        this.timestamp = data.timestamp || new Date().toISOString();
    }
}

module.exports = AuditEvent;
