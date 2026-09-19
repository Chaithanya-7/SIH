class EvidenceObject {
    constructor(data = {}) {
        this.id = data.id || `EV-${Math.floor(10000 + Math.random() * 90000)}`;
        this.evidence_type = data.evidence_type || 'GENERAL_SIGNAL';
        this.source = data.source || 'PHISHLENS_ENGINE';
        this.finding = data.finding || '';
        this.severity = data.severity || 'MEDIUM'; // CRITICAL, HIGH, MEDIUM, LOW
        this.confidence = data.confidence !== undefined ? data.confidence : 0.5;
        this.timestamp = data.timestamp || new Date().toISOString();
        this.related_ioc = data.related_ioc || null;
        this.explanation = data.explanation || '';
        this.provenance = {
            source_type: data.provenance?.source_type || 'SYSTEM',
            source_reference: data.provenance?.source_reference || 'UNKNOWN'
        };
    }
}

module.exports = EvidenceObject;
