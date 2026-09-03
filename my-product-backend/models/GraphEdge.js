class GraphEdge {
    constructor(data = {}) {
        this.id = data.id || `edge-${Math.floor(10000 + Math.random() * 90000)}`;
        this.source = data.source;
        this.target = data.target;
        this.relationship = data.relationship || 'RELATED_TO';
        this.confidence = data.confidence !== undefined ? data.confidence : 0.8;
        this.case_id = data.case_id || null;
        this.timestamp = data.timestamp || new Date().toISOString();
    }
}

module.exports = GraphEdge;
