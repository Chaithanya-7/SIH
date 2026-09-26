class GraphNode {
    constructor(data = {}) {
        this.id = data.id || `node-${Math.floor(10000 + Math.random() * 90000)}`;
        this.type = data.type || 'UNKNOWN'; // EMAIL, SENDER, DOMAIN, IP, URL, CASE, CAMPAIGN, EXECUTIVE
        this.label = data.label || '';
        this.properties = data.properties || {};
        this.first_seen = data.first_seen || new Date().toISOString();
        this.last_seen = data.last_seen || new Date().toISOString();
    }
}

module.exports = GraphNode;
