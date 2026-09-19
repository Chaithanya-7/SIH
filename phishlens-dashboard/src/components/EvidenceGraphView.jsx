import React, { useState } from 'react';
import { GitCommit, Network, Shield, User, Globe, AlertOctagon, Cpu, Hash, Layers } from 'lucide-react';

export default function EvidenceGraphView({ graphData, currentCaseId }) {
  const [selectedNode, setSelectedNode] = useState(null);

  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];

  return (
    <div style={{ backgroundColor: '#1a1a2e', borderRadius: '12px', border: '1px solid #2a2a4a', padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h4 style={{ margin: 0, fontSize: '1rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Network size={18} color="#8b5cf6" /> Persistent Campaign Knowledge Graph ({nodes.length} Nodes, {edges.length} Edges)
        </h4>
        <span style={{ fontSize: '0.75rem', color: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.15)', padding: '2px 8px', borderRadius: '4px', fontWeight: 'bold' }}>
          SQLite Persistence Active
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '16px' }}>
        {/* Interactive Visual Graph Canvas Area */}
        <div style={{ backgroundColor: '#0a0a0f', borderRadius: '8px', border: '1px solid #2a2a4a', height: '340px', padding: '16px', overflowY: 'auto', display: 'flex', flexWrap: 'wrap', gap: '10px', alignContent: 'flex-start' }}>
          {nodes.length === 0 ? (
            <div style={{ color: '#888', margin: 'auto', fontSize: '0.85rem' }}>No graph correlation nodes indexed yet.</div>
          ) : (
            nodes.map(node => {
              const isSelected = selectedNode?.id === node.id;
              const isCaseRelated = node.id.includes(currentCaseId || 'N/A');

              let nodeBg = '#1f1f38';
              let nodeColor = '#a0a0b0';
              if (node.type === 'CAMPAIGN') { nodeBg = '#8b5cf6'; nodeColor = '#fff'; }
              else if (node.type === 'CASE') { nodeBg = '#667eea'; nodeColor = '#fff'; }
              else if (node.type === 'EXECUTIVE') { nodeBg = '#ec4899'; nodeColor = '#fff'; }
              else if (node.type === 'SENDER') { nodeBg = '#3b82f6'; nodeColor = '#fff'; }
              else if (node.type === 'IP') { nodeBg = '#ef4444'; nodeColor = '#fff'; }
              else if (node.type === 'DOMAIN') { nodeBg = '#f59e0b'; nodeColor = '#fff'; }
              else if (node.type === 'URL') { nodeBg = '#10b981'; nodeColor = '#fff'; }
              else if (node.type === 'HASH') { nodeBg = '#6366f1'; nodeColor = '#fff'; }

              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  style={{
                    backgroundColor: isSelected ? '#ec4899' : nodeBg,
                    color: nodeColor,
                    border: isCaseRelated ? '2px solid #10b981' : '1px solid #2a2a4a',
                    borderRadius: '20px',
                    padding: '6px 14px',
                    fontSize: '0.75rem',
                    fontWeight: 'bold',
                    cursor: 'pointer',
                    boxShadow: isCaseRelated ? '0 0 10px rgba(16, 185, 129, 0.5)' : 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <GitCommit size={14} />
                  <span>{node.type}: {node.label}</span>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Node Inspector Panel */}
        <div style={{ backgroundColor: '#0a0a0f', borderRadius: '8px', border: '1px solid #2a2a4a', padding: '14px', fontSize: '0.8rem' }}>
          <h5 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Layers size={16} color="#8b5cf6" /> Graph Node Inspector
          </h5>
          {selectedNode ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', color: '#ccc' }}>
              <div><strong>Node ID:</strong> <span style={{ color: '#8b5cf6', wordBreak: 'break-all' }}>{selectedNode.id}</span></div>
              <div><strong>Node Type:</strong> <span style={{ color: '#fff', fontWeight: 'bold' }}>{selectedNode.type}</span></div>
              <div><strong>Label / Value:</strong> <span style={{ color: '#93c5fd' }}>{selectedNode.label}</span></div>
              <div><strong>First Seen:</strong> {new Date(selectedNode.first_seen).toLocaleString()}</div>
              <div><strong>Last Seen:</strong> {new Date(selectedNode.last_seen).toLocaleString()}</div>
              
              {/* Linked Relationships */}
              <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid #1f1f38' }}>
                <strong style={{ color: '#aaa' }}>Linked Edges ({edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).length}):</strong>
                <div style={{ fontSize: '0.7rem', color: '#888', marginTop: '4px', maxHeight: '120px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).map(e => (
                    <div key={e.id} style={{ backgroundColor: '#141424', padding: '4px 8px', borderRadius: '4px' }}>
                      {e.source === selectedNode.id ? `→ [${e.relationship}] ${e.target}` : `← [${e.relationship}] ${e.source}`}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ color: '#777', fontSize: '0.75rem' }}>Click any node in the Knowledge Graph to inspect relationships, evidence sources, and cross-case provenance.</div>
          )}
        </div>
      </div>
    </div>
  );
}
