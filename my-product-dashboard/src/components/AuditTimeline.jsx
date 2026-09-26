import React from 'react';
import { History, CheckCircle2 } from 'lucide-react';

export default function AuditTimeline({ events = [] }) {
  return (
    <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: '#f8fafc', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <History size={16} color="#3b82f6" /> System Provenance & Chain-of-Custody Audit Log
      </h4>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '360px', overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ color: '#64748b', fontSize: '0.75rem', fontStyle: 'italic' }}>No audit trail events logged yet.</div>
        ) : (
          events.slice().reverse().map((evt, idx) => (
            <div key={idx} style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '10px 12px', fontSize: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={14} color="#10b981" />
                <div>
                  <span className="font-mono" style={{ color: '#3b82f6', fontWeight: 600, marginRight: '8px' }}>[{evt.event_type}]</span>
                  <span style={{ color: '#f8fafc' }}>{evt.description}</span>
                </div>
              </div>
              <span className="font-mono" style={{ color: '#64748b', fontSize: '0.68rem' }}>{new Date(evt.timestamp).toLocaleTimeString()}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
