import React from 'react';
import { History, CheckCircle2 } from 'lucide-react';

export default function AuditTimeline({ events = [] }) {
  return (
    <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <History size={16} color="var(--accent)" /> System Provenance & Chain-of-Custody Audit Log
      </h4>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '360px', overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', fontSize: '0.75rem', fontStyle: 'italic' }}>No audit trail events logged yet.</div>
        ) : (
          events.slice().reverse().map((evt, idx) => (
            <div key={idx} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px', fontSize: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={14} color="var(--success)" />
                <div>
                  <span className="font-mono" style={{ color: 'var(--accent)', fontWeight: 600, marginRight: '8px' }}>[{evt.event_type}]</span>
                  <span style={{ color: 'var(--text-primary)' }}>{evt.description}</span>
                </div>
              </div>
              <span className="font-mono" style={{ color: 'var(--text-dim)', fontSize: '0.68rem' }}>{new Date(evt.timestamp).toLocaleTimeString()}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
