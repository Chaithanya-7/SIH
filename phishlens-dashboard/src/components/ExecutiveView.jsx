import React from 'react';
import { UserCheck } from 'lucide-react';

export default function ExecutiveView({ vips = [], cases = [] }) {
  return (
    <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <UserCheck size={16} color="var(--accent)" /> Executive Protection & VIP Guard Status
      </h4>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
        {vips.map((vip, idx) => {
          const targetedCases = cases.filter(c => 
            c.executive_context?.matched_vip?.email?.toLowerCase() === vip.email.toLowerCase() ||
            c.message?.recipient?.toLowerCase().includes(vip.email.toLowerCase())
          );

          const impersonatedCases = cases.filter(c => 
            c.executive_context?.is_impersonated && c.message?.sender?.toLowerCase().includes(vip.name.toLowerCase())
          );

          const hasIncidents = targetedCases.length > 0 || impersonatedCases.length > 0;

          return (
            <div
              key={idx}
              style={{
                backgroundColor: 'var(--bg-panel)',
                borderRadius: '6px',
                border: hasIncidents ? '1px solid var(--warning)' : '1px solid var(--border)',
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>{vip.name}</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{vip.title}</div>
                  </div>
                  <span style={{ backgroundColor: hasIncidents ? 'var(--tint-warning)' : 'var(--tint-success)', color: hasIncidents ? 'var(--warning)' : 'var(--success)', fontSize: '0.68rem', fontWeight: 600, padding: '2px 8px', borderRadius: '4px' }}>
                    {hasIncidents ? 'ATTACKS DETECTED' : 'PROTECTED'}
                  </span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--accent)' }}>{vip.email}</div>
              </div>

              <div style={{ borderTop: '1px solid var(--border)', marginTop: '12px', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                <span>Targeted: <strong style={{ color: 'var(--warning)' }}>{targetedCases.length}</strong></span>
                <span>Impersonated: <strong style={{ color: 'var(--danger)' }}>{impersonatedCases.length}</strong></span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
