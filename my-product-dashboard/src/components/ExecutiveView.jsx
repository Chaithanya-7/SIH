import React from 'react';
import { UserCheck } from 'lucide-react';

export default function ExecutiveView({ vips = [], cases = [] }) {
  return (
    <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: '#f8fafc', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <UserCheck size={16} color="#3b82f6" /> Executive Protection & VIP Guard Status
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
                backgroundColor: '#0d1322',
                borderRadius: '6px',
                border: hasIncidents ? '1px solid #f59e0b' : '1px solid #1e293b',
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#f8fafc' }}>{vip.name}</div>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>{vip.title}</div>
                  </div>
                  <span style={{ backgroundColor: hasIncidents ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)', color: hasIncidents ? '#f59e0b' : '#10b981', fontSize: '0.68rem', fontWeight: 600, padding: '2px 8px', borderRadius: '4px' }}>
                    {hasIncidents ? 'ATTACKS DETECTED' : 'PROTECTED'}
                  </span>
                </div>
                <div style={{ fontSize: '0.72rem', color: '#3b82f6' }}>{vip.email}</div>
              </div>

              <div style={{ borderTop: '1px solid #1e293b', marginTop: '12px', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#94a3b8' }}>
                <span>Targeted: <strong style={{ color: '#f59e0b' }}>{targetedCases.length}</strong></span>
                <span>Impersonated: <strong style={{ color: '#ef4444' }}>{impersonatedCases.length}</strong></span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
