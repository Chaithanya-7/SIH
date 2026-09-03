import React, { useState } from 'react';
import { Server } from 'lucide-react';

export default function RelayTimeline({ relays = [] }) {
  const [selectedHop, setSelectedHop] = useState(null);

  if (!relays || relays.length === 0) {
    return (
      <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '16px' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600 }}>Trust-Aware SMTP Delivery Path</h4>
        <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>No SMTP relay hop data extracted for this message.</div>
      </div>
    );
  }

  return (
    <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: '#f8fafc', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Server size={16} color="#3b82f6" /> Trust-Aware SMTP Delivery Path ({relays.length} Hops)
      </h4>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {relays.map((hop, idx) => {
          const trustPct = Math.round(hop.trust_level * 100);
          const classification = hop.classification || 'UNVERIFIED_HEADER_HOP';
          const isSelected = selectedHop?.hop_index === idx;

          let badgeBg = 'rgba(100, 116, 139, 0.15)';
          let badgeColor = '#94a3b8';

          if (classification === 'TRUSTED_RECEIVER') {
            badgeBg = 'rgba(16, 185, 129, 0.15)';
            badgeColor = '#10b981';
          } else if (classification === 'ORIGIN_CANDIDATE' || classification === 'PROVIDER_OUTBOUND_MTA') {
            badgeBg = 'rgba(59, 130, 246, 0.15)';
            badgeColor = '#3b82f6';
          } else if (classification === 'EXTERNAL_RELAY') {
            badgeBg = 'rgba(245, 158, 11, 0.15)';
            badgeColor = '#f59e0b';
          }

          return (
            <div
              key={idx}
              onClick={() => setSelectedHop(isSelected ? null : hop)}
              style={{
                backgroundColor: isSelected ? '#1e293b' : '#0d1322',
                borderRadius: '6px',
                border: isSelected ? '1px solid #3b82f6' : '1px solid #1e293b',
                padding: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ backgroundColor: '#1e293b', color: '#3b82f6', width: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem' }}>
                    {idx + 1}
                  </div>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f8fafc' }}>{hop.hostname}</div>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                      IP: <span className="font-mono">{hop.ip}</span> • {new Date(hop.timestamp).toLocaleTimeString()}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '2px' }}>{hop.trust_explanation}</div>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span style={{ backgroundColor: badgeBg, color: badgeColor, fontSize: '0.7rem', fontWeight: 600, padding: '3px 8px', borderRadius: '4px' }}>
                    {classification.replace('_', ' ')}
                  </span>
                  <div style={{ fontSize: '0.68rem', color: '#64748b', marginTop: '4px' }}>
                    Trust Score: {trustPct}%
                  </div>
                </div>
              </div>

              {/* Hop Detail Expansion */}
              {isSelected && (
                <div className="font-mono" style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid #1e293b', fontSize: '0.7rem', color: '#93c5fd', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>Public Routable IP: {hop.is_public ? 'YES' : 'NO (Private/Internal)'}</div>
                  <div>Authentication at Hop: {hop.auth_results ? JSON.stringify(hop.auth_results) : 'None'}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
