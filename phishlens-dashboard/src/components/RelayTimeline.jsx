import React, { useState } from 'react';
import { Server } from 'lucide-react';

export default function RelayTimeline({ relays = [] }) {
  const [selectedHop, setSelectedHop] = useState(null);

  if (!relays || relays.length === 0) {
    return (
      <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '16px' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>Trust-Aware SMTP Delivery Path</h4>
        <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>No SMTP relay hop data extracted for this message.</div>
      </div>
    );
  }

  return (
    <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '16px' }}>
      <h4 style={{ margin: '0 0 16px 0', fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Server size={16} color="var(--accent)" /> Trust-Aware SMTP Delivery Path ({relays.length} Hops)
      </h4>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {relays.map((hop, idx) => {
          const trustPct = Math.round(hop.trust_level * 100);
          const classification = hop.classification || 'UNVERIFIED_HEADER_HOP';
          const isSelected = selectedHop?.hop_index === idx;

          let badgeBg = 'var(--tint-neutral)';
          let badgeColor = 'var(--text-muted)';

          if (classification === 'TRUSTED_RECEIVER') {
            badgeBg = 'var(--tint-success)';
            badgeColor = 'var(--success)';
          } else if (classification === 'ORIGIN_CANDIDATE' || classification === 'PROVIDER_OUTBOUND_MTA') {
            badgeBg = 'var(--tint-accent)';
            badgeColor = 'var(--accent)';
          } else if (classification === 'EXTERNAL_RELAY') {
            badgeBg = 'var(--tint-warning)';
            badgeColor = 'var(--warning)';
          }

          return (
            <div
              key={idx}
              onClick={() => setSelectedHop(isSelected ? null : hop)}
              style={{
                backgroundColor: isSelected ? 'var(--border)' : 'var(--bg-panel)',
                borderRadius: '6px',
                border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                padding: '12px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ backgroundColor: 'var(--border)', color: 'var(--accent)', width: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem' }}>
                    {idx + 1}
                  </div>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{hop.hostname}</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      IP: <span className="font-mono">{hop.ip}</span> • {new Date(hop.timestamp).toLocaleTimeString()}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '2px' }}>{hop.trust_explanation}</div>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span style={{ backgroundColor: badgeBg, color: badgeColor, fontSize: '0.7rem', fontWeight: 600, padding: '3px 8px', borderRadius: '4px' }}>
                    {classification.replace('_', ' ')}
                  </span>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    Trust Score: {trustPct}%
                  </div>
                </div>
              </div>

              {/* Hop Detail Expansion */}
              {isSelected && (
                <div className="font-mono" style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--border)', fontSize: '0.7rem', color: 'var(--accent-soft)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
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
