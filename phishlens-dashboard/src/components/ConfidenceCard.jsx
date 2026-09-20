import React from 'react';
import { Gauge } from 'lucide-react';

export default function ConfidenceCard({ confidence, executiveContext }) {
  const threatPct = Math.round((confidence?.threat || 0) * 100);
  const infraPct = Math.round((confidence?.infrastructure_origin || 0) * 100);
  const campPct = Math.round((confidence?.campaign_association || 0) * 100);
  const isVipTarget = executiveContext?.is_targeted || executiveContext?.is_impersonated;

  let threatColor = 'var(--success)';
  if (threatPct >= 70) threatColor = 'var(--danger)';
  else if (threatPct >= 40) threatColor = 'var(--warning)';

  return (
    <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '14px' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Gauge size={14} color="var(--accent)" /> Confidence Metrics Summary
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
        {/* Threat Confidence */}
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', padding: '10px 12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Threat Score</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: threatColor, marginTop: '2px' }}>
            {threatPct}%
          </div>
        </div>

        {/* Infrastructure Origin Confidence */}
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', padding: '10px 12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Infra-Origin Trust</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--accent)', marginTop: '2px' }}>
            {infraPct}%
          </div>
        </div>

        {/* Campaign Association Confidence */}
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', padding: '10px 12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Campaign Assoc.</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: campPct > 0 ? 'var(--violet)' : 'var(--text-dim)', marginTop: '2px' }}>
            {campPct}%
          </div>
        </div>

        {/* Executive Target Context */}
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', padding: '10px 12px', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Executive Context</div>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: isVipTarget ? 'var(--warning)' : 'var(--text-dim)', marginTop: '4px' }}>
            {isVipTarget ? 'VIP TARGETED' : 'STANDARD'}
          </div>
        </div>
      </div>
    </div>
  );
}
