import React from 'react';
import { Gauge } from 'lucide-react';

export default function ConfidenceCard({ confidence, executiveContext }) {
  const threatPct = Math.round((confidence?.threat || 0) * 100);
  const infraPct = Math.round((confidence?.infrastructure_origin || 0) * 100);
  const campPct = Math.round((confidence?.campaign_association || 0) * 100);
  const isVipTarget = executiveContext?.is_targeted || executiveContext?.is_impersonated;

  let threatColor = '#10b981';
  if (threatPct >= 70) threatColor = '#ef4444';
  else if (threatPct >= 40) threatColor = '#f59e0b';

  return (
    <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '14px' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <Gauge size={14} color="#3b82f6" /> Confidence Metrics Summary
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
        {/* Threat Confidence */}
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', padding: '10px 12px', border: '1px solid #1e293b' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Threat Score</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: threatColor, marginTop: '2px' }}>
            {threatPct}%
          </div>
        </div>

        {/* Infrastructure Origin Confidence */}
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', padding: '10px 12px', border: '1px solid #1e293b' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Infra-Origin Trust</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: '#3b82f6', marginTop: '2px' }}>
            {infraPct}%
          </div>
        </div>

        {/* Campaign Association Confidence */}
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', padding: '10px 12px', border: '1px solid #1e293b' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Campaign Assoc.</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: campPct > 0 ? '#8b5cf6' : '#64748b', marginTop: '2px' }}>
            {campPct}%
          </div>
        </div>

        {/* Executive Target Context */}
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', padding: '10px 12px', border: '1px solid #1e293b' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Executive Context</div>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: isVipTarget ? '#f59e0b' : '#64748b', marginTop: '4px' }}>
            {isVipTarget ? 'VIP TARGETED' : 'STANDARD'}
          </div>
        </div>
      </div>
    </div>
  );
}
