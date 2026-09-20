import React, { useState } from 'react';
import { Filter, Search } from 'lucide-react';

function getRelativeTime(timestamp) {
  if (!timestamp) return 'Just now';
  const now = new Date();
  const past = new Date(timestamp);
  const diffMs = now - past;
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${Math.floor(diffHours / 24)}d ago`;
}

export default function ThreatFeed({ cases, selectedCase, onSelectCase }) {
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredCases = cases.filter(c => {
    if (filter === 'HIGH_RISK' && c.detection?.verdict !== 'HIGH_RISK') return false;
    if (filter === 'SUSPICIOUS' && c.detection?.verdict !== 'SUSPICIOUS') return false;
    if (filter === 'VIP' && !(c.executive_context?.is_targeted || c.executive_context?.is_impersonated)) return false;
    if (filter === 'QUARANTINED' && c.remediation?.status !== 'QUARANTINED') return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const subject = (c.message?.subject || '').toLowerCase();
      const sender = (c.message?.sender || '').toLowerCase();
      const caseId = (c.case_id || '').toLowerCase();
      return subject.includes(q) || sender.includes(q) || caseId.includes(q);
    }

    return true;
  }).slice().reverse();

  return (
    <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '14px', display: 'flex', flexDirection: 'column', height: '100%', minHeight: '500px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <h3 style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Threat Queue ({filteredCases.length})
        </h3>
        <span style={{ fontSize: '0.7rem', color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--success)' }}></span> Live Ingestion
        </span>
      </div>

      {/* Search Input */}
      <div style={{ position: 'relative', marginBottom: '10px' }}>
        <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
        <input
          type="text"
          placeholder="Filter queue by subject, sender, ID..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            width: '100%',
            backgroundColor: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '6px 10px 6px 30px',
            fontSize: '0.75rem',
            color: 'var(--text-primary)',
            outline: 'none'
          }}
        />
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '12px' }}>
        {['ALL', 'HIGH_RISK', 'SUSPICIOUS', 'VIP', 'QUARANTINED'].map(tab => (
          <button
            key={tab}
            onClick={() => setFilter(tab)}
            style={{
              backgroundColor: filter === tab ? 'var(--accent)' : 'var(--bg-panel)',
              color: filter === tab ? 'var(--text-on-accent)' : 'var(--text-muted)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              padding: '3px 8px',
              fontSize: '0.7rem',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            {tab.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Feed List */}
      <div style={{ overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {filteredCases.length === 0 ? (
          <div style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '32px 16px', fontSize: '0.8rem' }}>
            No security incidents match the selected filter.
          </div>
        ) : (
          filteredCases.map(c => {
            const isSelected = selectedCase?.case_id === c.case_id;
            const verdict = c.detection?.verdict || 'UNKNOWN';
            const isHigh = verdict === 'HIGH_RISK';
            const isSusp = verdict === 'SUSPICIOUS';

            let badgeBg = 'var(--tint-neutral)';
            let badgeColor = 'var(--text-muted)';
            if (isHigh) { badgeBg = 'var(--tint-danger)'; badgeColor = 'var(--danger)'; }
            else if (isSusp) { badgeBg = 'var(--tint-warning)'; badgeColor = 'var(--warning)'; }
            else if (verdict === 'SAFE') { badgeBg = 'var(--tint-success)'; badgeColor = 'var(--success)'; }

            const relativeTime = getRelativeTime(c.message?.delivered_at || c.timestamps?.ingested_at);

            return (
              <div
                key={c.case_id}
                onClick={() => onSelectCase(c)}
                style={{
                  backgroundColor: isSelected ? 'var(--border)' : 'var(--bg-panel)',
                  border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '10px 12px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ backgroundColor: badgeBg, color: badgeColor, fontSize: '0.65rem', fontWeight: 700, padding: '1px 6px', borderRadius: '3px', textTransform: 'uppercase' }}>
                      {verdict.replace('_', ' ')}
                    </span>
                    <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--accent)', fontWeight: 600 }}>{c.case_id}</span>
                  </div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>{relativeTime}</span>
                </div>

                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.message?.subject || '(No Subject)'}
                </div>

                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.message?.sender || 'Unknown Sender'}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
