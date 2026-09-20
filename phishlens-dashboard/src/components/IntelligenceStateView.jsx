import React, { useState, useEffect } from 'react';
import { Brain, Database, RefreshCw, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

/**
 * Makes the two self-updating parts of the system inspectable: what it has
 * learned from confirmed verdicts, and which indicator feeds it is matching
 * against. Both are shown with their limitations, so neither is taken on trust.
 */
export default function IntelligenceStateView() {
  const [learning, setLearning] = useState(null);
  const [intel, setIntel] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const [l, t] = await Promise.all([api.getLearningState(), api.getThreatIntelligence()]);
      setLearning(l);
      setIntel(t);
      setError(null);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  const runSync = async () => {
    setSyncing(true);
    try {
      await api.syncThreatIntelligence();
      await load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    } finally {
      setSyncing(false);
    }
  };

  if (error) return <div style={{ color: '#ef4444', fontSize: '0.8rem' }}>Could not load intelligence state: {error}</div>;
  if (!learning || !intel) return <div style={{ color: '#64748b', fontSize: '0.8rem' }}>Loading intelligence state…</div>;

  const adaptive = learning.adaptive;
  const status = intel.status;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* ---------- adaptive learning ---------- */}
      <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '10px' }}>
          <Brain size={15} color="#8b5cf6" />
          <h4 style={{ margin: 0, fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600 }}>Learned from confirmed verdicts</h4>
        </div>

        {!adaptive.ready ? (
          <div style={{ backgroundColor: 'rgba(245,158,11,0.08)', border: '1px solid #f59e0b', borderRadius: '5px', padding: '10px', fontSize: '0.75rem', color: '#cbd5e1' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f59e0b', fontWeight: 600, marginBottom: '4px' }}>
              <AlertTriangle size={13} /> Not yet contributing to scoring
            </div>
            Learned from {adaptive.learned_from.malicious} confirmed malicious and {adaptive.learned_from.legitimate} confirmed
            legitimate message(s). At least {adaptive.minimum_required_per_class} of each are needed before this contributes
            any evidence, so it currently adds nothing rather than guessing from too few examples.
          </div>
        ) : (
          <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
            Learned from <strong style={{ color: '#f8fafc' }}>{adaptive.learned_from.malicious}</strong> confirmed malicious
            and <strong style={{ color: '#f8fafc' }}>{adaptive.learned_from.legitimate}</strong> confirmed legitimate message(s),
            across <strong style={{ color: '#f8fafc' }}>{adaptive.characteristics_known}</strong> characteristics.
          </div>
        )}

        {learning.top_learned_indicators?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#64748b', marginBottom: '6px' }}>
              Strongest learned indicators
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {learning.top_learned_indicators.slice(0, 12).map(indicator => (
                <div key={indicator.characteristic} style={{
                  display: 'flex', justifyContent: 'space-between', gap: '10px',
                  backgroundColor: '#131b2e', borderRadius: '4px', padding: '6px 9px', fontSize: '0.72rem'
                }}>
                  <span className="font-mono" style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {indicator.characteristic}
                  </span>
                  <span style={{ color: '#94a3b8', whiteSpace: 'nowrap' }}>
                    weight {indicator.weight} · {indicator.seen_in_malicious} malicious / {indicator.seen_in_legitimate} legitimate
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {learning.behavioral && (
          <div style={{ marginTop: '12px', fontSize: '0.73rem', color: '#94a3b8' }}>
            Behavioural baselines: <strong style={{ color: '#f8fafc' }}>{learning.behavioral.senders_tracked}</strong> sender(s)
            and <strong style={{ color: '#f8fafc' }}>{learning.behavioral.display_names_tracked}</strong> display name(s) observed.
          </div>
        )}

        {adaptive.recent_learning_events?.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#64748b', marginBottom: '6px' }}>
              Recent learning events
            </div>
            {adaptive.recent_learning_events.slice(0, 6).map((event, i) => (
              <div key={i} style={{ fontSize: '0.71rem', color: '#94a3b8', padding: '3px 0' }}>
                <span className="font-mono" style={{ color: '#3b82f6' }}>{event.case_id}</span>
                {' '}learned as <strong style={{ color: event.label === 'malicious' ? '#ef4444' : '#10b981' }}>{event.label}</strong>
                {' '}({event.source.replace(/_/g, ' ').toLowerCase()})
                {event.corrected_previous_label && (
                  <span style={{ color: '#f59e0b' }}> — corrected an earlier "{event.corrected_previous_label}" label</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ---------- threat intelligence feeds ---------- */}
      <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
            <Database size={15} color="#3b82f6" />
            <h4 style={{ margin: 0, fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600 }}>Threat-intelligence feeds</h4>
          </div>
          <button
            onClick={runSync}
            disabled={syncing}
            style={{
              backgroundColor: '#1e293b', color: '#cbd5e1', border: '1px solid #334155', borderRadius: '4px',
              padding: '5px 10px', fontSize: '0.71rem', cursor: syncing ? 'default' : 'pointer',
              display: 'flex', alignItems: 'center', gap: '5px', opacity: syncing ? 0.6 : 1
            }}
          >
            <RefreshCw size={11} /> {syncing ? 'Syncing…' : 'Sync now'}
          </button>
        </div>

        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '10px' }}>
          {status.synced ? (
            <>
              <strong style={{ color: '#f8fafc' }}>{status.totals.urls}</strong> URLs,{' '}
              <strong style={{ color: '#f8fafc' }}>{status.totals.url_hosts}</strong> hosts,{' '}
              <strong style={{ color: '#f8fafc' }}>{status.totals.domains}</strong> domains,{' '}
              <strong style={{ color: '#f8fafc' }}>{status.totals.ips}</strong> IPs,{' '}
              <strong style={{ color: '#f8fafc' }}>{status.totals.netblocks}</strong> netblocks
              {status.age_hours !== null && <> · synced {status.age_hours}h ago</>}
            </>
          ) : (
            <span style={{ color: '#f59e0b' }}>No indicator feed has been synchronised yet.</span>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
          {Object.entries(status.feeds || {}).map(([id, feed]) => (
            <div key={id} style={{ backgroundColor: '#131b2e', borderRadius: '4px', padding: '8px 10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                <span style={{ fontSize: '0.74rem', color: '#f8fafc', fontWeight: 600 }}>{feed.name}</span>
                <span style={{ fontSize: '0.66rem', color: feed.status === 'SYNCED' ? '#10b981' : '#ef4444', fontWeight: 700 }}>
                  {feed.status}
                </span>
              </div>
              <div style={{ fontSize: '0.69rem', color: '#94a3b8', marginTop: '2px' }}>
                {feed.indicators} indicator(s){feed.error ? ` — ${feed.error}` : ''}
              </div>
              <div style={{ fontSize: '0.66rem', color: '#64748b', marginTop: '2px', fontStyle: 'italic' }}>
                Licence: {feed.licence}
              </div>
            </div>
          ))}
        </div>

        <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '10px', fontStyle: 'italic', lineHeight: 1.5 }}>
          {status.model}
        </div>
        <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '4px', fontStyle: 'italic', lineHeight: 1.5 }}>
          {status.limitation}
        </div>
      </div>
    </div>
  );
}
