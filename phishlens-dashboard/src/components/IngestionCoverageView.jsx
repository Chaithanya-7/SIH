import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, ShieldOff, AlertTriangle, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

const STATUS_STYLE = {
  ACTIVE: { color: '#10b981', bg: 'rgba(16,185,129,0.12)', label: 'Watched' },
  STALLED: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', label: 'Stopped reporting' },
  FAILED: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', label: 'Failed' },
  DISABLED: { color: '#64748b', bg: 'rgba(100,116,139,0.12)', label: 'Switched off' },
  NOT_CONFIGURED: { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', label: 'Not configured' }
};

/**
 * Answers the question an analyst actually needs answered: could a message
 * reach a user without being examined. Unwatched and stalled paths are shown as
 * prominently as healthy ones, because a door nobody is watching is the point.
 */
export default function IngestionCoverageView() {
  const [coverage, setCoverage] = useState(null);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      setCoverage(await api.getIngestionCoverage());
      setError(null);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return <div style={{ color: '#ef4444', fontSize: '0.8rem' }}>Could not load ingestion coverage: {error}</div>;
  }
  if (!coverage) {
    return <div style={{ color: '#64748b', fontSize: '0.8rem' }}>Loading ingestion coverage…</div>;
  }

  const monitoring = coverage.monitoring_live_mail;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Headline state: is anything actually being monitored */}
      <div style={{
        backgroundColor: monitoring ? 'rgba(16,185,129,0.08)' : 'rgba(245,158,11,0.08)',
        border: `1px solid ${monitoring ? '#10b981' : '#f59e0b'}`,
        borderRadius: '6px', padding: '14px', display: 'flex', alignItems: 'flex-start', gap: '12px'
      }}>
        {monitoring
          ? <ShieldCheck size={22} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
          : <ShieldAlert size={22} color="#f59e0b" style={{ flexShrink: 0, marginTop: '2px' }} />}
        <div>
          <div style={{ fontSize: '0.92rem', fontWeight: 700, color: monitoring ? '#10b981' : '#f59e0b' }}>
            {monitoring ? 'Monitoring live mail' : 'Not monitoring any mailbox or gateway'}
          </div>
          <div style={{ fontSize: '0.76rem', color: '#94a3b8', marginTop: '3px' }}>
            {monitoring
              ? `${coverage.summary.automatic_active} automatic source(s) active, ${coverage.summary.unwatched} entry path(s) unwatched.`
              : 'Only messages explicitly submitted to PhishLens are being analysed. No mailbox or gateway is being watched.'}
          </div>
        </div>
      </div>

      {/* Anything actively wrong */}
      {coverage.warnings.length > 0 && (
        <div style={{ backgroundColor: '#0d1322', border: '1px solid #f59e0b', borderRadius: '6px', padding: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
            <AlertTriangle size={14} color="#f59e0b" />
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f59e0b' }}>Coverage warnings</span>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', color: '#cbd5e1', fontSize: '0.75rem', lineHeight: 1.6 }}>
            {coverage.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}

      {/* Every entry path, watched or not */}
      <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
        <h4 style={{ margin: '0 0 10px 0', fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600 }}>
          Mail entry paths ({coverage.summary.total_sources})
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {coverage.sources.map(source => {
            const style = STATUS_STYLE[source.status] || STATUS_STYLE.NOT_CONFIGURED;
            return (
              <div key={source.id} style={{
                backgroundColor: '#131b2e', borderRadius: '5px', padding: '10px 12px',
                borderLeft: `3px solid ${style.color}`
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>
                    {source.name}
                    <span style={{ color: '#64748b', fontWeight: 400, marginLeft: '8px', fontSize: '0.7rem' }}>{source.transport}</span>
                  </span>
                  <span style={{
                    backgroundColor: style.bg, color: style.color, fontSize: '0.62rem',
                    fontWeight: 700, padding: '2px 7px', borderRadius: '3px', whiteSpace: 'nowrap'
                  }}>
                    {style.label}
                  </span>
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '4px' }}>{source.detail}</div>
                {source.enable_hint && (
                  <div style={{ fontSize: '0.7rem', color: '#f59e0b', marginTop: '4px' }}>
                    To enable: {source.enable_hint}
                  </div>
                )}
                <div style={{ display: 'flex', gap: '16px', fontSize: '0.68rem', color: '#64748b', marginTop: '6px' }}>
                  <span>{source.messages_ingested} message(s) ingested</span>
                  {source.failures > 0 && <span style={{ color: '#ef4444' }}>{source.failures} failure(s)</span>}
                  {source.last_message_at && <span>Last: {new Date(source.last_message_at).toLocaleString()}</span>}
                </div>
                {source.last_error && (
                  <div style={{ fontSize: '0.68rem', color: '#ef4444', marginTop: '4px' }}>
                    Last error: {source.last_error.message}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Gmail is the path most likely to be half-configured */}
      {coverage.gmail && (
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
          <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600 }}>Gmail connection readiness</h4>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '5px' }}>
            <div>
              <strong>OAuth application:</strong>{' '}
              <span style={{ color: coverage.gmail.oauth_app_configured ? '#10b981' : '#f59e0b' }}>
                {coverage.gmail.oauth_app_configured ? 'configured' : 'not configured'}
              </span>
            </div>
            <div><strong>Connected mailboxes:</strong> {coverage.gmail.connected_mailboxes}</div>
            {coverage.gmail.missing_environment.length > 0 && (
              <div><strong>Missing settings:</strong> <span className="font-mono" style={{ color: '#f59e0b' }}>{coverage.gmail.missing_environment.join(', ')}</span></div>
            )}
            <div style={{ color: '#cbd5e1', marginTop: '3px' }}>{coverage.gmail.next_step}</div>
            <div style={{ color: '#64748b', fontStyle: 'italic', marginTop: '3px' }}>{coverage.gmail.limitation}</div>
          </div>
        </div>
      )}

      <button
        onClick={load}
        style={{
          alignSelf: 'flex-start', backgroundColor: '#1e293b', color: '#cbd5e1', border: '1px solid #334155',
          borderRadius: '4px', padding: '6px 12px', fontSize: '0.73rem', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: '6px'
        }}
      >
        <RefreshCw size={12} /> Refresh
      </button>
    </div>
  );
}
