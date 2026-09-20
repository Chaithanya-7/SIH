import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, ShieldOff, AlertTriangle, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

const STATUS_STYLE = {
  ACTIVE: { color: 'var(--success)', bg: 'var(--tint-success)', label: 'Watched' },
  STALLED: { color: 'var(--danger)', bg: 'var(--tint-danger)', label: 'Stopped reporting' },
  FAILED: { color: 'var(--danger)', bg: 'var(--tint-danger)', label: 'Failed' },
  DISABLED: { color: 'var(--text-dim)', bg: 'var(--tint-neutral)', label: 'Switched off' },
  NOT_CONFIGURED: { color: 'var(--warning)', bg: 'var(--tint-warning)', label: 'Not configured' }
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
    return <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>Could not load ingestion coverage: {error}</div>;
  }
  if (!coverage) {
    return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Loading ingestion coverage…</div>;
  }

  const monitoring = coverage.monitoring_live_mail;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Headline state: is anything actually being monitored */}
      <div style={{
        backgroundColor: monitoring ? 'var(--tint-success)' : 'var(--tint-warning)',
        border: `1px solid ${monitoring ? 'var(--success)' : 'var(--warning)'}`,
        borderRadius: '6px', padding: '14px', display: 'flex', alignItems: 'flex-start', gap: '12px'
      }}>
        {monitoring
          ? <ShieldCheck size={22} color="var(--success)" style={{ flexShrink: 0, marginTop: '2px' }} />
          : <ShieldAlert size={22} color="var(--warning)" style={{ flexShrink: 0, marginTop: '2px' }} />}
        <div>
          <div style={{ fontSize: '0.92rem', fontWeight: 700, color: monitoring ? 'var(--success)' : 'var(--warning)' }}>
            {monitoring ? 'Monitoring live mail' : 'Not monitoring any mailbox or gateway'}
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '3px' }}>
            {monitoring
              ? `${coverage.summary.automatic_active} automatic source(s) active, ${coverage.summary.unwatched} entry path(s) unwatched.`
              : 'Only messages explicitly submitted to PhishLens are being analysed. No mailbox or gateway is being watched.'}
          </div>
        </div>
      </div>

      {/* Anything actively wrong */}
      {coverage.warnings.length > 0 && (
        <div style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--warning)', borderRadius: '6px', padding: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
            <AlertTriangle size={14} color="var(--warning)" />
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--warning)' }}>Coverage warnings</span>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', color: 'var(--text-secondary)', fontSize: '0.75rem', lineHeight: 1.6 }}>
            {coverage.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}

      {/* Every entry path, watched or not */}
      <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
        <h4 style={{ margin: '0 0 10px 0', fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>
          Mail entry paths ({coverage.summary.total_sources})
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {coverage.sources.map(source => {
            const style = STATUS_STYLE[source.status] || STATUS_STYLE.NOT_CONFIGURED;
            return (
              <div key={source.id} style={{
                backgroundColor: 'var(--bg-surface)', borderRadius: '5px', padding: '10px 12px',
                borderLeft: `3px solid ${style.color}`
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {source.name}
                    <span style={{ color: 'var(--text-dim)', fontWeight: 400, marginLeft: '8px', fontSize: '0.7rem' }}>{source.transport}</span>
                  </span>
                  <span style={{
                    backgroundColor: style.bg, color: style.color, fontSize: '0.62rem',
                    fontWeight: 700, padding: '2px 7px', borderRadius: '3px', whiteSpace: 'nowrap'
                  }}>
                    {style.label}
                  </span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>{source.detail}</div>
                {source.enable_hint && (
                  <div style={{ fontSize: '0.7rem', color: 'var(--warning)', marginTop: '4px' }}>
                    To enable: {source.enable_hint}
                  </div>
                )}
                <div style={{ display: 'flex', gap: '16px', fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                  <span>{source.messages_ingested} message(s) ingested</span>
                  {source.failures > 0 && <span style={{ color: 'var(--danger)' }}>{source.failures} failure(s)</span>}
                  {source.last_message_at && <span>Last: {new Date(source.last_message_at).toLocaleString()}</span>}
                </div>
                {source.last_error && (
                  <div style={{ fontSize: '0.68rem', color: 'var(--danger)', marginTop: '4px' }}>
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
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
          <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>Gmail connection readiness</h4>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '5px' }}>
            <div>
              <strong>OAuth application:</strong>{' '}
              <span style={{ color: coverage.gmail.oauth_app_configured ? 'var(--success)' : 'var(--warning)' }}>
                {coverage.gmail.oauth_app_configured ? 'configured' : 'not configured'}
              </span>
            </div>
            <div><strong>Connected mailboxes:</strong> {coverage.gmail.connected_mailboxes}</div>
            {coverage.gmail.missing_environment.length > 0 && (
              <div><strong>Missing settings:</strong> <span className="font-mono" style={{ color: 'var(--warning)' }}>{coverage.gmail.missing_environment.join(', ')}</span></div>
            )}
            <div style={{ color: 'var(--text-secondary)', marginTop: '3px' }}>{coverage.gmail.next_step}</div>
            <div style={{ color: 'var(--text-dim)', fontStyle: 'italic', marginTop: '3px' }}>{coverage.gmail.limitation}</div>
          </div>
        </div>
      )}

      <button
        onClick={load}
        style={{
          alignSelf: 'flex-start', backgroundColor: 'var(--border)', color: 'var(--text-secondary)', border: '1px solid var(--border-strong)',
          borderRadius: '4px', padding: '6px 12px', fontSize: '0.73rem', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: '6px'
        }}
      >
        <RefreshCw size={12} /> Refresh
      </button>
    </div>
  );
}
