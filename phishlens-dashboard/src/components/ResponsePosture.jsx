import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldOff, AlertTriangle, Globe, Plus, X, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

const SEVERITY_STYLE = {
  CRITICAL: { color: 'var(--danger)', bg: 'var(--tint-danger)' },
  HIGH: { color: 'var(--danger)', bg: 'var(--tint-danger)' },
  MEDIUM: { color: 'var(--warning)', bg: 'var(--tint-warning)' },
  LOW: { color: 'var(--accent)', bg: 'var(--tint-accent)' },
  OK: { color: 'var(--success)', bg: 'var(--tint-success)' }
};

/**
 * Answers, in one place, the question an operator most needs answered about
 * response: is anything actually being done to mail, or is PhishLens only
 * deciding what it would do.
 *
 * That distinction is stated at the top rather than buried, because a console
 * that shows "12 quarantined" without saying it simulated all twelve is worse
 * than one that shows nothing.
 */
export default function ResponsePosture() {
  const [posture, setPosture] = useState(null);
  const [domains, setDomains] = useState(null);
  const [newEntry, setNewEntry] = useState('');
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const [p, d] = await Promise.all([
        api.getRemediationPosture(),
        api.getDomainPosture().catch(() => null)
      ]);
      setPosture(p);
      setDomains(d);
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

  const addEntry = async () => {
    if (!newEntry.trim()) return;
    try {
      await api.addNeverContain(newEntry.trim());
      setNewEntry('');
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  const removeEntry = async (entry) => {
    try {
      await api.removeNeverContain(entry);
      load();
    } catch (e) {
      setError(e.response?.data?.error || e.message);
    }
  };

  if (error) return <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>Could not load response posture: {error}</div>;
  if (!posture) return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Loading response posture…</div>;

  const live = posture.capability?.can_act_on_mail;
  const guard = posture.guard || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

      {/* What this installation will actually do */}
      <div style={{
        background: live ? 'var(--tint-success)' : 'var(--tint-warning)',
        border: `1px solid ${live ? 'var(--success)' : 'var(--warning)'}`,
        borderRadius: '8px', padding: '1rem', display: 'flex', gap: '0.85rem', alignItems: 'flex-start'
      }}>
        {live
          ? <ShieldCheck size={22} style={{ color: 'var(--success)', flexShrink: 0, marginTop: 2 }} />
          : <ShieldOff size={22} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />}
        <div>
          <div style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '0.3rem' }}>
            {live ? 'Live — mail is being acted on' : 'Simulation — no mailbox is being changed'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            {posture.capability?.statement}
          </div>
          {posture.pending_approvals > 0 && (
            <div style={{ fontSize: '0.78rem', color: 'var(--warning)', marginTop: '0.5rem', fontWeight: 600 }}>
              {posture.pending_approvals} containment request{posture.pending_approvals === 1 ? '' : 's'} waiting on an analyst.
            </div>
          )}
        </div>
      </div>

      {/* The controls that constrain automatic action */}
      <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem' }}>
        <div style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
          Limits on automatic containment
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
          {[
            { label: 'Confidence floor', value: guard.minimum_confidence, note: 'Below this, a case is queued for a person instead of contained.' },
            { label: 'Burst ceiling', value: `${guard.automatic_actions_in_window ?? 0} / ${guard.burst_limit}`, note: `Automatic containments in the last ${guard.burst_window_minutes} minutes. Past the ceiling PhishLens stops acting on its own.` },
            { label: 'Never-contain entries', value: (guard.never_contain || []).length, note: 'Senders that are raised for review rather than moved automatically.' }
          ].map(item => (
            <div key={item.label} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '0.7rem' }}>
              <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-dim)' }}>{item.label}</div>
              <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)', margin: '0.2rem 0' }}>{item.value}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>{item.note}</div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
            Senders PhishLens must never move without a person saying so — payroll, a regulator, the service desk:
            mail whose delay costs more than the phishing it might occasionally carry.
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.6rem' }}>
            <input
              value={newEntry}
              onChange={e => setNewEntry(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addEntry()}
              placeholder="address or domain"
              style={{
                flex: 1, background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
                borderRadius: '6px', padding: '0.45rem 0.6rem', color: 'var(--text-primary)', fontSize: '0.78rem'
              }}
            />
            <button onClick={addEntry} style={{
              background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none',
              borderRadius: '6px', padding: '0.45rem 0.8rem', fontSize: '0.78rem', fontWeight: 600,
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem'
            }}><Plus size={13} /> Add</button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {(guard.never_contain || []).length === 0
              ? <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Nothing excluded.</span>
              : guard.never_contain.map(entry => (
                <span key={entry} style={{
                  background: 'var(--bg-raised)', borderRadius: '999px', padding: '0.25rem 0.5rem 0.25rem 0.7rem',
                  fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem'
                }}>
                  {entry}
                  <button onClick={() => removeEntry(entry)} title={`Remove ${entry}`} style={{
                    background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', padding: 0
                  }}><X size={12} /></button>
                </span>
              ))}
          </div>
        </div>
      </div>

      {/* Prevention rather than reaction */}
      <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
          <Globe size={15} style={{ color: 'var(--accent)' }} />
          <span style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--text-primary)' }}>Can your own domains be spoofed?</span>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.85rem', lineHeight: 1.5 }}>
          Everything else here reacts to a message that has already been sent. A domain published with DMARC
          p=reject cannot be spoofed outright, which pushes an attacker onto a lookalike domain — something the
          detection layer catches far more reliably than an exact impersonation.
        </div>

        {!domains || !domains.domains ? (
          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Checking published records…</div>
        ) : domains.domains.length === 0 ? (
          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>{domains.note}</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
            {domains.domains.map(assessment => {
              const style = SEVERITY_STYLE[assessment.severity] || SEVERITY_STYLE.LOW;
              return (
                <div key={assessment.domain} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '0.8rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                    {assessment.spoofable
                      ? <AlertTriangle size={14} style={{ color: style.color }} />
                      : <CheckCircle2 size={14} style={{ color: 'var(--success)' }} />}
                    <span style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--text-primary)' }}>{assessment.domain}</span>
                    <span style={{
                      background: style.bg, color: style.color, borderRadius: '4px',
                      padding: '0.1rem 0.4rem', fontSize: '0.64rem', fontWeight: 700, letterSpacing: '0.04em'
                    }}>{assessment.severity}</span>
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>{assessment.summary}</div>

                  {(assessment.findings || []).filter(f => f.severity !== 'OK').map((f, i) => (
                    <div key={i} style={{ borderLeft: `2px solid ${(SEVERITY_STYLE[f.severity] || style).color}`, paddingLeft: '0.6rem', marginBottom: '0.6rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>{f.finding}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', margin: '0.2rem 0', lineHeight: 1.5 }}>{f.consequence}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{f.recommendation}</div>
                      {f.dns_record && (
                        <code style={{
                          display: 'block', background: 'var(--bg-code)', borderRadius: '4px', padding: '0.45rem 0.55rem',
                          fontSize: '0.68rem', color: 'var(--accent-soft)', marginTop: '0.35rem', wordBreak: 'break-all'
                        }}>
                          {f.dns_record.name} {f.dns_record.type} "{f.dns_record.value}"
                        </code>
                      )}
                      <div style={{ fontSize: '0.66rem', color: 'var(--text-dim)', marginTop: '0.3rem' }}>{f.reference}</div>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
