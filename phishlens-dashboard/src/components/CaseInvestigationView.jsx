import React, { useState } from 'react';
import { FileText, ChevronDown, ChevronRight, AlertCircle, Shield, Key, Globe, Network, Activity } from 'lucide-react';
import ConfidenceCard from './ConfidenceCard';
import RelayTimeline from './RelayTimeline';
import ThreatMap from './ThreatMap';

export default function CaseInvestigationView({ selectedCase, onOpenReport }) {
  const [activeSection, setActiveSection] = useState('overview');
  const [expandedEvidence, setExpandedEvidence] = useState({});
  const [expandedAuth, setExpandedAuth] = useState(false);

  if (!selectedCase) {
    return (
      <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '48px', textAlign: 'center', color: '#64748b' }}>
        Select an incident case from the threat queue to initiate forensic analysis workspace.
      </div>
    );
  }

  const auth = selectedCase.forensics?.authentication || {};
  const iocs = selectedCase.iocs || {};
  const attachments = selectedCase.attachments || [];
  const evidence = selectedCase.evidence || [];
  const campaignAssoc = selectedCase.campaign_association || {};
  const campaign = selectedCase.campaign || {};
  const detection = selectedCase.detection || {};
  const nlp = selectedCase.nlp || { status: 'NOT_ANALYZED', signals: [], score: 0 };
  const behavioral = selectedCase.behavioral || { status: 'NOT_ANALYZED', signals: [] };
  const adaptive = selectedCase.adaptive || { status: 'NOT_SCORED', contributions: [] };
  const threatIntel = selectedCase.threat_intelligence || { status: 'NOT_ANALYZED', matches: [], domain_ages: [] };
  const verdict = detection.verdict || 'UNKNOWN';

  let verdictBg = 'rgba(100, 116, 139, 0.12)';
  let verdictColor = '#94a3b8';
  if (verdict === 'HIGH_RISK') { verdictBg = 'rgba(239, 68, 68, 0.12)'; verdictColor = '#ef4444'; }
  else if (verdict === 'SUSPICIOUS') { verdictBg = 'rgba(245, 158, 11, 0.12)'; verdictColor = '#f59e0b'; }
  else if (verdict === 'SAFE') { verdictBg = 'rgba(16, 185, 129, 0.12)'; verdictColor = '#10b981'; }

  const toggleEvidenceExpand = (idx) => {
    setExpandedEvidence(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  const renderAuthBadge = (protocol, status) => {
    const st = (status || 'unknown').toLowerCase();
    let bg = 'rgba(100, 116, 139, 0.12)';
    let color = '#94a3b8';
    let iconLabel = 'Neutral';

    if (st === 'pass') {
      bg = 'rgba(16, 185, 129, 0.12)';
      color = '#10b981';
      iconLabel = 'Passed';
    } else if (st === 'fail') {
      bg = 'rgba(239, 68, 68, 0.12)';
      color = '#ef4444';
      iconLabel = 'Failed';
    }

    return (
      <div style={{ flex: 1, backgroundColor: '#0d1322', borderRadius: '6px', padding: '10px 14px', border: '1px solid #1e293b' }}>
        <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 600 }}>{protocol}</div>
        <div style={{ fontSize: '0.88rem', fontWeight: 700, color, marginTop: '2px', textTransform: 'capitalize' }}>
          {st === 'fail' ? '✕ Failed' : st === 'pass' ? '✓ Passed' : '— Unknown'}
        </div>
      </div>
    );
  };

  return (
    <div className="animate-fade-in" style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Case Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1e293b', paddingBottom: '16px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="font-mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: '#3b82f6' }}>{selectedCase.case_id}</span>
            <span style={{ backgroundColor: verdictBg, color: verdictColor, fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase' }}>
              {verdict.replace('_', ' ')}
            </span>
            {detection.external_provider_result?.attempted && detection.external_provider_result?.status !== 'RESPONDED' && (
              <span style={{ backgroundColor: 'rgba(245, 158, 11, 0.18)', color: '#f59e0b', fontSize: '0.65rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', border: '1px solid #f59e0b' }}>
                EXTERNAL PROVIDER UNAVAILABLE (NATIVE DETECTION ONLY)
              </span>
            )}
          </div>
          <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc' }}>
            {selectedCase.message?.subject || '(No Subject)'}
          </h2>
          <div style={{ fontSize: '0.76rem', color: '#94a3b8', display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
            <span>From: <strong style={{ color: '#f8fafc' }}>{selectedCase.message?.sender}</strong></span>
            <span>→ Recipient: <strong style={{ color: '#f8fafc' }}>{selectedCase.message?.recipient}</strong></span>
            <span>Received: <strong style={{ color: '#94a3b8' }}>{new Date(selectedCase.message?.delivered_at || selectedCase.timestamps?.ingested_at).toLocaleString()}</strong></span>
          </div>
        </div>

        <button
          onClick={onOpenReport}
          style={{ backgroundColor: '#3b82f6', color: '#fff', border: 'none', borderRadius: '4px', padding: '7px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <FileText size={14} /> Forensic Report
        </button>
      </div>

      {/* 2. Compact Summary Metrics Bar */}
      <ConfidenceCard confidence={selectedCase.confidence} executiveContext={selectedCase.executive_context} />

      {/* 3. Section Tabs */}
      <div style={{ display: 'flex', gap: '4px', borderBottom: '1px solid #1e293b', paddingBottom: '8px', overflowX: 'auto' }}>
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'detection', label: 'Detection' },
          { id: 'authentication', label: 'Authentication' },
          { id: 'nlp', label: `Language Analysis (${nlp.signals.length})` },
          { id: 'behaviour', label: `Behaviour (${behavioral.signals?.length || 0})` },
          { id: 'threatintel', label: `Threat Intel (${threatIntel.matches?.length || 0})` },
          { id: 'infrastructure', label: 'Infrastructure' },
          { id: 'evidence', label: `Evidence (${evidence.length})` },
          { id: 'iocs', label: 'IOCs' },
          { id: 'attachments', label: `Attachments (${attachments.length})` },
          { id: 'campaign', label: 'Campaign' },
          { id: 'timeline', label: 'Timeline' },
          { id: 'response', label: 'Response' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveSection(tab.id)}
            style={{
              backgroundColor: activeSection === tab.id ? '#1e293b' : 'transparent',
              color: activeSection === tab.id ? '#3b82f6' : '#94a3b8',
              border: activeSection === tab.id ? '1px solid #3b82f6' : '1px solid transparent',
              borderRadius: '4px',
              padding: '5px 10px',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
              whiteSpace: 'nowrap'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 4. Section Content Rendering */}

      {/* OVERVIEW SECTION */}
      {activeSection === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Identity Info */}
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: '#f8fafc', fontWeight: 600 }}>Message Identity Summary</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.75rem', color: '#94a3b8' }}>
              <div><strong>Sender Address:</strong> <span style={{ color: '#f8fafc' }}>{selectedCase.message?.sender}</span></div>
              <div><strong>Envelope Recipient:</strong> <span style={{ color: '#f8fafc' }}>{selectedCase.message?.recipient}</span></div>
              <div><strong>SHA-256 Hash:</strong> <span className="font-mono" style={{ color: '#3b82f6', fontSize: '0.7rem' }}>{selectedCase.message?.raw_hash}</span></div>
              <div><strong>Return-Path Mismatch:</strong> <span style={{ color: selectedCase.forensics?.return_path_mismatch ? '#ef4444' : '#10b981', fontWeight: 600 }}>{selectedCase.forensics?.return_path_mismatch ? 'YES (SUSPICIOUS)' : 'NO'}</span></div>
            </div>
          </div>

          {/* Key Findings List */}
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: '#f8fafc', fontWeight: 600 }}>Top Threat Evidence Items</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {evidence.slice(0, 3).map((ev, idx) => (
                <div key={idx} style={{ backgroundColor: '#131b2e', padding: '8px 10px', borderRadius: '4px', borderLeft: ev.severity === 'HIGH' ? '3px solid #ef4444' : '3px solid #f59e0b' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f8fafc' }}>{ev.finding}</div>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '2px' }}>{ev.explanation}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DETECTION SECTION */}
      {activeSection === 'detection' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.75rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div><strong>Detection Verdict:</strong> <span style={{ color: verdictColor, fontWeight: 700 }}>{verdict}</span></div>
            <div><strong>Verification Status:</strong> <span style={{ color: '#10b981', fontWeight: 700 }}>{detection.verification_status || 'PENDING_NATIVE_ANALYSIS'}</span></div>
            <div><strong>Detection Provider:</strong> <span style={{ color: '#f8fafc', fontWeight: 600 }}>{detection.provider || 'PHISHLENS_NATIVE_MQL'}</span></div>
            <div><strong>Rules Evaluated / Matched:</strong> {detection.rule_engine ? `${detection.rule_engine.rules_evaluated} evaluated, ${detection.rule_engine.rules_matched} matched` : 'Not yet evaluated'}</div>
            {detection.external_provider_result?.attempted && (
              <div>
                <strong>External Provider Cross-Check ({detection.external_provider_result.provider}):</strong>{' '}
                <span style={{ color: detection.external_provider_result.status === 'RESPONDED' ? '#10b981' : '#f59e0b' }}>
                  {detection.external_provider_result.status}
                </span>
                {detection.external_provider_result.claimed_verdict && ` — claimed verdict: ${detection.external_provider_result.claimed_verdict}`}
                <div style={{ marginTop: '2px', fontStyle: 'italic', color: '#64748b' }}>{detection.external_provider_result.note}</div>
              </div>
            )}
          </div>

          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: '#f8fafc', fontWeight: 600 }}>Matched MQL Rules</h4>
            {(detection.matched_rules || []).length === 0 ? (
              <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>No native detection rules matched this message.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {detection.matched_rules.map(rule => (
                  <div key={rule.id} style={{ backgroundColor: '#131b2e', padding: '8px 10px', borderRadius: '4px', borderLeft: rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? '3px solid #ef4444' : '3px solid #f59e0b' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                      <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f8fafc' }}>{rule.id} — {rule.name}</span>
                      <span style={{ fontSize: '0.68rem', color: '#94a3b8' }}>{rule.severity} • {Math.round(rule.confidence * 100)}%</span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '2px' }}>{rule.matched_because}</div>
                    <div style={{ fontSize: '0.68rem', color: '#64748b', marginTop: '2px', fontStyle: 'italic' }}>Source: {rule.source}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* AUTHENTICATION SECTION */}
      {activeSection === 'authentication' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            {renderAuthBadge('SPF Validation', auth.spf)}
            {renderAuthBadge('DKIM Validation', auth.dkim)}
            {renderAuthBadge('DMARC Compliance', auth.dmarc)}
          </div>

          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
            <button
              onClick={() => setExpandedAuth(!expandedAuth)}
              style={{ backgroundColor: 'transparent', border: 'none', color: '#3b82f6', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              {expandedAuth ? <ChevronDown size={14} /> : <ChevronRight size={14} />} View Technical Authentication Details
            </button>
            {expandedAuth && (
              <div className="font-mono" style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '8px', whiteSpace: 'pre-wrap', backgroundColor: '#090d16', padding: '10px', borderRadius: '4px' }}>
                {JSON.stringify(auth, null, 2)}
              </div>
            )}
          </div>
        </div>
      )}

      {/* BEHAVIOURAL SECTION — how this message compares to what was seen before */}
      {activeSection === 'behaviour' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px', fontSize: '0.75rem', color: '#94a3b8' }}>
            <div><strong>Sender previously seen:</strong> <span style={{ color: behavioral.known_sender ? '#10b981' : '#f59e0b', fontWeight: 600 }}>{behavioral.known_sender ? 'Yes' : 'No — first contact'}</span></div>
            <div style={{ marginTop: '4px' }}><strong>Messages seen from this sender:</strong> {behavioral.messages_seen_from_sender ?? 0}</div>
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: '#64748b' }}>{behavioral.limitation}</div>
          </div>

          {(behavioral.signals || []).length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>
              No behavioural deviation was identified against observed sender history.
            </div>
          ) : behavioral.signals.map((signal, idx) => (
            <div key={`${signal.type}-${idx}`} style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '10px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                <span style={{ color: '#f8fafc', fontSize: '0.8rem', fontWeight: 600 }}>{signal.type.replace(/_/g, ' ')}</span>
                <span style={{ color: signal.severity === 'HIGH' ? '#ef4444' : signal.severity === 'MEDIUM' ? '#f59e0b' : '#94a3b8', fontSize: '0.68rem' }}>
                  {signal.severity} • {Math.round(signal.confidence * 100)}%
                </span>
              </div>
              <div style={{ fontSize: '0.73rem', color: '#94a3b8', marginTop: '4px', lineHeight: 1.5 }}>{signal.explanation}</div>
            </div>
          ))}

          {/* What the system learned, and why it scored this message that way */}
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Learned-pattern match</h4>
            {adaptive.status !== 'SCORED' ? (
              <div style={{ fontSize: '0.73rem', color: '#64748b', fontStyle: 'italic' }}>
                {adaptive.limitation || 'Adaptive learning has not scored this message.'}
              </div>
            ) : (
              <>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  Similarity to previously confirmed mail: <strong style={{ color: '#f8fafc' }}>{Math.round(adaptive.score * 100)}%</strong>
                  {' '}across {adaptive.matched_characteristics} characteristic(s), learned from {adaptive.learned_from.malicious} malicious
                  and {adaptive.learned_from.legitimate} legitimate example(s).
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '8px' }}>
                  {(adaptive.contributions || []).slice(0, 8).map(c => (
                    <div key={c.characteristic} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', fontSize: '0.7rem', color: '#94a3b8' }}>
                      <span className="font-mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.characteristic}</span>
                      <span style={{ whiteSpace: 'nowrap', color: c.weight > 0 ? '#ef4444' : '#10b981' }}>
                        {c.weight > 0 ? '+' : ''}{c.weight} ({c.seen_in_malicious}M / {c.seen_in_legitimate}L)
                      </span>
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: '0.69rem', color: '#64748b', marginTop: '8px', fontStyle: 'italic' }}>{adaptive.limitation}</div>
              </>
            )}
          </div>
        </div>
      )}

      {/* THREAT INTELLIGENCE SECTION */}
      {activeSection === 'threatintel' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px', fontSize: '0.75rem', color: '#94a3b8' }}>
            <div><strong>Feed state:</strong> {threatIntel.feed_state?.synced ? `synced ${threatIntel.feed_state.age_hours}h ago` : 'no feed data'}</div>
            {threatIntel.feed_state?.indicator_totals && (
              <div style={{ marginTop: '4px' }}>
                <strong>Indicators held locally:</strong>{' '}
                {threatIntel.feed_state.indicator_totals.urls} URLs, {threatIntel.feed_state.indicator_totals.domains} domains,{' '}
                {threatIntel.feed_state.indicator_totals.ips} IPs, {threatIntel.feed_state.indicator_totals.netblocks} netblocks
              </div>
            )}
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: '#64748b' }}>{threatIntel.limitation}</div>
          </div>

          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Indicator matches</h4>
            {(threatIntel.matches || []).length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic' }}>
                No indicator from this message matched a known-bad list. That means nothing is known about them, not that they are safe.
              </div>
            ) : threatIntel.matches.map((match, idx) => (
              <div key={idx} style={{ backgroundColor: '#131b2e', borderRadius: '4px', padding: '8px 10px', marginBottom: '5px', borderLeft: '3px solid #ef4444' }}>
                <div style={{ fontSize: '0.74rem', color: '#f8fafc', fontWeight: 600 }}>
                  {match.indicator_type} — {match.matched.replace(/_/g, ' ').toLowerCase()}
                </div>
                <div className="font-mono" style={{ fontSize: '0.7rem', color: '#ef4444', marginTop: '2px', wordBreak: 'break-all' }}>{match.indicator}</div>
                <div style={{ fontSize: '0.68rem', color: '#94a3b8', marginTop: '2px' }}>Source feed: {match.feed}</div>
              </div>
            ))}
          </div>

          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Domain registration age</h4>
            {(threatIntel.domain_ages || []).length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic' }}>No domain age data was resolved for this message.</div>
            ) : threatIntel.domain_ages.map(entry => (
              <div key={entry.domain} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', fontSize: '0.73rem', color: '#94a3b8', padding: '4px 0' }}>
                <span className="font-mono" style={{ color: '#f8fafc' }}>
                  {entry.domain}{entry.is_sender_domain ? ' (sender)' : ''}
                </span>
                <span style={{ color: entry.age_days !== null && entry.age_days <= 30 ? '#ef4444' : '#94a3b8', whiteSpace: 'nowrap' }}>
                  {entry.status === 'AVAILABLE' ? `${entry.age_days} days old` : `unavailable${entry.reason ? ` — ${entry.reason}` : ''}`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* INFRASTRUCTURE SECTION */}
      {activeSection === 'infrastructure' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <ThreatMap infrastructure={selectedCase.infrastructure} />
          <RelayTimeline relays={selectedCase.forensics?.smtp_relay} />
        </div>
      )}

      {/* EXPLAINABLE NLP SECTION */}
      {activeSection === 'nlp' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px', fontSize: '0.75rem', color: '#94a3b8' }}>
            <div><strong>Analysis Engine:</strong> {nlp.engine || 'Not analyzed'}</div>
            <div style={{ marginTop: '4px' }}><strong>Language Signal Score:</strong> {Math.round((nlp.score || 0) * 100)}%</div>
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: '#64748b' }}>{nlp.limitation || 'Language analysis is supporting evidence only.'}</div>
          </div>
          {nlp.signals.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>No supported social-engineering language signals were identified.</div>
          ) : nlp.signals.map((signal, idx) => (
            <div key={`${signal.type}-${idx}`} style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '10px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                <span style={{ color: '#f8fafc', fontSize: '0.8rem', fontWeight: 600 }}>{signal.type.replace(/_/g, ' ')}</span>
                <span style={{ color: signal.severity === 'HIGH' ? '#ef4444' : '#f59e0b', fontSize: '0.68rem' }}>{signal.severity} • {Math.round(signal.confidence * 100)}%</span>
              </div>
              <div style={{ color: '#94a3b8', fontSize: '0.72rem', marginTop: '5px' }}>{signal.explanation}</div>
              <div className="font-mono" style={{ color: '#3b82f6', fontSize: '0.7rem', marginTop: '6px' }}>Matched terms: {signal.matched_terms.join(', ')}</div>
            </div>
          ))}
        </div>
      )}

      {/* EVIDENCE SECTION */}
      {activeSection === 'evidence' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {evidence.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>No forensic evidence items generated.</div>
          ) : (
            evidence.map((ev, idx) => (
              <div key={idx} style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '10px 12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>{ev.finding}</span>
                  <span style={{ fontSize: '0.68rem', color: '#94a3b8' }}>{ev.severity} • {ev.source}</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginBottom: '6px' }}>{ev.explanation}</div>

                <button
                  onClick={() => toggleEvidenceExpand(idx)}
                  style={{ backgroundColor: 'transparent', border: 'none', color: '#3b82f6', fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', padding: 0 }}
                >
                  {expandedEvidence[idx] ? <ChevronDown size={12} /> : <ChevronRight size={12} />} View technical evidence
                </button>

                {expandedEvidence[idx] && (
                  <div className="font-mono" style={{ fontSize: '0.68rem', color: '#94a3b8', backgroundColor: '#090d16', padding: '8px 10px', borderRadius: '4px', marginTop: '6px' }}>
                    <div>Type: {ev.evidence_type}</div>
                    <div>Source Reference: {ev.provenance?.source_reference || 'N/A'}</div>
                    <div>Confidence: {Math.round(ev.confidence * 100)}%</div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* IOCS SECTION */}
      {activeSection === 'iocs' && (
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.75rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div><strong>IP Addresses:</strong> <span className="font-mono" style={{ color: '#3b82f6' }}>{iocs.ips?.length > 0 ? iocs.ips.join(', ') : 'None extracted'}</span></div>
          <div><strong>Domains:</strong> <span className="font-mono" style={{ color: '#f59e0b' }}>{iocs.domains?.length > 0 ? iocs.domains.join(', ') : 'None extracted'}</span></div>
          <div><strong>URLs:</strong> <span className="font-mono" style={{ color: '#10b981' }}>{iocs.urls?.length > 0 ? iocs.urls.join(', ') : 'None extracted'}</span></div>
        </div>
      )}

      {/* ATTACHMENT FORENSICS SECTION */}
      {activeSection === 'attachments' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {attachments.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: '0.78rem', fontStyle: 'italic' }}>No MIME attachments were identified.</div>
          ) : attachments.map((attachment, idx) => (
            <div key={`${attachment.sha256}-${idx}`} style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '10px 12px', fontSize: '0.74rem', color: '#94a3b8' }}>
              <div style={{ color: '#f8fafc', fontWeight: 600 }}>{attachment.file_name}</div>
              <div style={{ marginTop: '5px' }}>MIME: {attachment.mime_type} · Size: {attachment.size_bytes} bytes · Extension: {attachment.extension || 'none'}</div>
              <div className="font-mono" style={{ color: '#3b82f6', marginTop: '5px', overflowWrap: 'anywhere' }}>SHA-256: {attachment.sha256}</div>
              <div style={{ color: '#64748b', fontStyle: 'italic', marginTop: '5px' }}>{attachment.limitation}</div>
            </div>
          ))}
        </div>
      )}

      {/* CAMPAIGN SECTION */}
      {activeSection === 'campaign' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.75rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div><strong>Campaign ID:</strong> <span className="font-mono" style={{ color: '#8b5cf6', fontWeight: 700 }}>{campaign.campaign_id || 'UNASSOCIATED'}</span></div>
            <div><strong>Association Status:</strong> {campaignAssoc.status || 'UNASSOCIATED'} ({Math.round((campaignAssoc.confidence || 0) * 100)}%)</div>
            <div><strong>Correlated Cases:</strong> {(campaignAssoc.related_cases || []).join(', ') || 'None'}</div>
            <div><strong>Attacker Attribution:</strong> <span style={{ color: '#ec4899', fontWeight: 600 }}>INSUFFICIENT EVIDENCE</span></div>
          </div>

          {(campaignAssoc.factors || []).length > 0 && (
            <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Why these cases are linked</h4>
              {campaignAssoc.factors.map((factor, idx) => (
                <div key={idx} style={{ backgroundColor: '#131b2e', borderRadius: '4px', padding: '8px 10px', marginBottom: '5px', borderLeft: '3px solid #8b5cf6' }}>
                  <div style={{ fontSize: '0.74rem', color: '#f8fafc', fontWeight: 600 }}>{factor.factor.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: '0.71rem', color: '#94a3b8', marginTop: '2px' }}>{factor.evidence}</div>
                </div>
              ))}
              {(campaignAssoc.scoring || []).length > 0 && (
                <div style={{ fontSize: '0.69rem', color: '#64748b', marginTop: '6px' }}>
                  Scoring by family: {campaignAssoc.scoring.map(s => `${s.family} ${s.contribution}`).join(' · ')}
                  {' '}— the strongest factor in each family counts in full, further ones at reducing weight.
                </div>
              )}
            </div>
          )}

          {/* Deliberately not linked. An analyst asking why two similar-looking
              cases were not grouped deserves the reason. */}
          {(campaignAssoc.suppressed_factors || []).length > 0 && (
            <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #334155', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Links deliberately not made</h4>
              {campaignAssoc.suppressed_factors.map((s, idx) => (
                <div key={idx} style={{ fontSize: '0.72rem', color: '#94a3b8', padding: '4px 0', borderBottom: idx < campaignAssoc.suppressed_factors.length - 1 ? '1px solid #1e293b' : 'none' }}>
                  <span className="font-mono" style={{ color: '#cbd5e1' }}>{s.indicator}</span> — {s.reason}
                </div>
              ))}
            </div>
          )}

          {(campaignAssoc.semantic_matches || []).length > 0 && (
            <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: '#f8fafc', fontWeight: 600 }}>Messages reusing the same wording</h4>
              {campaignAssoc.semantic_matches.map(match => (
                <div key={match.case_id} style={{ fontSize: '0.72rem', color: '#94a3b8', padding: '5px 0' }}>
                  <span className="font-mono" style={{ color: '#3b82f6' }}>{match.case_id}</span>
                  {' '}<strong style={{ color: '#f8fafc' }}>{Math.round(match.similarity * 100)}%</strong> similar — “{match.subject}”
                  <div style={{ color: '#64748b', fontSize: '0.68rem' }}>Shared terms: {match.shared_terms.join(', ')}</div>
                </div>
              ))}
            </div>
          )}

          <div style={{ fontSize: '0.7rem', color: '#64748b', fontStyle: 'italic', lineHeight: 1.5 }}>
            {campaignAssoc.limitation || 'Campaign association supports pattern analysis but does not establish actor identity.'}
          </div>
        </div>
      )}

      {/* TIMELINE SECTION */}
      {activeSection === 'timeline' && (
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.75rem', color: '#94a3b8' }}>
          <div><strong>Delivered Timestamp:</strong> {new Date(selectedCase.message?.delivered_at || selectedCase.timestamps?.ingested_at).toLocaleString()}</div>
          <div><strong>Processed Timestamp:</strong> {selectedCase.timestamps?.ingested_at}</div>
        </div>
      )}

      {/* RESPONSE SECTION */}
      {activeSection === 'response' && (
        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.75rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div><strong>Remediation Status:</strong> <span style={{ color: selectedCase.remediation?.status === 'QUARANTINED' ? '#10b981' : '#f59e0b', fontWeight: 700 }}>{selectedCase.remediation?.status || 'NO ACTION'}</span></div>
          <div><strong>Policy Matched:</strong> {selectedCase.remediation?.policy_matched || 'None'}</div>
        </div>
      )}
    </div>
  );
}
