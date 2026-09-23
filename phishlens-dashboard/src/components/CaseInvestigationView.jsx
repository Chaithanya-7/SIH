import React, { useState } from 'react';
import { FileText, ChevronDown, ChevronRight, AlertCircle, Shield, Key, Globe, Network, Activity } from 'lucide-react';
import ConfidenceCard from './ConfidenceCard';
import AnalysisModeNotice, { AnalysisModeBadge } from './AnalysisModeNotice';
import RelayTimeline from './RelayTimeline';
import ThreatMap from './ThreatMap';

export default function CaseInvestigationView({ selectedCase, onOpenReport }) {
  const [activeSection, setActiveSection] = useState('overview');
  const [expandedEvidence, setExpandedEvidence] = useState({});
  const [expandedAuth, setExpandedAuth] = useState(false);

  if (!selectedCase) {
    return (
      <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '6px', border: '1px solid var(--border)', padding: '48px', textAlign: 'center', color: 'var(--text-dim)' }}>
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
  const qr = selectedCase.qr || null;
  const arc = selectedCase.forensics?.arc || null;
  const nlp = selectedCase.nlp || { status: 'NOT_ANALYZED', signals: [], score: 0 };
  const behavioral = selectedCase.behavioral || { status: 'NOT_ANALYZED', signals: [] };
  const adaptive = selectedCase.adaptive || { status: 'NOT_SCORED', contributions: [] };
  const threatIntel = selectedCase.threat_intelligence || { status: 'NOT_ANALYZED', matches: [], domain_ages: [] };
  const verdict = detection.verdict || 'UNKNOWN';

  let verdictBg = 'var(--tint-neutral)';
  let verdictColor = 'var(--text-muted)';
  if (verdict === 'HIGH_RISK') { verdictBg = 'var(--tint-danger)'; verdictColor = 'var(--danger)'; }
  else if (verdict === 'SUSPICIOUS') { verdictBg = 'var(--tint-warning)'; verdictColor = 'var(--warning)'; }
  else if (verdict === 'SAFE') { verdictBg = 'var(--tint-success)'; verdictColor = 'var(--success)'; }

  const toggleEvidenceExpand = (idx) => {
    setExpandedEvidence(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  const renderAuthBadge = (protocol, status) => {
    const st = (status || 'unknown').toLowerCase();
    let bg = 'var(--tint-neutral)';
    let color = 'var(--text-muted)';
    let iconLabel = 'Neutral';

    if (st === 'pass') {
      bg = 'var(--tint-success)';
      color = 'var(--success)';
      iconLabel = 'Passed';
    } else if (st === 'fail') {
      bg = 'var(--tint-danger)';
      color = 'var(--danger)';
      iconLabel = 'Failed';
    }

    return (
      <div style={{ flex: 1, backgroundColor: 'var(--bg-panel)', borderRadius: '6px', padding: '10px 14px', border: '1px solid var(--border)' }}>
        <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>{protocol}</div>
        <div style={{ fontSize: '0.88rem', fontWeight: 700, color, marginTop: '2px', textTransform: 'capitalize' }}>
          {st === 'fail' ? '✕ Failed' : st === 'pass' ? '✓ Passed' : '— Unknown'}
        </div>
      </div>
    );
  };

  return (
    <div className="animate-fade-in" style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '6px', border: '1px solid var(--border)', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Case Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border)', paddingBottom: '16px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="font-mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent)' }}>{selectedCase.case_id}</span>
            <span style={{ backgroundColor: verdictBg, color: verdictColor, fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase' }}>
              {verdict.replace('_', ' ')}
            </span>
            {detection.external_provider_result?.attempted && detection.external_provider_result?.status !== 'RESPONDED' && (
              <span style={{ backgroundColor: 'var(--tint-warning)', color: 'var(--warning)', fontSize: '0.65rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--warning)' }}>
                EXTERNAL PROVIDER UNAVAILABLE (NATIVE DETECTION ONLY)
              </span>
            )}
            {/* Beside the verdict, because that is where the eye lands. A safe
                verdict from a backlog scan rests on fewer checks than a live
                one, and the two must not be read as the same reassurance. */}
            <AnalysisModeBadge analysisMode={selectedCase.analysis_mode} />
          </div>
          <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {selectedCase.message?.subject || '(No Subject)'}
          </h2>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
            <span>From: <strong style={{ color: 'var(--text-primary)' }}>{selectedCase.message?.sender}</strong></span>
            <span>→ Recipient: <strong style={{ color: 'var(--text-primary)' }}>{selectedCase.message?.recipient}</strong></span>
            <span>Received: <strong style={{ color: 'var(--text-muted)' }}>{new Date(selectedCase.message?.delivered_at || selectedCase.timestamps?.ingested_at).toLocaleString()}</strong></span>
          </div>
        </div>

        <button
          onClick={onOpenReport}
          style={{ backgroundColor: 'var(--accent)', color: '#fff', border: 'none', borderRadius: '4px', padding: '7px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <FileText size={14} /> Forensic Report
        </button>
      </div>

      {/* 2. What this verdict rests on, before the verdict's number is shown.
             Deliberately above the confidence card: a qualification placed
             after the score is read after the score has already been believed. */}
      <AnalysisModeNotice analysisMode={selectedCase.analysis_mode} />

      {/* 3. Compact Summary Metrics Bar */}
      <ConfidenceCard confidence={selectedCase.confidence} executiveContext={selectedCase.executive_context} />

      {/* 3. Section Tabs */}
      <div style={{ display: 'flex', gap: '4px', borderBottom: '1px solid var(--border)', paddingBottom: '8px', overflowX: 'auto' }}>
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
              backgroundColor: activeSection === tab.id ? 'var(--border)' : 'transparent',
              color: activeSection === tab.id ? 'var(--accent)' : 'var(--text-muted)',
              border: activeSection === tab.id ? '1px solid var(--accent)' : '1px solid transparent',
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
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>Message Identity Summary</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <div><strong>Sender Address:</strong> <span style={{ color: 'var(--text-primary)' }}>{selectedCase.message?.sender}</span></div>
              <div><strong>Envelope Recipient:</strong> <span style={{ color: 'var(--text-primary)' }}>{selectedCase.message?.recipient}</span></div>
              <div><strong>SHA-256 Hash:</strong> <span className="font-mono" style={{ color: 'var(--accent)', fontSize: '0.7rem' }}>{selectedCase.message?.raw_hash}</span></div>
              <div><strong>Return-Path Mismatch:</strong> <span style={{ color: selectedCase.forensics?.return_path_mismatch ? 'var(--danger)' : 'var(--success)', fontWeight: 600 }}>{selectedCase.forensics?.return_path_mismatch ? 'YES (SUSPICIOUS)' : 'NO'}</span></div>
            </div>
          </div>

          {/* Key Findings List */}
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>Top Threat Evidence Items</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {evidence.slice(0, 3).map((ev, idx) => (
                <div key={idx} style={{ backgroundColor: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', borderLeft: ev.severity === 'HIGH' ? '3px solid var(--danger)' : '3px solid var(--warning)' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>{ev.finding}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>{ev.explanation}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DETECTION SECTION */}
      {activeSection === 'detection' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div><strong>Detection Verdict:</strong> <span style={{ color: verdictColor, fontWeight: 700 }}>{verdict}</span></div>
            <div><strong>Verification Status:</strong> <span style={{ color: 'var(--success)', fontWeight: 700 }}>{detection.verification_status || 'PENDING_NATIVE_ANALYSIS'}</span></div>
            <div><strong>Detection Provider:</strong> <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{detection.provider || 'PHISHLENS_NATIVE_MQL'}</span></div>
            <div><strong>Rules Evaluated / Matched:</strong> {detection.rule_engine ? `${detection.rule_engine.rules_evaluated} evaluated, ${detection.rule_engine.rules_matched} matched` : 'Not yet evaluated'}</div>
            {detection.external_provider_result?.attempted && (
              <div>
                <strong>External Provider Cross-Check ({detection.external_provider_result.provider}):</strong>{' '}
                <span style={{ color: detection.external_provider_result.status === 'RESPONDED' ? 'var(--success)' : 'var(--warning)' }}>
                  {detection.external_provider_result.status}
                </span>
                {detection.external_provider_result.claimed_verdict && ` — claimed verdict: ${detection.external_provider_result.claimed_verdict}`}
                <div style={{ marginTop: '2px', fontStyle: 'italic', color: 'var(--text-dim)' }}>{detection.external_provider_result.note}</div>
              </div>
            )}
          </div>

          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>Matched MQL Rules</h4>
            {(detection.matched_rules || []).length === 0 ? (
              <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>No native detection rules matched this message.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {detection.matched_rules.map(rule => (
                  <div key={rule.id} style={{ backgroundColor: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', borderLeft: rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? '3px solid var(--danger)' : '3px solid var(--warning)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                      <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>{rule.id} — {rule.name}</span>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{rule.severity} • {Math.round(rule.confidence * 100)}%</span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>{rule.matched_because}</div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '2px', fontStyle: 'italic' }}>Source: {rule.source}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Techniques as identifiers an analyst can carry to another tool,
              each showing which rules attributed it so it can be questioned. */}
          {(detection.attack_patterns || []).length > 0 && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
              <h4 style={{ margin: '0 0 4px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>Attack techniques (MITRE ATT&amp;CK)</h4>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
                Attributed from the rules that matched. Each is shown with the rules responsible, so the attribution can be checked rather than taken on trust.
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {detection.attack_patterns.map(pattern => (
                  <div key={pattern.technique} style={{ display: 'flex', alignItems: 'baseline', gap: '10px', backgroundColor: 'var(--bg-surface)', padding: '7px 10px', borderRadius: '4px' }}>
                    <code style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-soft)' }}>{pattern.technique}</code>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-primary)', flex: 1 }}>{pattern.name || 'Technique name not held locally'}</span>
                    <span style={{ fontSize: '0.66rem', color: 'var(--text-dim)' }}>{pattern.attributed_by.join(', ')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* A QR code is a link nobody can read off the screen. If one was
              decoded, the destination is the single most important thing on
              this page - so it is shown in full rather than summarised. */}
          {qr && (qr.codes_found > 0 || (qr.not_scanned || []).length > 0) && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
              <h4 style={{ margin: '0 0 4px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>QR codes in attachments</h4>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
                Decoded locally from the attached images. A link inside a code appears nowhere in the message text, and is usually opened on a phone rather than the managed device.
              </div>

              {(qr.codes || []).map((code, i) => (
                <div key={i} style={{ backgroundColor: 'var(--bg-surface)', padding: '9px 10px', borderRadius: '4px', marginBottom: '6px', borderLeft: '3px solid var(--warning)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', marginBottom: '3px' }}>
                    <span style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-primary)' }}>{code.filename}</span>
                    <span style={{ fontSize: '0.66rem', color: 'var(--text-dim)' }}>
                      {code.dimensions} · {code.payload_kind.replace(/_/g, ' ')}{code.polarity === 'inverted' ? ' · inverted' : ''}
                    </span>
                  </div>
                  <code style={{ display: 'block', fontSize: '0.71rem', color: 'var(--accent-soft)', wordBreak: 'break-all', backgroundColor: 'var(--bg-code)', padding: '5px 7px', borderRadius: '3px' }}>
                    {code.payload}
                  </code>
                </div>
              ))}

              {(qr.not_scanned || []).map((item, i) => (
                <div key={`ns-${i}`} style={{ fontSize: '0.71rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                  <strong style={{ color: 'var(--text-muted)' }}>{item.filename}</strong> — {item.reason}
                </div>
              ))}
            </div>
          )}

          {/* Shown only when a chain exists, and worded so a passing chain
              cannot be read as reassurance. */}
          {arc && arc.status !== 'ABSENT' && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px' }}>
              <h4 style={{ margin: '0 0 4px 0', fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                Forwarding chain (ARC) — {arc.status === 'SEALED' ? 'structurally valid' : 'malformed'}
              </h4>
              <div style={{ fontSize: '0.73rem', color: 'var(--text-secondary)', marginBottom: '8px', lineHeight: 1.5 }}>{arc.explanation}</div>
              {(arc.intermediaries || []).map(hop => (
                <div key={hop.instance} style={{ fontSize: '0.72rem', color: 'var(--text-muted)', backgroundColor: 'var(--bg-surface)', padding: '6px 9px', borderRadius: '4px', marginBottom: '4px' }}>
                  <strong style={{ color: 'var(--text-primary)' }}>i={hop.instance}</strong> {hop.signing_domain || 'unnamed'}
                  {hop.authentication_seen && ` — saw spf=${hop.authentication_seen.spf || 'n/a'}, dkim=${hop.authentication_seen.dkim || 'n/a'}`}
                </div>
              ))}
              <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontStyle: 'italic', marginTop: '6px' }}>{arc.risk_note}</div>
            </div>
          )}
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

          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
            <button
              onClick={() => setExpandedAuth(!expandedAuth)}
              style={{ backgroundColor: 'transparent', border: 'none', color: 'var(--accent)', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              {expandedAuth ? <ChevronDown size={14} /> : <ChevronRight size={14} />} View Technical Authentication Details
            </button>
            {expandedAuth && (
              <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '8px', whiteSpace: 'pre-wrap', backgroundColor: 'var(--bg-code)', padding: '10px', borderRadius: '4px' }}>
                {JSON.stringify(auth, null, 2)}
              </div>
            )}
          </div>
        </div>
      )}

      {/* BEHAVIOURAL SECTION — how this message compares to what was seen before */}
      {activeSection === 'behaviour' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div><strong>Sender previously seen:</strong> <span style={{ color: behavioral.known_sender ? 'var(--success)' : 'var(--warning)', fontWeight: 600 }}>{behavioral.known_sender ? 'Yes' : 'No — first contact'}</span></div>
            <div style={{ marginTop: '4px' }}><strong>Messages seen from this sender:</strong> {behavioral.messages_seen_from_sender ?? 0}</div>
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: 'var(--text-dim)' }}>{behavioral.limitation}</div>
          </div>

          {(behavioral.signals || []).length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>
              No behavioural deviation was identified against observed sender history.
            </div>
          ) : behavioral.signals.map((signal, idx) => (
            <div key={`${signal.type}-${idx}`} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                <span style={{ color: 'var(--text-primary)', fontSize: '0.8rem', fontWeight: 600 }}>{signal.type.replace(/_/g, ' ')}</span>
                <span style={{ color: signal.severity === 'HIGH' ? 'var(--danger)' : signal.severity === 'MEDIUM' ? 'var(--warning)' : 'var(--text-muted)', fontSize: '0.68rem' }}>
                  {signal.severity} • {Math.round(signal.confidence * 100)}%
                </span>
              </div>
              <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginTop: '4px', lineHeight: 1.5 }}>{signal.explanation}</div>
            </div>
          ))}

          {/* What the system learned, and why it scored this message that way */}
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Learned-pattern match</h4>
            {adaptive.status !== 'SCORED' ? (
              <div style={{ fontSize: '0.73rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                {adaptive.limitation || 'Adaptive learning has not scored this message.'}
              </div>
            ) : (
              <>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Similarity to previously confirmed mail: <strong style={{ color: 'var(--text-primary)' }}>{Math.round(adaptive.score * 100)}%</strong>
                  {' '}across {adaptive.matched_characteristics} characteristic(s), learned from {adaptive.learned_from.malicious} malicious
                  and {adaptive.learned_from.legitimate} legitimate example(s).
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '8px' }}>
                  {(adaptive.contributions || []).slice(0, 8).map(c => (
                    <div key={c.characteristic} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      <span className="font-mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.characteristic}</span>
                      <span style={{ whiteSpace: 'nowrap', color: c.weight > 0 ? 'var(--danger)' : 'var(--success)' }}>
                        {c.weight > 0 ? '+' : ''}{c.weight} ({c.seen_in_malicious}M / {c.seen_in_legitimate}L)
                      </span>
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: '0.69rem', color: 'var(--text-dim)', marginTop: '8px', fontStyle: 'italic' }}>{adaptive.limitation}</div>
              </>
            )}
          </div>
        </div>
      )}

      {/* THREAT INTELLIGENCE SECTION */}
      {activeSection === 'threatintel' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div><strong>Feed state:</strong> {threatIntel.feed_state?.synced ? `synced ${threatIntel.feed_state.age_hours}h ago` : 'no feed data'}</div>
            {threatIntel.feed_state?.indicator_totals && (
              <div style={{ marginTop: '4px' }}>
                <strong>Indicators held locally:</strong>{' '}
                {threatIntel.feed_state.indicator_totals.urls} URLs, {threatIntel.feed_state.indicator_totals.domains} domains,{' '}
                {threatIntel.feed_state.indicator_totals.ips} IPs, {threatIntel.feed_state.indicator_totals.netblocks} netblocks
              </div>
            )}
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: 'var(--text-dim)' }}>{threatIntel.limitation}</div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Indicator matches</h4>
            {(threatIntel.matches || []).length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                No indicator from this message matched a known-bad list. That means nothing is known about them, not that they are safe.
              </div>
            ) : threatIntel.matches.map((match, idx) => (
              <div key={idx} style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '4px', padding: '8px 10px', marginBottom: '5px', borderLeft: '3px solid var(--danger)' }}>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                  {match.indicator_type} — {match.matched.replace(/_/g, ' ').toLowerCase()}
                </div>
                <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--danger)', marginTop: '2px', wordBreak: 'break-all' }}>{match.indicator}</div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '2px' }}>Source feed: {match.feed}</div>
              </div>
            ))}
          </div>

          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Domain registration age</h4>
            {(threatIntel.domain_ages || []).length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>No domain age data was resolved for this message.</div>
            ) : threatIntel.domain_ages.map(entry => (
              <div key={entry.domain} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', fontSize: '0.73rem', color: 'var(--text-muted)', padding: '4px 0' }}>
                <span className="font-mono" style={{ color: 'var(--text-primary)' }}>
                  {entry.domain}{entry.is_sender_domain ? ' (sender)' : ''}
                </span>
                <span style={{ color: entry.age_days !== null && entry.age_days <= 30 ? 'var(--danger)' : 'var(--text-muted)', whiteSpace: 'nowrap' }}>
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
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div><strong>Analysis Engine:</strong> {nlp.engine || 'Not analyzed'}</div>
            <div style={{ marginTop: '4px' }}><strong>Language Signal Score:</strong> {Math.round((nlp.score || 0) * 100)}%</div>
            <div style={{ marginTop: '6px', fontStyle: 'italic', color: 'var(--text-dim)' }}>{nlp.limitation || 'Language analysis is supporting evidence only.'}</div>
          </div>
          {nlp.signals.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>No supported social-engineering language signals were identified.</div>
          ) : nlp.signals.map((signal, idx) => (
            <div key={`${signal.type}-${idx}`} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                <span style={{ color: 'var(--text-primary)', fontSize: '0.8rem', fontWeight: 600 }}>{signal.type.replace(/_/g, ' ')}</span>
                <span style={{ color: signal.severity === 'HIGH' ? 'var(--danger)' : 'var(--warning)', fontSize: '0.68rem' }}>{signal.severity} • {Math.round(signal.confidence * 100)}%</span>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: '5px' }}>{signal.explanation}</div>
              <div className="font-mono" style={{ color: 'var(--accent)', fontSize: '0.7rem', marginTop: '6px' }}>Matched terms: {signal.matched_terms.join(', ')}</div>
            </div>
          ))}
        </div>
      )}

      {/* EVIDENCE SECTION */}
      {activeSection === 'evidence' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {evidence.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>No forensic evidence items generated.</div>
          ) : (
            evidence.map((ev, idx) => (
              <div key={idx} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{ev.finding}</span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{ev.severity} • {ev.source}</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '6px' }}>{ev.explanation}</div>

                <button
                  onClick={() => toggleEvidenceExpand(idx)}
                  style={{ backgroundColor: 'transparent', border: 'none', color: 'var(--accent)', fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', padding: 0 }}
                >
                  {expandedEvidence[idx] ? <ChevronDown size={12} /> : <ChevronRight size={12} />} View technical evidence
                </button>

                {expandedEvidence[idx] && (
                  <div className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)', backgroundColor: 'var(--bg-code)', padding: '8px 10px', borderRadius: '4px', marginTop: '6px' }}>
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
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div><strong>IP Addresses:</strong> <span className="font-mono" style={{ color: 'var(--accent)' }}>{iocs.ips?.length > 0 ? iocs.ips.join(', ') : 'None extracted'}</span></div>
          <div><strong>Domains:</strong> <span className="font-mono" style={{ color: 'var(--warning)' }}>{iocs.domains?.length > 0 ? iocs.domains.join(', ') : 'None extracted'}</span></div>
          <div><strong>URLs:</strong> <span className="font-mono" style={{ color: 'var(--success)' }}>{iocs.urls?.length > 0 ? iocs.urls.join(', ') : 'None extracted'}</span></div>
        </div>
      )}

      {/* ATTACHMENT FORENSICS SECTION */}
      {activeSection === 'attachments' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {attachments.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic' }}>No MIME attachments were identified.</div>
          ) : attachments.map((attachment, idx) => (
            <div key={`${attachment.sha256}-${idx}`} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{attachment.file_name}</div>
              <div style={{ marginTop: '5px' }}>MIME: {attachment.mime_type} · Size: {attachment.size_bytes} bytes · Extension: {attachment.extension || 'none'}</div>
              <div className="font-mono" style={{ color: 'var(--accent)', marginTop: '5px', overflowWrap: 'anywhere' }}>SHA-256: {attachment.sha256}</div>
              <div style={{ color: 'var(--text-dim)', fontStyle: 'italic', marginTop: '5px' }}>{attachment.limitation}</div>
            </div>
          ))}
        </div>
      )}

      {/* CAMPAIGN SECTION */}
      {activeSection === 'campaign' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div><strong>Campaign ID:</strong> <span className="font-mono" style={{ color: 'var(--violet)', fontWeight: 700 }}>{campaign.campaign_id || 'UNASSOCIATED'}</span></div>
            <div><strong>Association Status:</strong> {campaignAssoc.status || 'UNASSOCIATED'} ({Math.round((campaignAssoc.confidence || 0) * 100)}%)</div>
            <div><strong>Correlated Cases:</strong> {(campaignAssoc.related_cases || []).join(', ') || 'None'}</div>
            <div><strong>Attacker Attribution:</strong> <span style={{ color: 'var(--pink)', fontWeight: 600 }}>INSUFFICIENT EVIDENCE</span></div>
          </div>

          {(campaignAssoc.factors || []).length > 0 && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Why these cases are linked</h4>
              {campaignAssoc.factors.map((factor, idx) => (
                <div key={idx} style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '4px', padding: '8px 10px', marginBottom: '5px', borderLeft: '3px solid var(--violet)' }}>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-primary)', fontWeight: 600 }}>{factor.factor.replace(/_/g, ' ')}</div>
                  <div style={{ fontSize: '0.71rem', color: 'var(--text-muted)', marginTop: '2px' }}>{factor.evidence}</div>
                </div>
              ))}
              {(campaignAssoc.scoring || []).length > 0 && (
                <div style={{ fontSize: '0.69rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                  Scoring by family: {campaignAssoc.scoring.map(s => `${s.family} ${s.contribution}`).join(' · ')}
                  {' '}— the strongest factor in each family counts in full, further ones at reducing weight.
                </div>
              )}
            </div>
          )}

          {/* Deliberately not linked. An analyst asking why two similar-looking
              cases were not grouped deserves the reason. */}
          {(campaignAssoc.suppressed_factors || []).length > 0 && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border-strong)', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Links deliberately not made</h4>
              {campaignAssoc.suppressed_factors.map((s, idx) => (
                <div key={idx} style={{ fontSize: '0.72rem', color: 'var(--text-muted)', padding: '4px 0', borderBottom: idx < campaignAssoc.suppressed_factors.length - 1 ? '1px solid var(--border)' : 'none' }}>
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{s.indicator}</span> — {s.reason}
                </div>
              ))}
            </div>
          )}

          {(campaignAssoc.semantic_matches || []).length > 0 && (
            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '12px' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>Messages reusing the same wording</h4>
              {campaignAssoc.semantic_matches.map(match => (
                <div key={match.case_id} style={{ fontSize: '0.72rem', color: 'var(--text-muted)', padding: '5px 0' }}>
                  <span className="font-mono" style={{ color: 'var(--accent)' }}>{match.case_id}</span>
                  {' '}<strong style={{ color: 'var(--text-primary)' }}>{Math.round(match.similarity * 100)}%</strong> similar — “{match.subject}”
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.68rem' }}>Shared terms: {match.shared_terms.join(', ')}</div>
                </div>
              ))}
            </div>
          )}

          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontStyle: 'italic', lineHeight: 1.5 }}>
            {campaignAssoc.limitation || 'Campaign association supports pattern analysis but does not establish actor identity.'}
          </div>
        </div>
      )}

      {/* TIMELINE SECTION */}
      {activeSection === 'timeline' && (
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <div><strong>Delivered Timestamp:</strong> {new Date(selectedCase.message?.delivered_at || selectedCase.timestamps?.ingested_at).toLocaleString()}</div>
          <div><strong>Processed Timestamp:</strong> {selectedCase.timestamps?.ingested_at}</div>
        </div>
      )}

      {/* RESPONSE SECTION */}
      {activeSection === 'response' && (
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div><strong>Remediation Status:</strong> <span style={{ color: selectedCase.remediation?.status === 'QUARANTINED' ? 'var(--success)' : 'var(--warning)', fontWeight: 700 }}>{selectedCase.remediation?.status || 'NO ACTION'}</span></div>
          <div><strong>Policy Matched:</strong> {selectedCase.remediation?.policy_matched || 'None'}</div>
        </div>
      )}
    </div>
  );
}
