import React, { useState } from 'react';
import { History, ChevronDown, ChevronRight } from 'lucide-react';

/**
 * Says when a verdict rests on less than a live one does.
 *
 * A backlog scan analyses mail that arrived months or years ago. Most of the
 * pipeline is unaffected by that - attachments, detection rules, concealed
 * text, payload shape, language, relay structure and thread integrity all read
 * the message as delivered, and are exactly as valid on a message from 2023 as
 * on one from this morning.
 *
 * But the checks that describe infrastructure could only describe it as it is
 * now. Domain registration age inverts outright: a domain three days old when
 * it attacked you is two years old today, so the signal that would have caught
 * it is precisely the one that cannot fire. Indicator feeds carry what is
 * malicious now and have long delisted what was malicious then. Addresses
 * change hands. Those checks are therefore not run at all, rather than run and
 * recorded as having found nothing.
 *
 * ## Why this component has to exist
 *
 * The backend already refuses to score a check it could not honestly perform.
 * That is only half the job: if the console then renders the result the same
 * way it renders a live one, a SAFE that rests on five fewer checks looks
 * exactly like a SAFE that rests on all of them - and somebody reads it as the
 * same reassurance.
 *
 * So the asymmetry is stated where the verdict is read. A high-risk verdict on
 * historical mail means what it always means, because every decisive finding is
 * time-independent. A safe one means less, and says so.
 */
export default function AnalysisModeNotice({ analysisMode }) {
  const [showChecks, setShowChecks] = useState(false);

  // Live analysis, or a case written before this field existed. Either way
  // there is nothing to qualify.
  if (!analysisMode || analysisMode.mode !== 'HISTORICAL') return null;

  const skipped = analysisMode.checks_not_applicable || [];

  return (
    <div
      style={{
        backgroundColor: 'var(--tint-warning)',
        border: '1px solid var(--warning)',
        borderRadius: '6px',
        padding: '12px 14px',
        display: 'flex',
        gap: '11px',
        alignItems: 'flex-start'
      }}
    >
      <History size={17} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: '1px' }} />

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--warning)', marginBottom: '4px' }}>
          Analysed after the fact
          {analysisMode.age_description ? ` — ${analysisMode.age_description}` : ''}
        </div>

        <div style={{ fontSize: '0.76rem', lineHeight: 1.55, color: 'var(--text-primary)' }}>
          {analysisMode.verdict_caveat}
        </div>

        {skipped.length > 0 && (
          <>
            <button
              onClick={() => setShowChecks(v => !v)}
              style={{
                marginTop: '8px',
                background: 'none',
                border: 'none',
                padding: 0,
                cursor: 'pointer',
                color: 'var(--warning)',
                fontSize: '0.73rem',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              {showChecks ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              {showChecks ? 'Hide' : 'Show'} the {skipped.length} check(s) that were not run
            </button>

            {showChecks && (
              <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '7px' }}>
                {skipped.map(entry => (
                  <div
                    key={entry.check}
                    style={{
                      backgroundColor: 'var(--bg-raised)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '7px 9px'
                    }}
                  >
                    <div
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        color: 'var(--text-primary)',
                        marginBottom: '3px'
                      }}
                    >
                      {entry.check.replace(/_/g, ' ')}
                    </div>
                    {/* The reason, not just the fact. "Not applicable" with no
                        explanation is the same dead end as a silent skip. */}
                    <div style={{ fontSize: '0.71rem', lineHeight: 1.5, color: 'var(--text-muted)' }}>
                      {entry.reason}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {analysisMode.remediation && (
          <div style={{ marginTop: '8px', fontSize: '0.71rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            {analysisMode.remediation}
          </div>
        )}
      </div>
    </div>
  );
}

/** The compact form, for a list where a full notice would not fit. */
export function AnalysisModeBadge({ analysisMode }) {
  if (!analysisMode || analysisMode.mode !== 'HISTORICAL') return null;

  return (
    <span
      title="Analysed after the fact. Checks that describe infrastructure were not run, because they could only describe it as it is now."
      style={{
        backgroundColor: 'var(--tint-warning)',
        color: 'var(--warning)',
        fontSize: '0.65rem',
        fontWeight: 700,
        padding: '2px 6px',
        borderRadius: '4px',
        border: '1px solid var(--warning)',
        whiteSpace: 'nowrap'
      }}
    >
      HISTORICAL SCAN
    </span>
  );
}
