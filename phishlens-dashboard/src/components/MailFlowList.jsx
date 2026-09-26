import React, { useState, useEffect, useMemo, useRef } from 'react';
import { CircleHelp, X } from 'lucide-react';
import { api } from '../services/api';
import { compileFilter, fieldSuggestions, FILTER_EXAMPLES, FIELDS } from '../services/displayFilter';

/**
 * Mail as a packet analyser would list it.
 *
 * ## What was taken from Wireshark, and why each part is there
 *
 * **The display filter bar, coloured by validity.** Green when the expression
 * compiles, red when it does not, with the reason beneath it. This is the single
 * most useful thing about Wireshark's interface: it tells you the filter is wrong
 * while you are typing, rather than showing you a confidently empty list. A
 * filter that failed open would be worse than none, because an analyst would
 * read "no dangerous mail" from an expression that never ran.
 *
 * **One dense monospace row per message, numbered from the first seen.**
 * Proportional type makes columns of addresses impossible to compare down a
 * page; a fixed pitch is why every packet tool has ever used one.
 *
 * **Rows tinted by significance.** Wireshark colours rows by rule so the eye
 * finds the interesting ones without reading. Here the rule is the verdict:
 * red for dangerous, yellow for suspicious, green for legitimate.
 *
 * **The detail tree under the list.** Selecting a row expands the journey the
 * message took, hop by hop, in the way Wireshark expands a frame into its
 * layers. The last hop is always this installation, and it is the only one whose
 * protocol and port are not somebody else's claim.
 *
 * ## Where this deliberately parts company with Wireshark
 *
 * A packet list promises that every column was observed on the wire. Mail is not
 * packets, and most of a message's journey happened before this system saw it.
 * A `Received:` header is free text and the great majority never record a port.
 *
 * So columns that cannot be filled honestly show a dash, and the header explains
 * which those are. Filling a port column for every row would have been easy and
 * would have looked far more convincing - and somebody would eventually have
 * quoted a number that was never real.
 */

/** Row tint and the coloured ball, from the verdict. */
const TONE = {
    RED: { ball: 'var(--danger)', tint: 'var(--tint-danger)', label: 'Dangerous' },
    YELLOW: { ball: 'var(--warning)', tint: 'var(--tint-warning)', label: 'Suspicious' },
    GREEN: { ball: 'var(--success)', tint: 'transparent', label: 'Legitimate' },
    GREY: { ball: 'var(--text-dim)', tint: 'transparent', label: 'Not scored' }
};

/**
 * Column widths as fractions of the table.
 *
 * The order is the one asked for: number, name, source, destination, with each
 * address followed by its port, and the summary last where a reader's eye
 * finishes - which is also where Wireshark puts Info.
 */
const COLUMNS = [
    { key: 'no', label: 'No.', width: '58px', align: 'right' },
    { key: 'time', label: 'Time', width: '104px' },
    { key: 'name', label: 'Email', width: 'minmax(180px, 1.4fr)' },
    { key: 'source', label: 'Source', width: 'minmax(120px, 0.9fr)' },
    { key: 'source_port', label: 'S.Port', width: '62px', align: 'right', mayBeEmpty: true },
    { key: 'destination', label: 'Destination', width: 'minmax(120px, 0.9fr)' },
    { key: 'destination_port', label: 'D.Port', width: '62px', align: 'right', mayBeEmpty: true },
    { key: 'protocol', label: 'Protocol', width: '76px' },
    { key: 'length', label: 'Len', width: '62px', align: 'right', mayBeEmpty: true },
    { key: 'info', label: 'Info', width: 'minmax(200px, 1.6fr)' }
];

const GRID = COLUMNS.map(c => c.width).join(' ');

const dash = value => (value === null || value === undefined || value === '' ? '—' : value);

function clockTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function MailFlowList({ cases, selectedCase, onSelectCase }) {
    const [rows, setRows] = useState([]);
    const [provenance, setProvenance] = useState({});
    const [expression, setExpression] = useState('');
    const [loadError, setLoadError] = useState(null);
    const [showHelp, setShowHelp] = useState(false);
    const [expandedRow, setExpandedRow] = useState(null);
    const inputRef = useRef(null);

    // Reloaded whenever the parent's case list changes, so the flow and the
    // detail view below it never drift apart by a refresh.
    useEffect(() => {
        let cancelled = false;
        api.getFlow()
            .then(answer => {
                if (cancelled) return;
                setRows(answer.flow || []);
                setProvenance(answer.column_provenance || {});
                setLoadError(null);
            })
            .catch(err => { if (!cancelled) setLoadError(err.message || 'The flow could not be read.'); });
        return () => { cancelled = true; };
    }, [cases.length]);

    const compiled = useMemo(() => compileFilter(expression), [expression]);
    const suggestions = useMemo(() => (expression ? fieldSuggestions(expression) : []), [expression]);

    const visible = useMemo(() => {
        if (compiled.error) return rows;          // Keep the last good view rather than blanking it.
        return rows.filter(compiled.test);
    }, [rows, compiled]);

    const counts = useMemo(() => ({
        RED: visible.filter(r => r.colour === 'RED').length,
        YELLOW: visible.filter(r => r.colour === 'YELLOW').length,
        GREEN: visible.filter(r => r.colour === 'GREEN').length
    }), [visible]);

    // Green valid, red invalid - the thing that makes the language usable.
    const barColour = compiled.error
        ? { border: 'var(--danger)', background: 'var(--tint-danger)' }
        : compiled.empty
            ? { border: 'var(--border)', background: 'var(--bg-panel)' }
            : { border: 'var(--success)', background: 'var(--tint-success)' };

    const selectRow = row => {
        setExpandedRow(expandedRow === row.no ? null : row.no);
        const match = cases.find(c => c.case_id === row.case_id);
        if (match) onSelectCase(match);
    };

    return (
        <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {/* ---- the display filter ---- */}
            <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'stretch' }}>
                    <div style={{ flex: 1, position: 'relative' }}>
                        <input
                            ref={inputRef}
                            value={expression}
                            onChange={e => setExpression(e.target.value)}
                            placeholder="Apply a display filter — e.g. verdict == HIGH_RISK && attachments > 0"
                            spellCheck={false}
                            style={{
                                width: '100%', boxSizing: 'border-box',
                                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                                fontSize: '0.78rem', padding: '7px 10px',
                                color: 'var(--text-primary)', outline: 'none',
                                borderRadius: '5px',
                                border: `1.5px solid ${barColour.border}`,
                                backgroundColor: barColour.background
                            }}
                        />
                        {expression && (
                            <button
                                onClick={() => setExpression('')}
                                title="Clear the filter"
                                style={{ position: 'absolute', right: '6px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', display: 'flex' }}
                            >
                                <X size={13} />
                            </button>
                        )}
                    </div>
                    <button
                        onClick={() => setShowHelp(v => !v)}
                        title="Fields and examples"
                        style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '5px', padding: '0 9px', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
                    >
                        <CircleHelp size={14} />
                    </button>
                </div>

                {/* The reason, not just the red. A filter bar that goes red with
                    no explanation is a puzzle rather than a tool. */}
                {compiled.error && (
                    <div style={{ marginTop: '5px', fontSize: '0.72rem', color: 'var(--danger)', fontFamily: 'ui-monospace, monospace' }}>
                        {compiled.error.message}
                        {typeof compiled.error.at === 'number' ? ` (at character ${compiled.error.at + 1})` : ''}
                        <span style={{ color: 'var(--text-dim)', fontFamily: 'inherit' }}> — showing the unfiltered list until this is valid</span>
                    </div>
                )}

                {!compiled.error && suggestions.length > 0 && (
                    <div style={{ marginTop: '5px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {suggestions.map(s => (
                            <button
                                key={s.name}
                                onClick={() => {
                                    const parts = expression.split(/([\s()!&|]+)/);
                                    parts[parts.length - 1] = s.name;
                                    setExpression(parts.join(''));
                                    inputRef.current?.focus();
                                }}
                                title={s.help}
                                style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.68rem', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '3px', padding: '1px 5px', cursor: 'pointer', color: 'var(--accent)' }}
                            >
                                {s.name}
                            </button>
                        ))}
                    </div>
                )}

                <div style={{ marginTop: '7px', display: 'flex', gap: '14px', alignItems: 'center', flexWrap: 'wrap', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                    <span>{visible.length} of {rows.length} shown</span>
                    {['RED', 'YELLOW', 'GREEN'].map(c => (
                        <span key={c} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: TONE[c].ball, display: 'inline-block' }} />
                            {TONE[c].label} {counts[c]}
                        </span>
                    ))}
                    {loadError && <span style={{ color: 'var(--warning)' }}>Flow unavailable: {loadError}</span>}
                </div>

                {showHelp && (
                    <div style={{ marginTop: '9px', backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '5px', padding: '10px 11px' }}>
                        <div style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '5px' }}>Examples</div>
                        {FILTER_EXAMPLES.map(ex => (
                            <div key={ex.expression} style={{ display: 'flex', gap: '8px', marginBottom: '3px', alignItems: 'baseline' }}>
                                <button
                                    onClick={() => setExpression(ex.expression)}
                                    style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.7rem', background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--accent)', textAlign: 'left', whiteSpace: 'nowrap' }}
                                >
                                    {ex.expression}
                                </button>
                                <span style={{ fontSize: '0.69rem', color: 'var(--text-dim)' }}>{ex.describes}</span>
                            </div>
                        ))}
                        <div style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--text-primary)', margin: '9px 0 5px' }}>Fields</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
                            {Object.entries(FIELDS).map(([name, f]) => (
                                <span key={name} title={f.help} style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.67rem', color: 'var(--text-muted)', border: '1px solid var(--border)', borderRadius: '3px', padding: '1px 4px' }}>{name}</span>
                            ))}
                        </div>
                        <div style={{ fontSize: '0.69rem', color: 'var(--text-dim)', marginTop: '8px', lineHeight: 1.5 }}>
                            Combine with <code>&amp;&amp;</code>, <code>||</code>, <code>!</code> and brackets. Compare with
                            <code> == != &gt; &lt; &gt;= &lt;= </code>, <code>contains</code> or <code>matches</code> for a regular expression.
                        </div>
                    </div>
                )}
            </div>

            {/* ---- column headings ---- */}
            <div style={{
                display: 'grid', gridTemplateColumns: GRID, gap: '0',
                backgroundColor: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
                fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.03em'
            }}>
                {COLUMNS.map(col => (
                    <div
                        key={col.key}
                        title={provenance[col.key] || undefined}
                        style={{ padding: '6px 8px', textAlign: col.align || 'left', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden' }}
                    >
                        {col.label}
                        {/* Marks a column that is often legitimately empty, with the
                            reason on hover. Better than a reader assuming the data
                            is missing through a fault. */}
                        {col.mayBeEmpty && provenance[col.key] && <span style={{ color: 'var(--text-dim)' }}> ?</span>}
                    </div>
                ))}
            </div>

            {/* ---- the rows ---- */}
            <div style={{ maxHeight: '52vh', overflowY: 'auto', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: '0.73rem' }}>
                {visible.length === 0 ? (
                    <div style={{ padding: '28px 16px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.78rem', fontFamily: 'inherit' }}>
                        {rows.length === 0
                            ? 'No mail has been analysed yet. Every message that arrives will appear here as a row.'
                            : 'No message matches this filter.'}
                    </div>
                ) : visible.map(row => {
                    const tone = TONE[row.colour] || TONE.GREY;
                    const isSelected = selectedCase?.case_id === row.case_id;
                    const isExpanded = expandedRow === row.no;

                    return (
                        <React.Fragment key={row.case_id}>
                            <div
                                onClick={() => selectRow(row)}
                                style={{
                                    display: 'grid', gridTemplateColumns: GRID,
                                    cursor: 'pointer',
                                    backgroundColor: isSelected ? 'var(--border)' : tone.tint,
                                    borderBottom: '1px solid var(--border)',
                                    borderLeft: isSelected ? '2px solid var(--accent)' : '2px solid transparent',
                                    color: 'var(--text-primary)'
                                }}
                            >
                                {/* The sequence number, carrying the coloured ball. */}
                                <div style={{ padding: '4px 8px', textAlign: 'right', display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'flex-end' }}>
                                    <span
                                        title={`${tone.label}${row.confidence !== null ? ` — ${Math.round(row.confidence * 100)}% confident` : ''}`}
                                        style={{ width: '9px', height: '9px', borderRadius: '50%', backgroundColor: tone.ball, flexShrink: 0, boxShadow: `0 0 0 1px var(--bg-surface)` }}
                                    />
                                    {row.no}
                                </div>
                                <div style={{ padding: '4px 8px', color: 'var(--text-dim)' }}>{clockTime(row.time)}</div>
                                <div style={{ padding: '4px 8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={`${row.name}\nfrom ${row.sender || 'unknown'}`}>{row.name}</div>
                                <div style={{ padding: '4px 8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.source_host || row.source || ''}>
                                    {dash(row.source || row.source_host)}
                                </div>
                                <div style={{ padding: '4px 8px', textAlign: 'right', color: row.source_port ? 'inherit' : 'var(--text-dim)' }}>{dash(row.source_port)}</div>
                                <div style={{ padding: '4px 8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.destination_basis || ''}>
                                    {dash(row.destination || row.destination_host)}
                                </div>
                                <div style={{ padding: '4px 8px', textAlign: 'right', color: row.destination_port ? 'inherit' : 'var(--text-dim)' }}>{dash(row.destination_port)}</div>
                                <div style={{ padding: '4px 8px' }} title={row.protocol_basis || ''}>{dash(row.protocol)}</div>
                                <div style={{ padding: '4px 8px', textAlign: 'right', color: row.length ? 'inherit' : 'var(--text-dim)' }}>{dash(row.length)}</div>
                                <div style={{ padding: '4px 8px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.info}>{row.info}</div>
                            </div>

                            {/* ---- the frame detail, as Wireshark expands a packet ---- */}
                            {isExpanded && (
                                <div style={{ gridColumn: '1 / -1', backgroundColor: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', padding: '10px 14px' }}>
                                    <div style={{ fontSize: '0.71rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
                                        Path of message {row.no} — {row.frames.length} hop(s)
                                    </div>
                                    {row.frames.map(frame => (
                                        <div key={frame.index} style={{ display: 'flex', gap: '9px', padding: '3px 0', alignItems: 'baseline', borderBottom: '1px dotted var(--border)' }}>
                                            <span style={{ color: 'var(--text-dim)', minWidth: '20px' }}>{frame.index}.</span>
                                            <span style={{ color: frame.observed_by_us ? 'var(--success)' : 'var(--text-primary)', minWidth: '130px' }}>
                                                {frame.address || frame.host || '—'}
                                            </span>
                                            <span style={{ color: 'var(--text-muted)', minWidth: '150px' }}>{frame.classification || ''}</span>
                                            {frame.protocol && <span style={{ color: 'var(--accent)' }}>{frame.protocol}{frame.port ? `:${frame.port}` : ''}</span>}
                                            <span style={{ color: 'var(--text-dim)', flex: 1 }}>{frame.explanation || ''}</span>
                                        </div>
                                    ))}
                                    <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '7px', lineHeight: 1.5, fontFamily: 'system-ui, sans-serif' }}>
                                        Every hop but the last is what a mail server wrote in a <code>Received:</code> header, which is
                                        free text and can be forged by anything upstream of the first trusted relay. The last hop is the
                                        only one this system witnessed itself.
                                    </div>
                                </div>
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            {/* ---- what the columns can and cannot say ---- */}
            <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border)', fontSize: '0.68rem', color: 'var(--text-dim)', lineHeight: 1.5 }}>
                A dash means the value was not recorded, not that it was zero. Ports come from a
                <code> Received:</code> header only when a mail server wrote one, which most do not — so the source port is
                usually empty, and it is never inferred. The destination port is the one PhishLens itself listened on.
            </div>
        </div>
    );
}
