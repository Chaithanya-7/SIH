import React, { useState, useMemo } from 'react';
import { FileText, Download, Search, Loader, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

/**
 * Every examined message, with its report available from here.
 *
 * This page used to render the single-case detail view bound to whatever had
 * been selected somewhere else. Arriving at Reports from the sidebar - the
 * ordinary way to arrive at it - meant nothing was selected, so the page was
 * empty and there was no report to download. The reports existed the whole
 * time; there was simply no way to reach one.
 */

const VERDICT = {
    HIGH_RISK: { label: 'Dangerous', colour: 'var(--danger)', tint: 'var(--tint-danger)' },
    SUSPICIOUS: { label: 'Suspicious', colour: 'var(--warning)', tint: 'var(--tint-warning)' },
    SAFE: { label: 'Looks fine', colour: 'var(--success)', tint: 'var(--tint-success)' },
    UNKNOWN: { label: 'Not classified', colour: 'var(--text-dim)', tint: 'var(--tint-neutral)' }
};

function when(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function ReportsView({ cases = [], onOpenCase }) {
    const [query, setQuery] = useState('');
    const [downloading, setDownloading] = useState(null);
    const [failure, setFailure] = useState(null);

    const visible = useMemo(() => {
        const needle = query.trim().toLowerCase();
        const matched = needle
            ? cases.filter(c =>
                (c.message?.subject || '').toLowerCase().includes(needle) ||
                (c.message?.sender || '').toLowerCase().includes(needle) ||
                (c.case_id || '').toLowerCase().includes(needle))
            : cases;
        return matched.slice().sort((a, b) =>
            new Date(b.timestamps?.ingested_at || 0) - new Date(a.timestamps?.ingested_at || 0));
    }, [cases, query]);

    const download = async (event, caseId) => {
        // The row itself opens the message, so the button must not do both.
        event.stopPropagation();
        setDownloading(caseId);
        setFailure(null);
        try {
            await api.downloadReportPdf(caseId);
        } catch (e) {
            setFailure(`${caseId}: ${e.response?.data?.error || e.message}`);
        } finally {
            setDownloading(null);
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
                <h3 style={{ margin: '0 0 5px 0', fontSize: '1rem', color: 'var(--text-primary)' }}>Reports</h3>
                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '640px' }}>
                    Every message PhishLens has examined. Each report is a PDF recording what was found,
                    why it was decided, and what was done about it — suitable for handing to someone else.
                </p>
            </div>

            {failure && (
                <div style={{ background: 'var(--tint-danger)', borderRadius: '8px', padding: '12px 15px', display: 'flex', gap: '9px', alignItems: 'center' }}>
                    <AlertTriangle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>That report could not be downloaded — {failure}</span>
                </div>
            )}

            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
                <div style={{ padding: '11px 15px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '9px' }}>
                    <Search size={15} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />
                    <input
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                        placeholder="Search by subject, sender or reference"
                        style={{
                            flex: 1, background: 'transparent', border: 'none', outline: 'none',
                            color: 'var(--text-primary)', fontSize: '0.82rem'
                        }}
                    />
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                        {visible.length} of {cases.length}
                    </span>
                </div>

                {visible.length === 0 ? (
                    <div style={{ padding: '30px 18px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                        {cases.length === 0
                            ? 'No messages have been examined yet. Connect a mailbox, or check an email from the "Check an email" page.'
                            : 'No message matches that search.'}
                    </div>
                ) : visible.map(item => {
                    const meta = VERDICT[item.detection?.verdict] || VERDICT.UNKNOWN;
                    const isDownloading = downloading === item.case_id;
                    return (
                        <div
                            key={item.case_id}
                            onClick={() => onOpenCase && onOpenCase(item.case_id)}
                            title="Open the full examination of this message"
                            style={{
                                padding: '12px 15px', borderTop: '1px solid var(--border)',
                                display: 'flex', alignItems: 'center', gap: '13px',
                                cursor: onOpenCase ? 'pointer' : 'default'
                            }}
                        >
                            <FileText size={17} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />

                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{
                                    fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)',
                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                                }}>
                                    {item.message?.subject || '(no subject)'}
                                </div>
                                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                                    from {item.message?.sender || '(unknown sender)'}
                                    {when(item.timestamps?.ingested_at) ? ` · ${when(item.timestamps.ingested_at)}` : ''}
                                </div>
                            </div>

                            <span style={{
                                fontSize: '0.69rem', fontWeight: 700, padding: '3px 9px', borderRadius: '999px',
                                background: meta.tint, color: meta.colour, whiteSpace: 'nowrap', flexShrink: 0
                            }}>
                                {meta.label}
                            </span>

                            <button
                                onClick={e => download(e, item.case_id)}
                                disabled={isDownloading}
                                title={`Download the report for "${item.message?.subject || item.case_id}"`}
                                style={{
                                    background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
                                    color: 'var(--text-secondary)', borderRadius: '6px', padding: '6px 11px',
                                    fontSize: '0.76rem', cursor: isDownloading ? 'wait' : 'pointer',
                                    display: 'inline-flex', alignItems: 'center', gap: '6px', flexShrink: 0
                                }}
                            >
                                {isDownloading ? <Loader size={13} /> : <Download size={13} />}
                                {isDownloading ? 'Preparing…' : 'PDF'}
                            </button>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
