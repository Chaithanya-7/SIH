import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle2, AlertTriangle, ShieldAlert, Loader, X } from 'lucide-react';
import { api } from '../services/api';

/**
 * Submit a saved email and see what PhishLens makes of it.
 *
 * This page exists because there was no way to hand the product an email from
 * the interface at all: live mail arrived through a connected mailbox, and
 * everything else went through the HTTP API. Somebody wanting to try it on a
 * message they had actually received had nowhere to put it.
 *
 * It also explains where a .eml file comes from, because "export the message as
 * .eml" is obvious only to people who already knew.
 */

const VERDICT = {
    HIGH_RISK: {
        label: 'Dangerous',
        detail: 'This looks like a real phishing attempt. Do not click anything in it.',
        colour: 'var(--danger)', tint: 'var(--tint-danger)', Icon: ShieldAlert
    },
    SUSPICIOUS: {
        label: 'Suspicious',
        detail: 'Something about this is not right. Treat it with caution.',
        colour: 'var(--warning)', tint: 'var(--tint-warning)', Icon: AlertTriangle
    },
    SAFE: {
        label: 'Looks fine',
        detail: 'Nothing here matched a known attack pattern.',
        colour: 'var(--success)', tint: 'var(--tint-success)', Icon: CheckCircle2
    },
    UNKNOWN: {
        label: 'Not classified',
        detail: 'There was not enough in this message to judge it either way.',
        colour: 'var(--text-dim)', tint: 'var(--tint-neutral)', Icon: FileText
    }
};

const HOW_TO = [
    { name: 'Gmail', steps: 'Open the message, click the ⋮ menu at the top right of it, choose "Show original", then "Download Original".' },
    { name: 'Outlook (desktop)', steps: 'Drag the message out of the message list and drop it onto your desktop. It saves as a .eml or .msg file.' },
    { name: 'Apple Mail', steps: 'Select the message, then File → Save As, and choose Raw Message Source.' },
    { name: 'Thunderbird', steps: 'Right-click the message and choose "Save As", which writes a .eml file.' }
];

export default function CheckAnEmail({ onOpenCase }) {
    const [results, setResults] = useState([]);
    const [busy, setBusy] = useState(false);
    const [dragging, setDragging] = useState(false);
    const inputRef = useRef(null);

    const submit = async (files) => {
        const list = Array.from(files || []);
        if (list.length === 0) return;
        setBusy(true);

        for (const file of list) {
            // Sequential on purpose: each message is analysed properly rather
            // than several being raced, and the results appear in the order
            // they were dropped.
            try {
                const response = await api.uploadMessageFile(file);
                const threat = response.threatObject;
                setResults(prev => [{
                    key: `${file.name}-${Date.now()}-${Math.random()}`,
                    filename: file.name,
                    caseId: threat.case_id,
                    verdict: threat.detection?.verdict || 'UNKNOWN',
                    confidence: threat.confidence?.threat ?? null,
                    subject: threat.message?.subject || '(no subject)',
                    sender: threat.message?.sender || '(unknown sender)',
                    reasons: (threat.evidence || [])
                        .slice()
                        .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
                        .slice(0, 5)
                        .map(e => ({ text: e.finding, severity: e.severity }))
                }, ...prev]);
            } catch (e) {
                setResults(prev => [{
                    key: `${file.name}-${Date.now()}-${Math.random()}`,
                    filename: file.name,
                    error: e.response?.data?.error || e.message,
                    hint: e.response?.data?.hint || null
                }, ...prev]);
            }
        }

        setBusy(false);
        if (inputRef.current) inputRef.current.value = '';
    };

    const onDrop = (e) => {
        e.preventDefault();
        setDragging(false);
        submit(e.dataTransfer.files);
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
                <h3 style={{ margin: '0 0 6px 0', fontSize: '1rem', color: 'var(--text-primary)' }}>Check an email</h3>
                <p style={{ margin: '0 0 16px 0', fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '660px' }}>
                    Drop a saved email here and PhishLens will examine it the same way it examines mail
                    from a connected mailbox. Nothing is uploaded anywhere — the message is read on this
                    computer.
                </p>

                <div
                    onDragOver={e => { e.preventDefault(); setDragging(true); }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={onDrop}
                    onClick={() => inputRef.current?.click()}
                    style={{
                        border: `2px dashed ${dragging ? 'var(--accent)' : 'var(--border-strong)'}`,
                        background: dragging ? 'var(--tint-accent)' : 'var(--bg-surface)',
                        borderRadius: '8px', padding: '30px 20px', textAlign: 'center',
                        cursor: busy ? 'wait' : 'pointer', transition: 'all 0.15s ease'
                    }}
                >
                    {busy
                        ? <Loader size={26} style={{ color: 'var(--accent)' }} />
                        : <Upload size={26} style={{ color: dragging ? 'var(--accent)' : 'var(--text-dim)' }} />}
                    <div style={{ fontSize: '0.87rem', color: 'var(--text-primary)', fontWeight: 600, marginTop: '9px' }}>
                        {busy ? 'Examining…' : 'Drop email files here, or click to choose them'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                        .eml files. You can drop several at once.
                    </div>
                    <input
                        ref={inputRef} type="file" multiple accept=".eml,message/rfc822"
                        onChange={e => submit(e.target.files)} style={{ display: 'none' }}
                    />
                </div>
            </div>

            {results.length > 0 && (
                <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
                    <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <h3 style={{ margin: 0, fontSize: '0.88rem', color: 'var(--text-primary)' }}>Results</h3>
                        <button
                            onClick={() => setResults([])}
                            style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                        >
                            <X size={13} /> Clear
                        </button>
                    </div>

                    <div>
                        {results.map(r => {
                            if (r.error) {
                                return (
                                    <div key={r.key} style={{ padding: '14px 16px', borderTop: '1px solid var(--border)', background: 'var(--tint-danger)' }}>
                                        <div style={{ fontSize: '0.83rem', fontWeight: 600, color: 'var(--text-primary)' }}>{r.filename}</div>
                                        <div style={{ fontSize: '0.78rem', color: 'var(--danger)', marginTop: '3px' }}>{r.error}</div>
                                        {r.hint && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: 1.5 }}>{r.hint}</div>}
                                    </div>
                                );
                            }

                            const meta = VERDICT[r.verdict] || VERDICT.UNKNOWN;
                            const { Icon } = meta;
                            return (
                                <div
                                    key={r.key}
                                    onClick={() => onOpenCase && onOpenCase(r.caseId)}
                                    title="Open the full examination of this message"
                                    style={{ padding: '14px 16px', borderTop: '1px solid var(--border)', cursor: onOpenCase ? 'pointer' : 'default', display: 'flex', gap: '13px' }}
                                >
                                    <div style={{ background: meta.tint, borderRadius: '7px', padding: '9px', height: 'fit-content' }}>
                                        <Icon size={19} style={{ color: meta.colour, display: 'block' }} />
                                    </div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ display: 'flex', alignItems: 'baseline', gap: '9px', flexWrap: 'wrap' }}>
                                            <span style={{ fontSize: '0.93rem', fontWeight: 700, color: meta.colour }}>{meta.label}</span>
                                            {r.confidence != null && (
                                                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                                    {Math.round(r.confidence * 100)}% confident
                                                </span>
                                            )}
                                        </div>
                                        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{meta.detail}</div>

                                        <div style={{ marginTop: '9px', fontSize: '0.81rem', color: 'var(--text-primary)', fontWeight: 600 }}>{r.subject}</div>
                                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>from {r.sender}</div>

                                        {r.reasons.length > 0 && (
                                            <div style={{ marginTop: '9px' }}>
                                                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '4px' }}>Why:</div>
                                                {r.reasons.map((reason, i) => (
                                                    <div key={i} style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                                                        • {reason.text}
                                                    </div>
                                                ))}
                                            </div>
                                        )}

                                        <div style={{ fontSize: '0.71rem', color: 'var(--text-dim)', marginTop: '8px' }}>
                                            {r.filename} · click to see everything that was checked
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
                <h3 style={{ margin: '0 0 4px 0', fontSize: '0.92rem', color: 'var(--text-primary)' }}>How to save an email to a file</h3>
                <p style={{ margin: '0 0 13px 0', fontSize: '0.79rem', color: 'var(--text-muted)' }}>
                    A forwarded copy is not the same message — forwarding rewrites the sender and the
                    delivery records, which are most of what PhishLens examines. Save the original instead.
                </p>
                <div style={{ display: 'grid', gap: '9px' }}>
                    {HOW_TO.map(item => (
                        <div key={item.name} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '11px 13px' }}>
                            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{item.name}</div>
                            <div style={{ fontSize: '0.77rem', color: 'var(--text-muted)', marginTop: '2px', lineHeight: 1.55 }}>{item.steps}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
