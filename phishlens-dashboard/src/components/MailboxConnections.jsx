import React, { useState, useEffect } from 'react';
import { Mail, Plus, Trash2, CheckCircle2, AlertTriangle, Loader } from 'lucide-react';
import { api } from '../services/api';

/**
 * Connecting a real mailbox, in the words of someone who has one.
 *
 * Deliberately free of the vocabulary the rest of the console uses. A person
 * setting this up is not an analyst yet - they are someone with a Gmail account
 * who wants their mail checked - so the page talks about an email address and a
 * password, explains up front that Google needs a special one, and says what
 * will happen to their mail once it is connected.
 */
export default function MailboxConnections() {
    const [state, setState] = useState(null);
    const [adding, setAdding] = useState(false);
    const [form, setForm] = useState({ provider: 'gmail', email: '', password: '', host: '', port: 993, folder: 'INBOX' });
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [hint, setHint] = useState(null);
    const [success, setSuccess] = useState(null);

    const load = async () => {
        try {
            setState(await api.getConnections());
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        }
    };

    useEffect(() => {
        load();
        const timer = setInterval(load, 15000);
        return () => clearInterval(timer);
    }, []);

    const provider = state?.providers?.find(p => p.id === form.provider);

    const submit = async (testOnly) => {
        setBusy(true);
        setError(null);
        setHint(null);
        setSuccess(null);
        try {
            const payload = {
                ...form,
                host: form.provider === 'custom' ? form.host : provider?.host,
                port: Number(form.port) || 993,
                folder: form.folder || 'INBOX'
            };
            if (testOnly) {
                const result = await api.testConnection(payload);
                if (result.success) {
                    setSuccess(`Signed in successfully. That folder currently holds ${result.messages_in_folder} message(s).`);
                } else {
                    setError(result.error);
                    setHint(result.hint);
                }
            } else {
                const result = await api.addConnection(payload);
                setSuccess(`${result.connection.email} is connected. New mail will be checked every 30 seconds.`);
                setForm({ provider: 'gmail', email: '', password: '', host: '', port: 993, folder: 'INBOX' });
                setAdding(false);
                load();
            }
        } catch (e) {
            setError(e.response?.data?.error || e.message);
            setHint(e.response?.data?.hint || null);
        } finally {
            setBusy(false);
        }
    };

    const disconnect = async (id, email) => {
        if (!window.confirm(`Stop checking ${email}? Messages already examined are kept.`)) return;
        try {
            await api.removeConnection(id);
            load();
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        }
    };

    if (!state) return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Loading connected mailboxes…</div>;

    const field = {
        width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
        borderRadius: '6px', padding: '9px 11px', color: 'var(--text-primary)', fontSize: '0.82rem'
    };
    const label = { fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
                <h3 style={{ margin: '0 0 6px 0', fontSize: '1rem', color: 'var(--text-primary)' }}>Your mailboxes</h3>
                <p style={{ margin: '0 0 16px 0', fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '640px' }}>
                    Connect an email account and PhishLens will check new messages as they arrive. It only
                    reads mail — nothing is moved, deleted or replied to unless you turn that on separately
                    under Response.
                </p>

                <div style={{
                    background: 'var(--bg-surface)', borderRadius: '6px', padding: '12px 14px',
                    marginBottom: '16px', fontSize: '0.77rem', color: 'var(--text-muted)', lineHeight: 1.6
                }}>
                    <strong style={{ color: 'var(--text-secondary)' }}>What gets checked:</strong> new mail
                    arriving in the folder you choose, looked at every 30 seconds. Mail that was already
                    in the folder before you connected is not re-examined, and each connection watches one
                    folder — so to cover both, connect the account twice, once for Inbox and once for Spam.
                </div>

                {state.mailboxes.length === 0 ? (
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)', padding: '14px', background: 'var(--bg-surface)', borderRadius: '6px' }}>
                        No mailbox is connected yet, so no live mail is being checked.
                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '9px' }}>
                        {state.mailboxes.map(m => (
                            <div key={m.id} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '13px 15px', display: 'flex', alignItems: 'center', gap: '13px' }}>
                                <Mail size={17} style={{ color: m.last_error ? 'var(--danger)' : 'var(--success)', flexShrink: 0 }} />
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontWeight: 600, fontSize: '0.87rem', color: 'var(--text-primary)' }}>{m.email}</div>
                                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                                        {m.provider_label} · {m.folder || 'INBOX'} · {m.messages_seen} message{m.messages_seen === 1 ? '' : 's'} checked
                                        {m.last_checked_at ? ` · last looked ${new Date(m.last_checked_at).toLocaleTimeString()}` : ''}
                                    </div>
                                    {m.last_error && (
                                        <div style={{ fontSize: '0.74rem', color: 'var(--danger)', marginTop: '4px' }}>{m.last_error}</div>
                                    )}
                                </div>
                                <span style={{
                                    fontSize: '0.68rem', fontWeight: 700, padding: '3px 8px', borderRadius: '999px',
                                    background: m.watching && !m.last_error ? 'var(--tint-success)' : 'var(--tint-warning)',
                                    color: m.watching && !m.last_error ? 'var(--success)' : 'var(--warning)'
                                }}>
                                    {m.watching && !m.last_error ? 'Checking' : 'Not checking'}
                                </span>
                                <button
                                    onClick={() => disconnect(m.id, m.email)}
                                    title={`Disconnect ${m.email}`}
                                    style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', display: 'flex' }}
                                >
                                    <Trash2 size={15} />
                                </button>
                            </div>
                        ))}
                    </div>
                )}

                {!adding && (
                    <button
                        onClick={() => { setAdding(true); setError(null); setSuccess(null); }}
                        style={{ marginTop: '15px', background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none', borderRadius: '6px', padding: '9px 15px', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '7px' }}
                    >
                        <Plus size={15} /> Connect a mailbox
                    </button>
                )}
            </div>

            {adding && (
                <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
                    <h3 style={{ margin: '0 0 14px 0', fontSize: '0.95rem', color: 'var(--text-primary)' }}>Connect a mailbox</h3>

                    <div style={{ display: 'grid', gap: '13px', maxWidth: '520px' }}>
                        <div>
                            <span style={label}>Where is this account?</span>
                            <select
                                value={form.provider}
                                onChange={e => {
                                    // Folder names are provider-specific, so keeping the old one
                                    // would silently ask Gmail to open "Junk Email".
                                    const next = state.providers.find(p => p.id === e.target.value);
                                    setForm({ ...form, provider: e.target.value, folder: next?.folders?.[0]?.path || 'INBOX' });
                                }}
                                style={field}
                            >
                                {state.providers.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
                            </select>
                        </div>

                        {provider?.guidance && (
                            <div style={{ background: 'var(--tint-accent)', borderRadius: '6px', padding: '11px 13px', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                                {provider.guidance}
                            </div>
                        )}

                        {provider?.folders?.length > 1 && (
                            <div>
                                <span style={label}>Which folder should be watched?</span>
                                <select
                                    value={form.folder}
                                    onChange={e => setForm({ ...form, folder: e.target.value })}
                                    style={field}
                                >
                                    {provider.folders.map(f => <option key={f.path} value={f.path}>{f.label}</option>)}
                                </select>
                                <small style={{ fontSize: '0.71rem', color: 'var(--text-dim)', display: 'block', marginTop: '5px', lineHeight: 1.5 }}>
                                    One folder is watched per connection. Spam is worth adding as a second
                                    connection for the same account: a phishing message your provider filed
                                    as spam never reaches the inbox, so it would otherwise never be examined.
                                </small>
                            </div>
                        )}

                        <div>
                            <span style={label}>Email address</span>
                            <input
                                type="email" value={form.email} autoComplete="off"
                                onChange={e => setForm({ ...form, email: e.target.value })}
                                placeholder="you@gmail.com" style={field}
                            />
                        </div>

                        <div>
                            <span style={label}>{provider?.requires_app_password ? 'App password' : 'Password'}</span>
                            <input
                                type="password" value={form.password} autoComplete="new-password"
                                onChange={e => setForm({ ...form, password: e.target.value })}
                                placeholder={provider?.requires_app_password ? 'The 16-character app password' : 'Mailbox password'}
                                style={field}
                            />
                            <small style={{ fontSize: '0.71rem', color: 'var(--text-dim)', display: 'block', marginTop: '5px', lineHeight: 1.5 }}>
                                Stored encrypted on this computer and used only to sign in to this mailbox.
                                It is never displayed again and never leaves this machine.
                            </small>
                        </div>

                        {form.provider === 'custom' && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 110px', gap: '10px' }}>
                                <div>
                                    <span style={label}>IMAP server</span>
                                    <input value={form.host} onChange={e => setForm({ ...form, host: e.target.value })} placeholder="imap.example.com" style={field} />
                                </div>
                                <div>
                                    <span style={label}>Port</span>
                                    <input value={form.port} onChange={e => setForm({ ...form, port: e.target.value })} style={field} />
                                </div>
                            </div>
                        )}

                        {error && (
                            <div style={{ background: 'var(--tint-danger)', borderRadius: '6px', padding: '11px 13px' }}>
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                                    <AlertTriangle size={15} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 1 }} />
                                    <div>
                                        <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>{error}</div>
                                        {hint && <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '5px', lineHeight: 1.5 }}>{hint}</div>}
                                    </div>
                                </div>
                            </div>
                        )}

                        {success && (
                            <div style={{ background: 'var(--tint-success)', borderRadius: '6px', padding: '11px 13px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <CheckCircle2 size={15} style={{ color: 'var(--success)', flexShrink: 0 }} />
                                <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>{success}</span>
                            </div>
                        )}

                        <div style={{ display: 'flex', gap: '9px', marginTop: '3px' }}>
                            <button
                                onClick={() => submit(false)} disabled={busy || !form.email || !form.password}
                                style={{ background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none', borderRadius: '6px', padding: '9px 16px', fontSize: '0.82rem', fontWeight: 600, cursor: busy ? 'wait' : 'pointer', display: 'inline-flex', alignItems: 'center', gap: '7px', opacity: (!form.email || !form.password) ? 0.5 : 1 }}
                            >
                                {busy ? <Loader size={14} /> : <CheckCircle2 size={14} />} Connect and start checking
                            </button>
                            <button
                                onClick={() => submit(true)} disabled={busy || !form.email || !form.password}
                                style={{ background: 'var(--bg-raised)', color: 'var(--text-secondary)', border: '1px solid var(--border-strong)', borderRadius: '6px', padding: '9px 16px', fontSize: '0.82rem', cursor: 'pointer' }}
                            >
                                Just test it
                            </button>
                            <button
                                onClick={() => { setAdding(false); setError(null); setSuccess(null); }}
                                style={{ background: 'transparent', color: 'var(--text-dim)', border: 'none', padding: '9px 10px', fontSize: '0.82rem', cursor: 'pointer' }}
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
