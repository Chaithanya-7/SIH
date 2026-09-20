import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertTriangle, ExternalLink, Loader, ChevronRight } from 'lucide-react';
import { api } from '../services/api';

/**
 * Connecting Gmail by signing in with Google.
 *
 * Google will not issue a token without a registered OAuth client, so somebody
 * has to own one. Shipping ours inside every copy would make every install
 * depend on our credential and would put a distributed secret in the package,
 * so this asks for one of the operator's own and walks through making it. It is
 * free and it is done once.
 *
 * Said plainly on screen, because "create an OAuth client" is the kind of
 * instruction that reads as a wall when it is five steps.
 */

const STEPS = [
    {
        title: 'Open the Google Cloud console',
        body: 'Go to console.cloud.google.com and create a project, or pick one you already have. A project is free and nothing here bills you.',
        link: 'https://console.cloud.google.com/projectcreate'
    },
    {
        title: 'Switch on the Gmail API',
        body: 'In that project, open "APIs & Services" → "Enable APIs and services", search for Gmail API, and enable it.',
        link: 'https://console.cloud.google.com/apis/library/gmail.googleapis.com'
    },
    {
        title: 'Fill in the consent screen',
        body: 'Under "OAuth consent screen" choose External, give the app a name, and add your own Google address as a test user. Staying in Testing mode is fine — it is your own account.',
        link: 'https://console.cloud.google.com/apis/credentials/consent'
    },
    {
        title: 'Create the client',
        body: 'Under "Credentials" → "Create credentials" → "OAuth client ID", choose Desktop app as the type. Copy the client ID and secret it shows you.',
        link: 'https://console.cloud.google.com/apis/credentials'
    }
];

export default function GoogleSignIn({ onConnected }) {
    const [client, setClient] = useState(null);
    const [form, setForm] = useState({ clientId: '', clientSecret: '' });
    const [folder, setFolder] = useState('INBOX');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [hint, setHint] = useState(null);
    const [waiting, setWaiting] = useState(false);
    const [showSetup, setShowSetup] = useState(false);

    const load = async () => {
        try {
            setClient(await api.getGoogleClient());
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        }
    };

    useEffect(() => { load(); }, []);

    // While a sign-in is in the browser, the connection appears here rather
    // than in this tab, so the page watches for it instead of asking the
    // person to refresh.
    useEffect(() => {
        if (!waiting) return;
        const timer = setInterval(async () => {
            try {
                const state = await api.getConnections();
                if ((state.mailboxes || []).length > 0) {
                    setWaiting(false);
                    if (onConnected) onConnected();
                }
            } catch (e) {
                // Left running: a single failed poll is not a reason to stop
                // watching for the connection.
            }
        }, 3000);
        return () => clearInterval(timer);
    }, [waiting, onConnected]);

    const saveClient = async () => {
        setBusy(true); setError(null); setHint(null);
        try {
            setClient(await api.saveGoogleClient(form.clientId, form.clientSecret));
            setForm({ clientId: '', clientSecret: '' });
            setShowSetup(false);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
            setHint(e.response?.data?.hint || null);
        } finally {
            setBusy(false);
        }
    };

    const signIn = async () => {
        setBusy(true); setError(null); setHint(null);
        try {
            const { url } = await api.beginGoogleSignIn(folder);
            // Opened in the real browser: Google refuses consent inside an
            // embedded window, and the desktop app routes window.open outward.
            window.open(url, '_blank', 'noopener');
            setWaiting(true);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
            setHint(e.response?.data?.hint || null);
        } finally {
            setBusy(false);
        }
    };

    const field = {
        width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
        borderRadius: '6px', padding: '9px 11px', color: 'var(--text-primary)', fontSize: '0.82rem'
    };
    const labelStyle = { fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '5px' };

    if (!client) return null;

    return (
        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
            <h3 style={{ margin: '0 0 6px 0', fontSize: '1rem', color: 'var(--text-primary)' }}>Sign in with Google</h3>
            <p style={{ margin: '0 0 16px 0', fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '640px' }}>
                Connect Gmail the usual way, without creating an app password. The sign-in happens on
                Google's own page, so your password is never typed into this application.
            </p>

            <div style={{
                background: 'var(--tint-warning)', borderRadius: '6px', padding: '11px 13px',
                fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '15px'
            }}>
                <strong style={{ color: 'var(--text-primary)' }}>Google's consent screen will say full
                access to your mail.</strong> That is accurate, and it is not something PhishLens chose:
                Gmail's IMAP offers no read-only permission, so that one scope is the only way in.
                PhishLens only ever reads, and never moves or deletes anything unless you separately
                switch that on under Actions taken. If you would rather grant something narrower, use an
                app password instead — it is limited in the same way.
            </div>

            {client.configured ? (
                <>
                    <div style={{ display: 'grid', gap: '13px', maxWidth: '520px' }}>
                        <div>
                            <span style={labelStyle}>Which folder should be watched?</span>
                            <select value={folder} onChange={e => setFolder(e.target.value)} style={field}>
                                <option value="INBOX">Inbox</option>
                                <option value="[Gmail]/Spam">Spam</option>
                                <option value="[Gmail]/All Mail">All Mail (everything, including already-read)</option>
                            </select>
                        </div>

                        {error && (
                            <div style={{ background: 'var(--tint-danger)', borderRadius: '6px', padding: '11px 13px', display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                                <AlertTriangle size={15} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 1 }} />
                                <div>
                                    <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>{error}</div>
                                    {hint && <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '5px', lineHeight: 1.5 }}>{hint}</div>}
                                </div>
                            </div>
                        )}

                        {waiting ? (
                            <div style={{ background: 'var(--tint-accent)', borderRadius: '6px', padding: '13px 15px', display: 'flex', gap: '10px', alignItems: 'center' }}>
                                <Loader size={16} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                                <div>
                                    <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>Waiting for Google…</div>
                                    <div style={{ fontSize: '0.77rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                                        Finish signing in on the page that opened in your browser. This will update by itself.
                                    </div>
                                </div>
                                <button
                                    onClick={() => setWaiting(false)}
                                    style={{ marginLeft: 'auto', background: 'transparent', border: 'none', color: 'var(--text-dim)', fontSize: '0.77rem', cursor: 'pointer' }}
                                >
                                    Cancel
                                </button>
                            </div>
                        ) : (
                            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
                                <button
                                    onClick={signIn}
                                    disabled={busy}
                                    style={{
                                        background: '#ffffff', color: '#1f1f1f', border: '1px solid #dadce0',
                                        borderRadius: '6px', padding: '10px 18px', fontSize: '0.85rem',
                                        fontWeight: 600, cursor: busy ? 'wait' : 'pointer',
                                        display: 'inline-flex', alignItems: 'center', gap: '10px'
                                    }}
                                >
                                    <svg width="17" height="17" viewBox="0 0 48 48" aria-hidden="true">
                                        <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.6 2.6 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.8 6.1C12.3 13.2 17.7 9.5 24 9.5z" />
                                        <path fill="#4285F4" d="M46.1 24.6c0-1.6-.1-3.1-.4-4.6H24v9.1h12.4c-.5 2.9-2.2 5.4-4.6 7l7.6 5.9c4.4-4.1 6.7-10.1 6.7-17.4z" />
                                        <path fill="#FBBC05" d="M10.4 28.7c-.5-1.5-.8-3.1-.8-4.7s.3-3.2.8-4.7l-7.8-6.1C.9 16.3 0 20 0 24s.9 7.7 2.6 10.8l7.8-6.1z" />
                                        <path fill="#34A853" d="M24 48c6.2 0 11.5-2 15.3-5.5l-7.6-5.9c-2.1 1.4-4.8 2.3-7.7 2.3-6.3 0-11.7-3.7-13.6-9.2l-7.8 6.1C6.5 42.6 14.6 48 24 48z" />
                                    </svg>
                                    Sign in with Google
                                </button>
                                <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                                    Opens Google in your browser
                                </span>
                            </div>
                        )}
                    </div>

                    <div style={{ marginTop: '15px', paddingTop: '13px', borderTop: '1px solid var(--border)', fontSize: '0.74rem', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <CheckCircle2 size={13} style={{ color: 'var(--success)' }} />
                        <span>Using your own Google client <code style={{ color: 'var(--text-muted)' }}>{client.client_id?.slice(0, 28)}…</code></span>
                        <button
                            onClick={async () => { setClient(await api.forgetGoogleClient()); }}
                            style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', textDecoration: 'underline', cursor: 'pointer', fontSize: '0.74rem' }}
                        >
                            Use a different one
                        </button>
                    </div>
                </>
            ) : (
                <>
                    <div style={{ background: 'var(--tint-accent)', borderRadius: '6px', padding: '13px 15px', fontSize: '0.79rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '14px' }}>
                        Google only issues sign-ins to a registered application, so this needs one of your
                        own — free, and about five minutes, once. PhishLens deliberately does not ship a
                        shared one: that would make your mailbox depend on someone else's account and put
                        the same secret in every copy of this program.
                    </div>

                    {!showSetup ? (
                        <button
                            onClick={() => setShowSetup(true)}
                            style={{ background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none', borderRadius: '6px', padding: '9px 16px', fontSize: '0.83rem', fontWeight: 600, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '7px' }}
                        >
                            Set this up <ChevronRight size={15} />
                        </button>
                    ) : (
                        <div style={{ display: 'grid', gap: '11px', maxWidth: '620px' }}>
                            {STEPS.map((step, i) => (
                                <div key={step.title} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '12px 14px', display: 'flex', gap: '12px' }}>
                                    <span style={{
                                        background: 'var(--accent)', color: 'var(--text-on-accent)', borderRadius: '50%',
                                        width: '21px', height: '21px', flexShrink: 0, display: 'flex',
                                        alignItems: 'center', justifyContent: 'center', fontSize: '0.72rem', fontWeight: 700
                                    }}>{i + 1}</span>
                                    <div style={{ flex: 1 }}>
                                        <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{step.title}</div>
                                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '3px', lineHeight: 1.55 }}>{step.body}</div>
                                        <a
                                            href={step.link} target="_blank" rel="noreferrer"
                                            style={{ fontSize: '0.75rem', color: 'var(--accent)', marginTop: '5px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                                        >
                                            Open this step <ExternalLink size={11} />
                                        </a>
                                    </div>
                                </div>
                            ))}

                            <div style={{ marginTop: '4px' }}>
                                <span style={labelStyle}>Client ID</span>
                                <input
                                    value={form.clientId} autoComplete="off"
                                    onChange={e => setForm({ ...form, clientId: e.target.value })}
                                    placeholder="000000000000-xxxxxxxx.apps.googleusercontent.com" style={field}
                                />
                            </div>
                            <div>
                                <span style={labelStyle}>Client secret</span>
                                <input
                                    type="password" value={form.clientSecret} autoComplete="new-password"
                                    onChange={e => setForm({ ...form, clientSecret: e.target.value })}
                                    placeholder="GOCSPX-…" style={field}
                                />
                                <small style={{ fontSize: '0.71rem', color: 'var(--text-dim)', display: 'block', marginTop: '5px', lineHeight: 1.5 }}>
                                    Stored encrypted on this computer. A desktop client's secret is not truly
                                    confidential — Google says so — which is why the sign-in is also protected
                                    by PKCE rather than by this value alone.
                                </small>
                            </div>

                            {error && (
                                <div style={{ background: 'var(--tint-danger)', borderRadius: '6px', padding: '11px 13px', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                                    {error}
                                    {hint && <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '5px' }}>{hint}</div>}
                                </div>
                            )}

                            <div style={{ display: 'flex', gap: '9px' }}>
                                <button
                                    onClick={saveClient} disabled={busy || !form.clientId}
                                    style={{ background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none', borderRadius: '6px', padding: '9px 16px', fontSize: '0.82rem', fontWeight: 600, cursor: busy ? 'wait' : 'pointer', opacity: form.clientId ? 1 : 0.5 }}
                                >
                                    Save and continue
                                </button>
                                <button
                                    onClick={() => setShowSetup(false)}
                                    style={{ background: 'transparent', color: 'var(--text-dim)', border: 'none', padding: '9px 10px', fontSize: '0.82rem', cursor: 'pointer' }}
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
