import React, { useState } from 'react';
import { Globe, Copy, Check, FolderOpen } from 'lucide-react';
import { api } from '../services/api';

/**
 * Turning on the one channel that watches real mail.
 *
 * Everything else on the sources page describes itself and waits. This channel
 * needs a browser extension loaded by hand, which is four steps in a place
 * people do not usually go, and one of those steps is pasting a 64-character
 * key they have no obvious way to find. So the key is shown here, ready to
 * copy: the console already holds it, because it is the credential the console
 * itself authenticates with.
 *
 * The extension is loaded unpacked rather than from a store. That is the honest
 * consequence of a tool nobody publishes - and it is also why the folder path
 * is spelled out rather than described.
 */

const STEPS = [
    {
        title: 'Open your browser\'s extensions page',
        body: 'In Chrome or Edge, go to chrome://extensions. Turn on "Developer mode" with the switch at the top right.'
    },
    {
        title: 'Load the PhishLens extension',
        body: 'Click "Load unpacked" and choose the phishlens-extension folder shown below.'
    },
    {
        title: 'Give it this computer\'s key',
        body: 'Click "Details" on the PhishLens extension, then "Extension options", and paste the key below into the API key box. Save.'
    },
    {
        title: 'Open your mail',
        body: 'Open Gmail or Outlook on the web. New messages are examined as they appear, and anything dangerous is labelled in the list before you open it.'
    }
];

export default function BrowserWatcherSetup({ extensionPath }) {
    const [copied, setCopied] = useState(null);

    // The console authenticates with this key already; showing it saves
    // somebody hunting through an application data folder for a file.
    const key = api.getSessionToken();
    const backend = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001').replace(/\/$/, '');

    const copy = async (value, which) => {
        try {
            await navigator.clipboard.writeText(value);
            setCopied(which);
            setTimeout(() => setCopied(null), 2000);
        } catch (e) {
            setCopied(null);
        }
    };

    const copyField = (label, value, which) => (
        <div style={{ marginTop: '10px' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '4px' }}>{label}</div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'stretch' }}>
                <code style={{
                    flex: 1, minWidth: 0, background: 'var(--bg-code, var(--bg-surface))',
                    border: '1px solid var(--border-strong)', borderRadius: '6px',
                    padding: '9px 11px', fontSize: '0.76rem', color: 'var(--text-primary)',
                    overflow: 'auto', whiteSpace: 'nowrap'
                }}>
                    {value}
                </code>
                <button
                    onClick={() => copy(value, which)}
                    title={`Copy the ${label.toLowerCase()}`}
                    style={{
                        background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
                        color: copied === which ? 'var(--success)' : 'var(--text-secondary)',
                        borderRadius: '6px', padding: '0 13px', fontSize: '0.76rem',
                        cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px', flexShrink: 0
                    }}
                >
                    {copied === which ? <Check size={13} /> : <Copy size={13} />}
                    {copied === which ? 'Copied' : 'Copy'}
                </button>
            </div>
        </div>
    );

    return (
        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--accent)', borderRadius: '8px', padding: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <Globe size={19} style={{ color: 'var(--accent)' }} />
                <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>Watch your real mail</h3>
            </div>
            <p style={{ margin: '0 0 15px 0', fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '680px' }}>
                This is the part that examines the mail actually arriving in your inbox. It reads messages
                in Gmail or Outlook on the web using the sign-in already in your browser — no password,
                no app password, and nothing stored anywhere.
            </p>

            <div style={{ display: 'grid', gap: '9px' }}>
                {STEPS.map((step, i) => (
                    <div key={step.title} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '12px 14px', display: 'flex', gap: '12px' }}>
                        <span style={{
                            background: 'var(--accent)', color: 'var(--text-on-accent)', borderRadius: '50%',
                            width: '21px', height: '21px', flexShrink: 0, display: 'flex',
                            alignItems: 'center', justifyContent: 'center', fontSize: '0.72rem', fontWeight: 700
                        }}>{i + 1}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{step.title}</div>
                            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '3px', lineHeight: 1.55 }}>{step.body}</div>

                            {i === 1 && extensionPath && (
                                <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '7px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                    <FolderOpen size={13} style={{ flexShrink: 0, color: 'var(--text-dim)' }} />
                                    <code style={{ fontSize: '0.74rem' }}>{extensionPath}</code>
                                </div>
                            )}

                            {i === 2 && (
                                <>
                                    {copyField('PhishLens address', backend, 'url')}
                                    {key
                                        ? copyField('API key for this computer', key, 'key')
                                        : (
                                            <div style={{ marginTop: '9px', fontSize: '0.76rem', color: 'var(--warning)' }}>
                                                No key is available in this session, so it cannot be shown here.
                                            </div>
                                        )}
                                </>
                            )}
                        </div>
                    </div>
                ))}
            </div>

            <p style={{ margin: '14px 0 0 0', fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.6 }}>
                Once mail starts being examined this way, the browser channel below changes to
                &ldquo;Watching&rdquo; on its own — it is the traffic that proves the extension is running,
                so there is nothing else to switch on.
            </p>
        </div>
    );
}
