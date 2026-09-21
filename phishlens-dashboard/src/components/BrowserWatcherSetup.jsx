import React, { useState, useEffect } from 'react';
import { Globe, Copy, Check, FolderOpen } from 'lucide-react';
import { api } from '../services/api';

/**
 * Turning on the one channel that watches real mail.
 *
 * Every other channel on the sources page describes itself and waits. This one
 * needs a browser extension loaded by hand, and the step people actually got
 * stuck on was the third: pasting a 64-character key, generated per install,
 * that lives in an application data folder they have no reason to know about.
 *
 * So the desktop application now publishes a copy of the extension with its own
 * address and key already written in, and that step disappears. Two of the
 * three steps below are browser setup
 * remain, both of them in the browser.
 *
 * In a browser - where there is no desktop app to publish anything - the older
 * four-step path is still shown, because there the key genuinely does have to
 * be carried across by hand.
 */

const PROVISIONED_STEPS = [
    {
        title: 'Open your browser\'s extensions page',
        body: 'In Chrome or Edge, type chrome://extensions into the address bar. Turn on "Developer mode" — the switch at the top right of that page.'
    },
    {
        title: 'Load the folder below',
        body: 'Click "Load unpacked", paste the folder path below into the dialog\'s address bar, and press Enter, then "Select Folder".'
    },
    {
        title: 'Open your mail',
        body: 'Open Gmail or Outlook on the web. New messages are examined as they appear in the list, and anything dangerous is labelled before you open it.'
    }
];

const MANUAL_STEPS = [
    {
        title: 'Open your browser\'s extensions page',
        body: 'In Chrome or Edge, type chrome://extensions into the address bar and turn on "Developer mode" at the top right.'
    },
    {
        title: 'Load the PhishLens extension',
        body: 'Click "Load unpacked" and choose the phishlens-extension folder.'
    },
    {
        title: 'Give it this computer\'s key',
        body: 'Click "Details" on the PhishLens extension, then "Extension options", paste the address and key below, and save.'
    },
    {
        title: 'Open your mail',
        body: 'Open Gmail or Outlook on the web. New messages are examined as they appear in the list.'
    }
];

export default function BrowserWatcherSetup({ extensionPath }) {
    const [copied, setCopied] = useState(null);
    const [publishedPath, setPublishedPath] = useState(null);
    const [checkedForApp, setCheckedForApp] = useState(false);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                const value = window.phishlens?.getExtensionPath
                    ? await window.phishlens.getExtensionPath()
                    : null;
                if (!cancelled) setPublishedPath(value || null);
            } catch (e) {
                if (!cancelled) setPublishedPath(null);
            } finally {
                if (!cancelled) setCheckedForApp(true);
            }
        })();
        return () => { cancelled = true; };
    }, []);

    const key = api.getSessionToken();
    const backend = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001').replace(/\/$/, '');

    // The published copy is preferred: it is the one that needs no key typed in.
    const provisioned = !!publishedPath;
    const folder = publishedPath || extensionPath;
    const steps = provisioned ? PROVISIONED_STEPS : MANUAL_STEPS;
    const loadStepIndex = 1;
    const keyStepIndex = provisioned ? -1 : 2;

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
                        background: copied === which ? 'var(--tint-success)' : 'var(--accent)',
                        border: 'none',
                        color: copied === which ? 'var(--success)' : 'var(--text-on-accent)',
                        borderRadius: '6px', padding: '0 15px', fontSize: '0.76rem', fontWeight: 600,
                        cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px', flexShrink: 0
                    }}
                >
                    {copied === which ? <Check size={13} /> : <Copy size={13} />}
                    {copied === which ? 'Copied' : 'Copy'}
                </button>
            </div>
        </div>
    );

    if (!checkedForApp) return null;

    return (
        <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--accent)', borderRadius: '8px', padding: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <Globe size={19} style={{ color: 'var(--accent)' }} />
                <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>Watch your real mail</h3>
            </div>
            <p style={{ margin: '0 0 6px 0', fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, maxWidth: '680px' }}>
                This is the part that examines mail actually arriving in your inbox. It reads messages in
                Gmail or Outlook on the web using the sign-in already in your browser — no password, no
                app password, and nothing stored anywhere.
            </p>

            {provisioned && (
                <p style={{ margin: '0 0 15px 0', fontSize: '0.79rem', color: 'var(--success)', lineHeight: 1.6 }}>
                    PhishLens has already prepared a copy of the extension with this computer's address and
                    key written in, so there is nothing to type.
                </p>
            )}

            <div style={{ display: 'grid', gap: '9px', marginTop: provisioned ? 0 : '12px' }}>
                {steps.map((step, i) => (
                    <div key={step.title} style={{ background: 'var(--bg-surface)', borderRadius: '6px', padding: '12px 14px', display: 'flex', gap: '12px' }}>
                        <span style={{
                            background: 'var(--accent)', color: 'var(--text-on-accent)', borderRadius: '50%',
                            width: '21px', height: '21px', flexShrink: 0, display: 'flex',
                            alignItems: 'center', justifyContent: 'center', fontSize: '0.72rem', fontWeight: 700
                        }}>{i + 1}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{step.title}</div>
                            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '3px', lineHeight: 1.55 }}>{step.body}</div>

                            {i === loadStepIndex && folder && (
                                <>
                                    {copyField('Folder to load', folder, 'folder')}
                                    <div style={{ marginTop: '7px', display: 'flex', alignItems: 'center', gap: '7px', fontSize: '0.73rem', color: 'var(--text-dim)' }}>
                                        <FolderOpen size={12} style={{ flexShrink: 0 }} />
                                        <span>
                                            The file dialog has an address bar at the top — paste the path there rather
                                            than clicking through the folders.
                                        </span>
                                    </div>
                                </>
                            )}

                            {i === keyStepIndex && (
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
                Once mail starts being examined, the browser channel below changes to &ldquo;Watching&rdquo;
                by itself — it is the traffic that proves the extension is running, so there is nothing else
                to switch on. If it stays on &ldquo;Not set up&rdquo; after opening Gmail, the extension is
                loaded but not seeing messages, and that is worth telling us.
            </p>
        </div>
    );
}
