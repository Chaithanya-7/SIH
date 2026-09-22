import React, { useState, useEffect } from 'react';
import { Globe, Server, Inbox, Upload, Webhook, Terminal, CheckCircle2, AlertTriangle, Circle } from 'lucide-react';
import { api } from '../services/api';
import BrowserWatcherSetup from './BrowserWatcherSetup';

/**
 * Every way mail can reach this computer, and whether each one is watched.
 *
 * This replaces the mailbox connector, which was the wrong shape for the
 * problem: it asked for credentials, covered only the account somebody
 * remembered to add, and saw a message no sooner than a poll allowed. The
 * question worth answering is not "which account did you connect" but "could a
 * message reach you without being examined", and that is a question about
 * channels rather than accounts.
 *
 * The page is also honest about *when* each channel sees a message, because the
 * difference matters and is easy to overstate. Only the SMTP gateway sees mail
 * before it is delivered. Everything else sees it after the provider has it,
 * and the best any of them can do - which is still worth a great deal - is to
 * examine it before a person opens it.
 */

const CHANNEL_META = {
    browser_watch: {
        icon: Globe,
        timing: 'Before you open it',
        timingTone: 'good',
        plain: 'Watches Gmail and Outlook Web in your browser. As soon as a message appears in the list it is examined, and a dangerous one is labelled before you click it.',
        needs: 'Install the PhishLens browser extension and paste your API key into its options.'
    },
    smtp_gateway: {
        icon: Server,
        timing: 'Before it is delivered',
        timingTone: 'best',
        plain: 'Mail is delivered to PhishLens first, examined, and only then passed on. This is the only channel that sees a message before it reaches a mailbox at all.',
        needs: 'Requires control of where your mail is routed, so it suits a domain you run rather than a personal Gmail account.'
    },
    imap_poller: {
        icon: Inbox,
        timing: 'Shortly after it arrives',
        timingTone: 'ok',
        plain: 'Signs in to a mailbox and reads new messages. It needs a password or a sign-in, and only covers the accounts added to it.',
        needs: 'Kept for a mailbox nothing else can reach. The browser extension sees the same mail sooner and needs no credentials.'
    },
    gmail_api: {
        icon: Inbox,
        timing: 'Shortly after it arrives',
        timingTone: 'ok',
        plain: 'Receives a push from Google when mail arrives and fetches it through the Gmail API.',
        needs: 'Requires a Google Cloud project and a public address Google can reach.'
    },
    file_upload: {
        icon: Upload,
        timing: 'When you send it',
        timingTone: 'manual',
        plain: 'A saved message you drop onto the "Check an email" page.',
        needs: 'Always available.'
    },
    webhook: {
        icon: Webhook,
        timing: 'When something sends it',
        timingTone: 'manual',
        plain: 'Another system pushes a message in — a mail relay, a ticketing system, a SIEM.',
        needs: 'Always available to anything holding the API key.'
    },
    rest_api: {
        icon: Terminal,
        timing: 'When something sends it',
        timingTone: 'manual',
        plain: 'A message submitted directly to the API by an integration or a script.',
        needs: 'Always available to anything holding the API key.'
    }
};

const TIMING_TONE = {
    best: { color: 'var(--success)', bg: 'var(--tint-success)' },
    good: { color: 'var(--accent)', bg: 'var(--tint-accent)' },
    ok: { color: 'var(--warning)', bg: 'var(--tint-warning)' },
    manual: { color: 'var(--text-dim)', bg: 'var(--tint-neutral)' }
};

const STATUS_META = {
    ACTIVE: { label: 'Watching', Icon: CheckCircle2, color: 'var(--success)' },
    STALLED: { label: 'Stopped reporting', Icon: AlertTriangle, color: 'var(--danger)' },
    FAILED: { label: 'Failing', Icon: AlertTriangle, color: 'var(--danger)' },
    DISABLED: { label: 'Off', Icon: Circle, color: 'var(--text-dim)' },
    NOT_CONFIGURED: { label: 'Not set up', Icon: Circle, color: 'var(--text-dim)' }
};

export default function MailSources() {
    const [coverage, setCoverage] = useState(null);
    const [error, setError] = useState(null);

    const load = async () => {
        try {
            setCoverage(await api.getIngestionCoverage());
            setError(null);
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        }
    };

    useEffect(() => {
        load();
        const timer = setInterval(load, 10000);
        return () => clearInterval(timer);
    }, []);

    if (error) return <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>Could not load the monitoring status: {error}</div>;
    if (!coverage) return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Loading…</div>;

    const sources = coverage.sources || [];
    const automatic = sources.filter(s => !s.always_available);
    const manual = sources.filter(s => s.always_available);

    // Taken from the backend rather than recomputed here.
    //
    // The first version of this page counted every ACTIVE source, which made
    // the three always-open endpoints look like three watched channels and
    // announced that mail was being monitored when nothing was watching at
    // all. The registry already draws that distinction correctly, and there is
    // no reason for a second, quietly different answer to exist in the UI.
    const watchingCount = coverage.summary?.automatic_active ?? 0;
    const monitoring = coverage.monitoring_live_mail === true;

    /**
     * Whether to show the browser extension's setup steps.
     *
     * This used to hide them as soon as *any* live-mail channel was watching,
     * which is wrong as soon as more than one channel exists: switching on the
     * SMTP gateway hid the instructions for the browser extension, and the SMTP
     * gateway cannot see somebody's Gmail. The steps for a channel that is not
     * set up should not disappear because a different one is.
     */
    const browserChannel = (coverage.sources || []).find(s => s.id === 'browser_watch');
    const browserWatching = browserChannel ? browserChannel.status === 'ACTIVE' : false;

    const card = (source) => {
        const meta = CHANNEL_META[source.id] || {};
        const Icon = meta.icon || Inbox;
        const status = STATUS_META[source.status] || STATUS_META.NOT_CONFIGURED;
        const StatusIcon = status.Icon;
        const tone = TIMING_TONE[meta.timingTone] || TIMING_TONE.manual;

        return (
            <div key={source.id} style={{
                background: 'var(--bg-panel)', border: '1px solid var(--border)',
                borderRadius: '8px', padding: '16px 18px'
            }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '13px' }}>
                    <div style={{ background: 'var(--bg-surface)', borderRadius: '8px', padding: '9px', flexShrink: 0 }}>
                        <Icon size={18} style={{ color: status.color, display: 'block' }} />
                    </div>

                    <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)' }}>{source.name}</span>
                            {meta.timing && (
                                <span style={{
                                    fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: '999px',
                                    background: tone.bg, color: tone.color, whiteSpace: 'nowrap'
                                }}>
                                    {meta.timing}
                                </span>
                            )}
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: status.color, marginLeft: 'auto' }}>
                                <StatusIcon size={13} /> {status.label}
                            </span>
                        </div>

                        <p style={{ margin: '6px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                            {meta.plain || source.description}
                        </p>

                        {source.detail && (
                            <p style={{ margin: '6px 0 0 0', fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                                {source.detail}
                            </p>
                        )}

                        {source.status !== 'ACTIVE' && meta.needs && (
                            <p style={{ margin: '7px 0 0 0', fontSize: '0.76rem', color: 'var(--text-dim)', lineHeight: 1.55 }}>
                                <strong style={{ color: 'var(--text-secondary)' }}>To switch on:</strong> {meta.needs}
                            </p>
                        )}

                        <div style={{ marginTop: '8px', fontSize: '0.71rem', color: 'var(--text-dim)' }}>
                            {source.messages_ingested ?? 0} message{(source.messages_ingested ?? 0) === 1 ? '' : 's'} examined through this
                            {source.last_message_at ? ` · last ${new Date(source.last_message_at).toLocaleString()}` : ''}
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{
                background: monitoring ? 'var(--tint-success)' : 'var(--tint-warning)',
                border: `1px solid ${monitoring ? 'var(--success)' : 'var(--warning)'}`,
                borderRadius: '8px', padding: '16px 18px'
            }}>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {monitoring
                        ? `${watchingCount} mail channel${watchingCount === 1 ? ' is' : 's are'} being watched`
                        : 'No mail is being watched automatically'}
                </div>
                <p style={{ margin: '5px 0 0 0', fontSize: '0.81rem', color: 'var(--text-secondary)', lineHeight: 1.6, maxWidth: '720px' }}>
                    PhishLens watches the ways mail reaches this computer rather than asking you to connect
                    an account. Switch on whichever ones apply — each is examined the moment a message
                    appears, and anything dangerous is flagged before you open it.
                </p>
            </div>

            {!browserWatching && (
                <BrowserWatcherSetup extensionPath={coverage.extension_path} />
            )}

            <div>
                <h3 style={{ margin: '0 0 3px 0', fontSize: '0.9rem', color: 'var(--text-primary)' }}>Automatic monitoring</h3>
                <p style={{ margin: '0 0 11px 0', fontSize: '0.77rem', color: 'var(--text-dim)' }}>
                    These watch for mail on their own. Only the SMTP gateway sees a message before it is
                    delivered — for a provider like Gmail, nothing on this computer can see mail before
                    Google does, so the earliest anything else can act is before you open it.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '11px' }}>
                    {automatic.map(card)}
                </div>
            </div>

            <div>
                <h3 style={{ margin: '0 0 3px 0', fontSize: '0.9rem', color: 'var(--text-primary)' }}>When something sends a message in</h3>
                <p style={{ margin: '0 0 11px 0', fontSize: '0.77rem', color: 'var(--text-dim)' }}>
                    Always available, but nothing arrives through these unless you or another system sends it.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '11px' }}>
                    {manual.map(card)}
                </div>
            </div>

            {coverage.limitation && (
                <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', fontStyle: 'italic', lineHeight: 1.6 }}>
                    {coverage.limitation}
                </div>
            )}
        </div>
    );
}
