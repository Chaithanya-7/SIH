import React, { useState, useEffect } from 'react';
import { Microscope, FileSearch, Radar, ShieldCheck, ScanLine, CheckCircle2, Circle } from 'lucide-react';
import { api } from '../services/api';

/**
 * How deeply a message can be examined on this machine, and what is not being
 * looked at.
 *
 * Every one of these is optional. PhishLens reads and judges every message
 * without any of them installed, and the page has to say that clearly, because
 * a list of mostly-grey rows on a security tool reads as "broken" when it
 * actually means "two optional depths are unopened".
 *
 * The opposite misreading matters more. A tool that is absent finds nothing,
 * which looks identical to a tool that ran and found nothing - so each row says
 * what its absence costs, in the terms of the thing it would have found rather
 * than the name of the program that would have found it.
 *
 * Nothing here is bought. Every tool listed is open source and runs locally.
 */

const TOOL_META = {
    olevba: {
        icon: FileSearch,
        plain: 'Reads the macro code inside Office attachments',
        absent: 'Documents that carry macros are still detected, and the code inside them is not read.'
    },
    tshark: {
        icon: Radar,
        plain: 'Notices if this computer visits a dangerous link',
        absent: 'A dangerous link can be reported, but not whether anybody followed it.'
    },
    yara: {
        icon: ScanLine,
        plain: 'Widens what a detection rule may be written in',
        // Deliberately not "rules are not running". They are: the panel says so
        // directly above this list. Installing YARA only allows rules that use
        // parts of the language the built-in engine does not implement.
        absent: 'The rules that ship with PhishLens all run without it. It would only be needed for rules using parts of YARA the built-in engine does not implement.'
    },
    clamscan: {
        icon: ShieldCheck,
        plain: 'Checks attachments against known malware signatures',
        absent: 'Files already known to be malicious are not recognised by name.'
    }
};

export default function DetectionDepth() {
    const [state, setState] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let cancelled = false;

        // api is a set of named methods, not an axios instance. Calling a
        // generic api.get threw during render, and with no error boundary above
        // it that unmounted the whole console - every page, not just this panel.
        api.getSecurityTools()
            .then(data => { if (!cancelled) setState(data); })
            .catch(err => { if (!cancelled) setError(err.response?.data?.error || err.message); });

        return () => { cancelled = true; };
    }, []);

    if (error) return <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>Could not check which tools are installed: {error}</div>;
    if (!state) return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Checking…</div>;

    const tools = state.tools || [];
    const present = tools.filter(t => t.available).length;

    return (
        <div style={{
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            padding: '20px'
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <Microscope size={18} style={{ color: 'var(--accent)' }} />
                <h3 style={{ margin: 0, fontSize: '0.95rem', color: 'var(--text-primary)' }}>How closely attachments are examined</h3>
            </div>

            {/* Said before the list, so the grey rows below are read correctly. */}
            <p style={{ margin: '0 0 16px', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Every email is checked whether or not anything below is installed. These are extra
                tools that go deeper — all free, all open source, all running on this computer.
                Adding one is optional; {present === 0 ? 'none are' : `${present} of ${tools.length} are`} installed.
            </p>

            {state.rule_matching && state.rule_matching.rules_loaded > 0 && (
                <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: '13px',
                    background: 'var(--tint-success)',
                    border: '1px solid var(--border)',
                    borderRadius: '9px',
                    padding: '13px 15px',
                    marginBottom: '14px'
                }}>
                    <CheckCircle2 size={17} style={{ color: 'var(--success)', flexShrink: 0, marginTop: '2px' }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 500 }}>
                            {state.rule_matching.rules_loaded} detection rules are running
                        </div>
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '5px', lineHeight: 1.5 }}>
                            These look for how an attack is built rather than what it says — a page that
                            asks you to paste a command, an image carrying script, a shortcut that runs a
                            shell. They need nothing installed and are always on.
                        </div>
                        {state.rule_matching.rule_errors && state.rule_matching.rule_errors.length > 0 && (
                            /* A rule that failed to compile matches nothing, which reads
                               exactly like a rule that found nothing. Never silent. */
                            <div style={{ fontSize: '0.73rem', color: 'var(--danger)', marginTop: '6px' }}>
                                {state.rule_matching.rule_errors.length} rule(s) could not be loaded and were not applied.
                            </div>
                        )}
                    </div>
                </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {tools.map(tool => {
                    const meta = TOOL_META[tool.key] || {};
                    const Icon = meta.icon || Circle;

                    return (
                        <div key={tool.key} style={{
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '13px',
                            background: 'var(--bg-surface)',
                            border: '1px solid var(--border)',
                            borderRadius: '9px',
                            padding: '13px 15px',
                            // An absent tool is stated, not alarming: it is not a fault.
                            opacity: tool.available ? 1 : 0.82
                        }}>
                            <Icon size={17} style={{ color: tool.available ? 'var(--success)' : 'var(--text-dim)', flexShrink: 0, marginTop: '2px' }} />

                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '9px', flexWrap: 'wrap' }}>
                                    <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 500 }}>
                                        {meta.plain || tool.purpose}
                                    </span>
                                    {tool.available ? (
                                        <span style={{
                                            display: 'inline-flex', alignItems: 'center', gap: '4px',
                                            fontSize: '0.68rem', color: 'var(--success)',
                                            background: 'var(--tint-success)', borderRadius: '5px', padding: '2px 7px'
                                        }}>
                                            <CheckCircle2 size={11} /> Installed
                                        </span>
                                    ) : (
                                        <span style={{
                                            fontSize: '0.68rem', color: 'var(--text-muted)',
                                            background: 'var(--tint-neutral)', borderRadius: '5px', padding: '2px 7px'
                                        }}>
                                            Not installed
                                        </span>
                                    )}
                                </div>

                                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '5px', lineHeight: 1.5 }}>
                                    {/* What its absence costs, rather than what the program is called. */}
                                    {tool.available ? tool.limitation : meta.absent}
                                </div>

                                <div style={{ fontSize: '0.71rem', color: 'var(--text-dim)', marginTop: '6px' }}>
                                    {tool.available
                                        ? `${tool.name} ${tool.version} · ${tool.license}`
                                        : <>To add it: <code style={{ color: 'var(--text-muted)' }}>{tool.install_hint}</code></>}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
