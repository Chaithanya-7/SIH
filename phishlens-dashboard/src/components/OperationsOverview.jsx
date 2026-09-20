import React, { useState, useEffect } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
    ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';
import { api } from '../services/api';
import GlobalThreatMap from './GlobalThreatMap';
import { Inbox } from 'lucide-react';

/**
 * The operations overview: what arrived, how it was judged, where it came from
 * and which rules are firing.
 *
 * Counts are stated plainly and every figure is derived from stored cases, so
 * nothing on this screen is an estimate. An empty deployment says it is empty
 * rather than rendering an impressive-looking chart of nothing.
 */

const VERDICT_STYLE = {
    HIGH_RISK: { label: 'Dangerous', colour: 'var(--danger)', tint: 'var(--tint-danger)' },
    SUSPICIOUS: { label: 'Suspicious', colour: 'var(--warning)', tint: 'var(--tint-warning)' },
    SAFE: { label: 'Looks fine', colour: 'var(--success)', tint: 'var(--tint-success)' },
    UNKNOWN: { label: 'Not classified', colour: 'var(--text-dim)', tint: 'var(--tint-neutral)' }
};

const SEVERITY_COLOUR = {
    CRITICAL: 'var(--danger)',
    HIGH: 'var(--danger)',
    MEDIUM: 'var(--warning)',
    LOW: 'var(--text-dim)'
};

function StatCard({ label, value, tone = 'neutral', sub }) {
    const toneColour = {
        danger: 'var(--danger)',
        warning: 'var(--warning)',
        success: 'var(--success)',
        accent: 'var(--accent)',
        neutral: 'var(--text-primary)'
    }[tone];

    return (
        <div style={{
            backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)',
            borderRadius: '8px', padding: '16px 18px', flex: '1 1 150px', minWidth: '150px'
        }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 500 }}>{label}</div>
            <div style={{ fontSize: '2.1rem', fontWeight: 700, color: toneColour, lineHeight: 1.15, marginTop: '4px' }}>{value}</div>
            {sub && <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '2px' }}>{sub}</div>}
        </div>
    );
}

function Panel({ title, subtitle, children, padded = true }) {
    return (
        <div style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <h3 style={{ margin: 0, fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>{title}</h3>
                {subtitle && <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '2px' }}>{subtitle}</div>}
            </div>
            <div style={{ padding: padded ? '14px 16px' : 0 }}>{children}</div>
        </div>
    );
}

/**
 * Every message that has been examined, on the page that claims to be the
 * overview.
 *
 * The overview reported six totals and then moved on to charts, so the one
 * question those totals invite - which emails are they? - was the one thing it
 * would not show. The counts and this list now come from the same cases.
 */
function EveryEmail({ cases, onOpenCase }) {
    const [filter, setFilter] = useState('ALL');

    const ordered = React.useMemo(() => {
        const matching = filter === 'ALL'
            ? cases
            : cases.filter(c => (c.detection?.verdict || 'UNKNOWN') === filter);
        return matching.slice().sort((a, b) =>
            new Date(b.timestamps?.ingested_at || 0) - new Date(a.timestamps?.ingested_at || 0));
    }, [cases, filter]);

    const tabs = [
        { id: 'ALL', label: 'All' },
        { id: 'HIGH_RISK', label: 'Dangerous' },
        { id: 'SUSPICIOUS', label: 'Suspicious' },
        { id: 'SAFE', label: 'Looks fine' }
    ];

    return (
        <Panel
            title="Every email examined"
            subtitle={cases.length + ' in total \u00b7 click any one to see what was found'}
            padded={false}
        >
            <div style={{ display: 'flex', gap: '6px', padding: '10px 16px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
                {tabs.map(tab => {
                    const count = tab.id === 'ALL'
                        ? cases.length
                        : cases.filter(c => (c.detection?.verdict || 'UNKNOWN') === tab.id).length;
                    const active = filter === tab.id;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setFilter(tab.id)}
                            style={{
                                background: active ? 'var(--accent)' : 'var(--bg-surface)',
                                color: active ? 'var(--text-on-accent)' : 'var(--text-muted)',
                                border: '1px solid ' + (active ? 'var(--accent)' : 'var(--border)'),
                                borderRadius: '999px', padding: '4px 12px',
                                fontSize: '0.73rem', fontWeight: active ? 600 : 500, cursor: 'pointer'
                            }}
                        >
                            {tab.label} ({count})
                        </button>
                    );
                })}
            </div>

            {ordered.length === 0 ? (
                <div style={{ padding: '28px 18px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.79rem' }}>
                    {cases.length === 0
                        ? 'No emails have been examined yet. Switch on monitoring under "Where mail arrives", or drop one onto "Check an email".'
                        : 'No email has that result.'}
                </div>
            ) : (
                <div style={{ maxHeight: '340px', overflowY: 'auto' }}>
                    {ordered.map(item => {
                        const meta = VERDICT_STYLE[item.detection?.verdict] || VERDICT_STYLE.UNKNOWN;
                        return (
                            <div
                                key={item.case_id}
                                onClick={() => onOpenCase && onOpenCase(item.case_id)}
                                title="Open the full examination of this email"
                                style={{
                                    padding: '10px 16px', borderBottom: '1px solid var(--border)',
                                    display: 'flex', alignItems: 'center', gap: '12px',
                                    cursor: onOpenCase ? 'pointer' : 'default'
                                }}
                            >
                                <span style={{
                                    width: '8px', height: '8px', borderRadius: '50%',
                                    backgroundColor: meta.colour, flexShrink: 0
                                }} />
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{
                                        fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 500,
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                                    }}>
                                        {item.message?.subject || '(no subject)'}
                                    </div>
                                    <div style={{
                                        fontSize: '0.72rem', color: 'var(--text-muted)',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                                    }}>
                                        from {item.message?.sender || '(unknown sender)'}
                                    </div>
                                </div>
                                <span style={{
                                    fontSize: '0.68rem', fontWeight: 700, padding: '3px 9px', borderRadius: '999px',
                                    background: meta.tint, color: meta.colour, whiteSpace: 'nowrap', flexShrink: 0
                                }}>
                                    {meta.label}
                                </span>
                                <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', whiteSpace: 'nowrap', flexShrink: 0 }}>
                                    {item.timestamps?.ingested_at
                                        ? new Date(item.timestamps.ingested_at).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
                                        : ''}
                                </span>
                            </div>
                        );
                    })}
                </div>
            )}
        </Panel>
    );
}

export default function OperationsOverview({ cases = [], onOpenCase, onNavigate }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [mailboxCount, setMailboxCount] = useState(null);

    const load = async () => {
        try {
            setData(await api.getOverview());
            setError(null);
            // Whether any live mail is being read at all. Asked here because
            // this is the page somebody lands on, and "0 emails examined" and
            // "nothing is connected" are very different problems wearing the
            // same face.
            try {
                const connections = await api.getConnections();
                setMailboxCount((connections.mailboxes || []).length);
            } catch (e) {
                setMailboxCount(null);
            }
        } catch (e) {
            setError(e.response?.data?.error || e.message);
        }
    };

    useEffect(() => {
        load();
        const interval = setInterval(load, 10000);
        return () => clearInterval(interval);
    }, []);

    if (error) return <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>Could not load the overview: {error}</div>;
    if (!data) return <div style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Loading overview…</div>;

    const { counts, timeline, rule_summary: rules, ingestion_breakdown: sources, map_points: points, geo_coverage: coverage } = data;

    const chartData = timeline.map(bucket => ({
        time: new Date(bucket.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        'High risk': bucket.high_risk,
        Suspicious: bucket.suspicious,
        Safe: bucket.safe
    }));

    const sourceColours = ['var(--accent)', 'var(--violet)', 'var(--success)', 'var(--warning)', 'var(--pink)', 'var(--brand-cyan)'];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {mailboxCount === 0 && (
                <div style={{
                    background: 'var(--tint-warning)', border: '1px solid var(--warning)',
                    borderRadius: '8px', padding: '16px 18px',
                    display: 'flex', alignItems: 'center', gap: '15px', flexWrap: 'wrap'
                }}>
                    <Inbox size={22} style={{ color: 'var(--warning)', flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: '240px' }}>
                        <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                            No mail is being watched yet
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '3px', lineHeight: 1.55 }}>
                            PhishLens can watch the ways mail reaches this computer — your browser, a
                            desktop mail app, or mail delivered straight to it. Until one is switched on
                            it only sees emails you hand it yourself.
                        </div>
                    </div>
                    <button
                        onClick={() => onNavigate && onNavigate('sources')}
                        style={{
                            background: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none',
                            borderRadius: '6px', padding: '10px 17px', fontSize: '0.83rem',
                            fontWeight: 600, cursor: 'pointer', flexShrink: 0
                        }}
                    >
                        Set up monitoring
                    </button>
                </div>
            )}

            {/*
              * Two columns, with the map given the height it needs.
              *
              * This was one tall stack, so the map sat between a list and a
              * chart and nothing could be compared without scrolling past
              * something else. A summary screen is meant to be taken in at
              * once: the numbers and the detail on the left, where reading
              * starts, and the map beside them rather than below.
              *
              * `desktop-grid` is what collapses this to a single column under
              * 1024px. The class used here before, `overview-split`, had no CSS
              * rule behind it at all, so the layout never collapsed and a
              * narrow window squeezed both columns instead of stacking them.
              */}
            <div
                className="desktop-grid"
                style={{ display: 'grid', gridTemplateColumns: '1.55fr 1fr', gap: '16px', alignItems: 'start' }}
            >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                            <StatCard label="Emails examined" value={counts.total} tone="accent" />
                            <StatCard label="Dangerous" value={counts.high_risk} tone="danger" />
                            <StatCard label="Suspicious" value={counts.suspicious} tone="warning" />
                            <StatCard label="Looks fine" value={counts.safe} tone="success" />
                            <StatCard label="Held back" value={counts.quarantined} sub={`${counts.awaiting_review} waiting for a decision`} />
                            <StatCard label="Linked attacks" value={counts.campaigns} sub={`${counts.executive_incidents} aimed at a protected person`} />
                        </div>

                    <EveryEmail cases={cases} onOpenCase={onOpenCase} />

                    <Panel title="Activity over the last 24 hours" subtitle="Messages analysed per 30 minutes, by verdict">
                        {counts.total === 0 ? (
                            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic', padding: '30px 0', textAlign: 'center' }}>
                                No messages have been analysed yet.
                            </div>
                        ) : (
                            <div style={{ height: '230px' }}>
                                <ResponsiveContainer width="100%" height="100%">
                                    <AreaChart data={chartData} margin={{ top: 6, right: 8, left: -20, bottom: 0 }}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                                        <XAxis dataKey="time" tick={{ fill: 'var(--text-dim)', fontSize: 10 }} interval="preserveStartEnd" minTickGap={40} />
                                        <YAxis tick={{ fill: 'var(--text-dim)', fontSize: 10 }} allowDecimals={false} />
                                        <ReTooltip
                                            contentStyle={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '0.75rem' }}
                                            labelStyle={{ color: 'var(--text-primary)' }}
                                        />
                                        <Area type="monotone" dataKey="Safe" stackId="1" stroke="var(--success)" fill="var(--success)" fillOpacity={0.25} />
                                        <Area type="monotone" dataKey="Suspicious" stackId="1" stroke="var(--warning)" fill="var(--warning)" fillOpacity={0.3} />
                                        <Area type="monotone" dataKey="High risk" stackId="1" stroke="var(--danger)" fill="var(--danger)" fillOpacity={0.35} />
                                    </AreaChart>
                                </ResponsiveContainer>
                            </div>
                        )}
                    </Panel>

                    <Panel title="Detections by rule" subtitle="Which rules are firing, and how often" padded={false}>
                            {rules.length === 0 ? (
                                <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic', padding: '26px', textAlign: 'center' }}>
                                    No detection rule has matched a message yet.
                                </div>
                            ) : (
                                <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
                                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem' }}>
                                        <thead>
                                            <tr style={{ position: 'sticky', top: 0, backgroundColor: 'var(--bg-surface)' }}>
                                                <th style={{ textAlign: 'left', padding: '9px 16px', color: 'var(--text-muted)', fontWeight: 600, borderBottom: '1px solid var(--border)' }}>Rule</th>
                                                <th style={{ textAlign: 'left', padding: '9px 12px', color: 'var(--text-muted)', fontWeight: 600, borderBottom: '1px solid var(--border)', width: '110px' }}>Severity</th>
                                                <th style={{ textAlign: 'right', padding: '9px 16px', color: 'var(--text-muted)', fontWeight: 600, borderBottom: '1px solid var(--border)', width: '90px' }}>Events</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {rules.map(rule => (
                                                <tr key={rule.id}>
                                                    <td style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                                                        <span className="font-mono" style={{ color: 'var(--accent)', marginRight: '8px' }}>{rule.id}</span>
                                                        {rule.name}
                                                    </td>
                                                    <td style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)', color: SEVERITY_COLOUR[rule.severity] || 'var(--text-muted)', fontWeight: 600 }}>
                                                        {rule.severity}
                                                    </td>
                                                    <td style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', textAlign: 'right', color: 'var(--text-primary)', fontWeight: 600 }}>
                                                        {rule.events}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </Panel>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', minWidth: 0 }}>
                    <GlobalThreatMap points={points} coverage={coverage} />

                    <Panel title="Where messages entered" subtitle="Ingestion path breakdown">
                        {sources.length === 0 ? (
                            <div style={{ color: 'var(--text-dim)', fontSize: '0.78rem', fontStyle: 'italic', padding: '30px 0', textAlign: 'center' }}>
                                No messages have arrived through any path yet.
                            </div>
                        ) : (
                            <div style={{ height: '230px' }}>
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie data={sources} dataKey="count" nameKey="source" innerRadius={48} outerRadius={80} paddingAngle={2}>
                                            {sources.map((entry, i) => <Cell key={entry.source} fill={sourceColours[i % sourceColours.length]} />)}
                                        </Pie>
                                        <Legend wrapperStyle={{ fontSize: '0.68rem', color: 'var(--text-muted)' }} />
                                        <ReTooltip contentStyle={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '0.75rem' }} />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                        )}
                    </Panel>
                </div>
            </div>
        </div>
    );
}
