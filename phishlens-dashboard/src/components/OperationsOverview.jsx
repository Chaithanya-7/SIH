import React, { useState, useEffect } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
    ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';
import { api } from '../services/api';
import GlobalThreatMap from './GlobalThreatMap';

/**
 * The operations overview: what arrived, how it was judged, where it came from
 * and which rules are firing.
 *
 * Counts are stated plainly and every figure is derived from stored cases, so
 * nothing on this screen is an estimate. An empty deployment says it is empty
 * rather than rendering an impressive-looking chart of nothing.
 */

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

export default function OperationsOverview() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    const load = async () => {
        try {
            setData(await api.getOverview());
            setError(null);
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
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                <StatCard label="Messages analysed" value={counts.total} tone="accent" />
                <StatCard label="High risk" value={counts.high_risk} tone="danger" />
                <StatCard label="Suspicious" value={counts.suspicious} tone="warning" />
                <StatCard label="Legitimate" value={counts.safe} tone="success" />
                <StatCard label="Quarantined" value={counts.quarantined} sub={`${counts.awaiting_review} awaiting review`} />
                <StatCard label="Campaigns" value={counts.campaigns} sub={`${counts.executive_incidents} executive incident(s)`} />
            </div>

            <GlobalThreatMap points={points} coverage={coverage} />

            <div className="overview-split" style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '16px' }}>
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
    );
}
