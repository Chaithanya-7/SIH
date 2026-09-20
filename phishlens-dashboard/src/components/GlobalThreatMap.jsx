import React, { useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Tooltip } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

/**
 * Every geolocated address the deployment has observed, placed on a pannable
 * world map and coloured by the severity of the worst case it appeared in.
 *
 * Marker size reflects how often an address has been seen rather than how
 * dangerous it is, so a single high-severity hit stays visible while repeat
 * infrastructure reads as heavier. Severity is carried by colour alone so the
 * two dimensions cannot be confused.
 */

const SEVERITY = {
    HIGH: { colour: 'var(--danger)', label: 'High risk' },
    MEDIUM: { colour: 'var(--warning)', label: 'Suspicious' },
    LOW: { colour: 'var(--success)', label: 'Low / legitimate' }
};

function radiusFor(observations) {
    // Square-rooted so one very noisy address cannot swamp the map.
    return Math.min(18, 5 + Math.sqrt(observations) * 2.2);
}

export default function GlobalThreatMap({ points = [], coverage }) {
    const ordered = useMemo(() => {
        // Draw lower severities first so high-risk markers are never hidden beneath them.
        const rank = { LOW: 0, MEDIUM: 1, HIGH: 2 };
        return points.slice().sort((a, b) => rank[a.severity] - rank[b.severity]);
    }, [points]);

    const counts = useMemo(() => ({
        HIGH: points.filter(p => p.severity === 'HIGH').length,
        MEDIUM: points.filter(p => p.severity === 'MEDIUM').length,
        LOW: points.filter(p => p.severity === 'LOW').length
    }), [points]);

    return (
        <div style={{
            backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)',
            borderRadius: '8px', overflow: 'hidden', display: 'flex', flexDirection: 'column'
        }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                    <h3 style={{ margin: 0, fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>Observed sending infrastructure</h3>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                        {points.length} located address{points.length === 1 ? '' : 'es'} · drag to pan, scroll to zoom
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '14px', fontSize: '0.7rem' }}>
                    {Object.entries(SEVERITY).map(([key, meta]) => (
                        <span key={key} style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--text-muted)' }}>
                            <span style={{ width: '9px', height: '9px', borderRadius: '50%', backgroundColor: meta.colour, display: 'inline-block' }} />
                            {meta.label} ({counts[key]})
                        </span>
                    ))}
                </div>
            </div>

            <div style={{ height: '420px', width: '100%' }}>
                <MapContainer
                    center={[22, 12]}
                    zoom={2}
                    minZoom={2}
                    scrollWheelZoom
                    worldCopyJump
                    style={{ height: '100%', width: '100%', backgroundColor: 'var(--bg-code)' }}
                >
                    <TileLayer
                        attribution='&copy; OpenStreetMap contributors'
                        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        noWrap={false}
                    />
                    {ordered.map(point => {
                        const meta = SEVERITY[point.severity] || SEVERITY.LOW;
                        return (
                            <CircleMarker
                                key={point.ip}
                                center={[point.latitude, point.longitude]}
                                radius={radiusFor(point.observations)}
                                pathOptions={{
                                    color: meta.colour,
                                    fillColor: meta.colour,
                                    fillOpacity: 0.55,
                                    weight: 1.5
                                }}
                            >
                                <Tooltip direction="top" opacity={1}>
                                    <span style={{ fontWeight: 600 }}>{point.ip}</span>
                                    {point.city ? ` — ${point.city}` : ''}{point.country ? `, ${point.country}` : ''}
                                </Tooltip>
                                <Popup>
                                    <div style={{ fontSize: '0.78rem', lineHeight: 1.6, minWidth: '210px' }}>
                                        <div style={{ fontWeight: 700, marginBottom: '4px' }}>{point.ip}</div>
                                        <div><strong>Location:</strong> {point.city || 'Unknown city'}{point.country ? `, ${point.country}` : ''}</div>
                                        <div><strong>Network:</strong> {point.asn || 'Unknown'} {point.isp ? `(${point.isp})` : ''}</div>
                                        <div><strong>Observed as:</strong> {String(point.role || '').replace(/_/g, ' ').toLowerCase()}</div>
                                        <div><strong>Severity:</strong> {meta.label}</div>
                                        <div><strong>Seen in:</strong> {point.observations} case{point.observations === 1 ? '' : 's'}</div>
                                        <div style={{ marginTop: '5px', fontSize: '0.7rem', opacity: 0.75 }}>
                                            Location of the sending infrastructure, not of any person.
                                        </div>
                                    </div>
                                </Popup>
                            </CircleMarker>
                        );
                    })}
                </MapContainer>
            </div>

            {coverage && (
                <div style={{ padding: '9px 16px', borderTop: '1px solid var(--border)', fontSize: '0.68rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    {coverage.limitation}
                </div>
            )}
        </div>
    );
}
