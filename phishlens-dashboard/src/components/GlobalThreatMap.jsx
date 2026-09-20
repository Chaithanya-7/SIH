import React, { useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Tooltip } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

/**
 * Every geolocated address the deployment has observed, placed on a world map
 * and coloured by the severity of the worst case it appeared in.
 *
 * Marker size reflects how often an address has been seen rather than how
 * dangerous it is, so a single high-severity hit stays visible while repeat
 * infrastructure reads as heavier. Severity is carried by colour alone so the
 * two dimensions cannot be confused.
 *
 * Clicking a marker answers the question a dot on a map actually provokes -
 * what arrived from there - by listing the messages rather than reporting a
 * count.
 */

const SEVERITY = {
    HIGH: { colour: 'var(--danger)', label: 'High risk' },
    MEDIUM: { colour: 'var(--warning)', label: 'Suspicious' },
    LOW: { colour: 'var(--success)', label: 'Low / legitimate' }
};

const VERDICT_LABEL = {
    HIGH_RISK: 'High risk',
    SUSPICIOUS: 'Suspicious',
    SAFE: 'Legitimate',
    UNKNOWN: 'Not classified'
};

function radiusFor(observations) {
    // Square-rooted so one very noisy address cannot swamp the map.
    return Math.min(18, 5 + Math.sqrt(observations) * 2.2);
}

function when(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

/**
 * The basemap, and why it is OpenStreetMap's own tiles.
 *
 * CARTO's basemaps were tried here first: muted, dark, and served at double
 * resolution, which is exactly what this panel wants. They now render the words
 * "API KEY REQUIRED" across every tile. That is a paid dependency, and this
 * tool is not allowed one - so the map uses OpenStreetMap's own tile service,
 * which needs no key and no account and asks only for attribution.
 *
 * The honest trade: OSM serves no double-resolution tile, so there is no @2x
 * variant to request and labels are softer on a high-density screen than a paid
 * basemap would be. That is the cost of the constraint.
 *
 * Their cartography is light, which glares inside a dark console. It is turned
 * dark by a CSS filter on `.leaflet-tile` in theme.css, which already follows
 * the theme - a second copy of that logic lived here briefly and was removed.
 */
const OSM_TILES = {
    url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; OpenStreetMap contributors'
};


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
                    <h3 style={{ margin: 0, fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>Where messages were sent from</h3>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                        {points.length} located address{points.length === 1 ? '' : 'es'} · drag to pan, scroll to zoom, click a dot to see the messages
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

            <div style={{ height: '620px', width: '100%' }}>
                <MapContainer
                    center={[22, 12]}
                    zoom={2}
                    minZoom={2}
                    // Deep enough for individual streets and buildings. OpenStreetMap
                    // publishes tiles to zoom 19; asking for more only stretches the
                    // last real tile and invents detail that is not there.
                    maxZoom={19}
                    scrollWheelZoom
                    // The world is not repeated sideways.
                    //
                    // Leaflet otherwise pans into a second and third copy of the
                    // globe, so the same country appears more than once and a marker
                    // looks like it exists in several places at the same time.
                    // `worldCopyJump` made it worse by teleporting the view between
                    // copies mid-drag, which is the jump that felt like a glitch.
                    worldCopyJump={false}
                    maxBounds={[[-85, -180], [85, 180]]}
                    maxBoundsViscosity={1.0}
                    style={{ height: '100%', width: '100%', backgroundColor: 'var(--bg-code)' }}
                >
                    <TileLayer
                        attribution={OSM_TILES.attribution}
                        url={OSM_TILES.url}
                        // OpenStreetMap publishes to 19; asking for more only
                        // stretches the last real tile and invents detail.
                        maxZoom={19}
                        // Tiles stop at the edge of the world rather than repeating.
                        noWrap
                        bounds={[[-85, -180], [85, 180]]}
                    />
                    {ordered.map(point => {
                        const meta = SEVERITY[point.severity] || SEVERITY.LOW;
                        const messages = point.messages || [];
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
                                    <span style={{ fontWeight: 600 }}>
                                        {point.city || point.country || point.ip}
                                    </span>
                                    {' — '}{point.observations} message{point.observations === 1 ? '' : 's'}
                                </Tooltip>

                                <Popup maxWidth={420} minWidth={320}>
                                    <div style={{ fontSize: '0.78rem', lineHeight: 1.55 }}>
                                        <div style={{ fontWeight: 700, fontSize: '0.86rem', marginBottom: '2px' }}>
                                            {point.city ? `${point.city}, ` : ''}{point.country || 'Unknown location'}
                                        </div>
                                        <div style={{ color: '#555', fontSize: '0.72rem', marginBottom: '8px' }}>
                                            {point.ip}{point.isp ? ` · ${point.isp}` : ''}{point.asn ? ` (${point.asn})` : ''}
                                        </div>

                                        <div style={{ fontWeight: 700, fontSize: '0.74rem', marginBottom: '5px' }}>
                                            {point.observations} message{point.observations === 1 ? '' : 's'} sent from here
                                        </div>

                                        <div style={{ maxHeight: '190px', overflowY: 'auto' }}>
                                            {messages.length === 0 ? (
                                                <div style={{ fontSize: '0.72rem', color: '#666' }}>
                                                    No message details were recorded for this address.
                                                </div>
                                            ) : messages.map(m => (
                                                <div key={m.case_id} style={{ borderTop: '1px solid #e4e4e4', padding: '6px 0' }}>
                                                    <div style={{ fontWeight: 600 }}>{m.subject}</div>
                                                    <div style={{ fontSize: '0.72rem', color: '#444' }}>from {m.sender}</div>
                                                    <div style={{ fontSize: '0.72rem', marginTop: '2px' }}>
                                                        <strong>{VERDICT_LABEL[m.verdict] || m.verdict}</strong>
                                                        {m.confidence != null ? ` · ${Math.round(m.confidence * 100)}% confidence` : ''}
                                                        {when(m.received_at) ? ` · ${when(m.received_at)}` : ''}
                                                    </div>
                                                    {m.top_finding && (
                                                        <div style={{ fontSize: '0.71rem', color: '#555', marginTop: '3px' }}>
                                                            {m.top_finding}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                            {point.observations > messages.length && (
                                                <div style={{ fontSize: '0.7rem', color: '#666', paddingTop: '6px' }}>
                                                    …and {point.observations - messages.length} more. Open Investigations to see them all.
                                                </div>
                                            )}
                                        </div>

                                        <div style={{ marginTop: '7px', fontSize: '0.69rem', color: '#666', borderTop: '1px solid #e4e4e4', paddingTop: '5px' }}>
                                            This is where the sending computer is, not where any person is.
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
