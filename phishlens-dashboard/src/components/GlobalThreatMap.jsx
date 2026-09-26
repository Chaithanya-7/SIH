import React, { useMemo, useState, useEffect } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Tooltip, useMap } from 'react-leaflet';
import L from 'leaflet';
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

/**
 * The severity colours, resolved to actual colour values.
 *
 * The markers are drawn onto a canvas, and a canvas context cannot resolve CSS
 * custom properties: assigning "var(--danger)" to fillStyle is simply rejected
 * and the previous value stays. The markers were therefore painted with nothing
 * and the map came up empty, while the heading above it correctly said how many
 * addresses there were. In SVG mode the same code works, because the fill is an
 * attribute in the document and inherits the variable - which is why this was
 * easy to miss.
 *
 * Re-read when the theme changes, so switching between light and dark repaints
 * the markers rather than leaving them the previous theme's colour.
 */
function useSeverityColours() {
    const read = () => {
        const styles = getComputedStyle(document.documentElement);
        // The fallbacks are what gets used if a variable is ever renamed: a
        // visible marker in roughly the right colour beats an invisible one.
        const resolve = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
        return {
            HIGH: resolve('--danger', '#c02626'),
            MEDIUM: resolve('--warning', '#b8860b'),
            LOW: resolve('--success', '#2e7d32')
        };
    };

    const [colours, setColours] = useState(read);

    useEffect(() => {
        const observer = new MutationObserver(() => setColours(read()));
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
        return () => observer.disconnect();
    }, []);

    return colours;
}

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
 * The basemaps on offer, all of them keyless.
 *
 * CARTO's were tried first - muted, dark, double resolution, exactly what this
 * panel wants - and they now render "API KEY REQUIRED" across every tile. That
 * is a paid dependency this tool is not allowed, so everything here is a
 * service that answers without an account.
 *
 * None of them are filtered to match the console's theme. Doing that made four
 * deliberately different styles arrive looking identical, and inverting a tile
 * inverts its labels - so street and place names became least legible at
 * exactly the zoom somebody is reading them. Each renders as drawn.
 */
const BASEMAPS = [
    {
        id: 'standard',
        label: 'Standard',
        url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
        attribution: '&copy; OpenStreetMap contributors',
        maxZoom: 19
    },
    {
        id: 'satellite',
        label: 'Satellite',
        // Photography does not cover the whole planet and cannot be made to.
        // Measured: cities reach zoom 19, deserts and forest stop near 17, and
        // open ocean, Greenland and Antarctica have nothing better than 15 m per
        // pixel and stop at 11. Past the edge Esri returns a grey "no data"
        // tile, so an ordinary map is drawn underneath and those tiles are left
        // transparent. Somewhere on earth is then never blank.
        fallbackUrl: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
        // The map underneath is only ever seen where photography is missing, and
        // that is overwhelmingly ocean, ice and empty desert - places nobody
        // inspects at street level. Fetching it to zoom 19 as well doubled the
        // tiles for a layer that is invisible wherever imagery exists. Stopping
        // at 12 lets Leaflet scale those tiles instead: slightly soft in the few
        // deep-zoomed places with no photography, and free everywhere else.
        fallbackMaxZoom: 12,
        inspectTiles: true,
        url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
        attribution: 'Imagery &copy; Esri, Maxar, Earthstar Geographics',
        // Esri serves this one row-before-column, which is why the template
        // above reads {z}/{y}/{x} rather than the usual order.
        //
        // 19, which is the depth this imagery actually has everywhere.
        //
        // This was 20, from measuring one tile over Manhattan and taking it for
        // the planet. Checked across Moscow, Novosibirsk, Karachi, Islamabad,
        // Lagos, Sao Paulo, Sydney and Anchorage: 17, 18 and 19 return real
        // photography in all of them, while 20 returns it only in Sydney and
        // Anchorage. Everywhere else it answers with a 2,521-byte tile that
        // reads "Map data not yet available" - which is precisely the message
        // that appeared on zooming in.
        //
        // Stopping at 19 and letting Leaflet scale beyond it trades a little
        // sharpness in the few cities that have 20 for never showing that tile
        // anywhere. Individual buildings and vehicles are still legible at 19.
        maxZoom: 19,
        // Photography carries no writing. On its own this showed rooftops and
        // coastlines with no way to tell which city you were looking at, which
        // is useless for the question the panel exists to answer. Esri publish
        // free reference layers that draw roads and names over imagery, and
        // they are what make it readable rather than merely detailed.
        overlays: [
            {
                id: 'transport',
                url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Transportation/MapServer/tile/{z}/{y}/{x}',
                maxZoom: 19,
                // Roads are not drawn until somebody is close enough to read a
                // street, because that is the only zoom at which they say
                // anything - and they are not free.
                //
                // Measured: one zoom costs 24 tile requests per layer, and the
                // wait is very nearly linear in the total. Imagery alone
                // finishes in about 840ms, imagery and place names in 1440ms,
                // all three in 2350ms. Street geometry over a whole country is
                // a grey haze that costs 900ms of that, on every zoom, at the
                // levels this map spends most of its time.
                minZoom: 9
            },
            {
                id: 'places',
                url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}',
                maxZoom: 19
            }
        ]
    },
    {
        id: 'uniform',
        label: 'Uniform 2024',
        // The honest answer to "I do not want old imagery".
        //
        // The satellite layer above is already the newest photography Esri
        // publishes - verified by fetching the same tiles from Esri's own
        // newest archived release and comparing them byte for byte: identical.
        // There is no newer free source to switch to, and there is no paid one
        // with globally current coverage either.
        //
        // What can be fixed is the *unevenness*. Esri's mosaic is assembled from
        // flights and passes of wildly different ages: a city may be months old
        // while parts of Siberia have nothing newer than 2012. This layer is a
        // single cloud-free Sentinel-2 composite for one stated year, so every
        // place on earth is from the same recent period.
        //
        // The trade is resolution: 10 metres per pixel against sub-metre in
        // cities, so it stops at zoom 14 and shows no buildings. Offered beside
        // the others rather than instead of them, because for a location where
        // Esri's photography is a decade old this is genuinely the more current
        // picture, and for a city centre it is plainly the worse one.
        url: 'https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless-2024_3857/default/g/{z}/{y}/{x}.jpg',
        attribution: 'Sentinel-2 cloudless 2024 by EOX IT Services, contains modified Copernicus Sentinel data',
        maxZoom: 14,
        maxNativeZoom: 14,
        // Same treatment as the satellite layer: a drawn map underneath so
        // nowhere is ever blank, and streets on top, because a 10 m composite
        // has no roads a person can follow.
        fallbackUrl: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
        fallbackMaxZoom: 12,
        uniformYear: 2024
    },
    {
        id: 'terrain',
        label: 'Terrain',
        url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
        attribution: '&copy; OpenStreetMap contributors, SRTM | &copy; OpenTopoMap',
        subdomains: 'abc',
        maxZoom: 17
    },
    {
        id: 'plain',
        label: 'Plain',
        url: 'https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png',
        attribution: '&copy; OpenStreetMap contributors | Humanitarian OSM Team',
        subdomains: 'abc',
        maxZoom: 19
    }
];

// Imagery by default.
//
// The console is dark, and a drawn map has to be inverted to sit in it - which
// pushes OpenStreetMap's pale ocean to within a shade of the panel behind it and
// leaves very little to read. Satellite imagery is already dark, needs no
// filtering at all, and separates land from sea by itself. The drawn maps stay
// one choice away for anyone who wants labels and borders.
// Two levels past the deepest imagery any basemap publishes.
//
// Past a source's own maxNativeZoom Leaflet scales the deepest real tile rather
// than asking for one that does not exist, so this is how much closer somebody
// may look. Two levels is soft but readable, and it is the difference between
// running out of zoom and being shown a tile that says there is no data.
// One level past the deepest imagery that exists, not two.
//
// Past a source's own maximum there is no more detail anywhere on earth; the
// map simply magnifies the pixels it already has. Measured on this display:
// zoom 19 draws imagery at 1.25 device pixels per image pixel, zoom 20 at 2.5,
// and zoom 21 at 5.0 - by which point a building is a handful of coloured
// squares. Allowing two levels of that bought nothing but the impression that
// the map had gone out of focus.
//
// One level is kept because it is genuinely useful for placing a marker
// precisely, and the caption says when the view has passed real detail.
const DEEPEST_ZOOM = Math.max(...BASEMAPS.map(b => b.maxZoom)) + 1;

const DEFAULT_BASEMAP = 'satellite';
const BASEMAP_STORAGE_KEY = 'phishlens.basemap';

/**
 * Tells Leaflet how big its container actually is.
 *
 * Leaflet measures its container once, at construction, and caches that. This
 * map lives in a panel whose width changes - the sidebar collapses, the window
 * resizes - and without re-measuring, clicks land at the wrong coordinates and
 * the tile grid is computed for a viewport that no longer exists.
 *
 * Added while chasing a zoom that would not respond, which turned out not to be
 * this: animated zoom waits for a CSS transitionend event, and the automated
 * browser it was being tested in never fires one. Kept anyway, because
 * re-measuring on resize is correct regardless of what it did not fix.
 */
/**
 * When the photography under the cursor was actually taken.
 *
 * Satellite imagery is not "now". It is a photograph with a date, and that date
 * varies enormously by place - around ten months for Indian cities, two and a
 * half years for the United States sample checked. For a tool whose job is to
 * say where a message came from, showing a location on imagery of unstated
 * vintage invites reading it as current. So the date is stated.
 *
 * Esri publish this per tile through a free, keyless service, which is asked
 * once per view rather than once per tile. A failed or slow lookup shows
 * nothing at all: an unanswered question is better left unanswered than filled
 * with a guess.
 */
function ImageryDate({ active, onDate }) {
    const map = useMap();

    useEffect(() => {
        if (!active) { onDate(null); return; }

        let cancelled = false;
        let timer = null;

        const ask = async () => {
            const centre = map.getCenter();
            const lon = centre.lng, lat = centre.lat;
            const url = 'https://services.arcgisonline.com/arcgis/rest/services/World_Imagery/MapServer/identify'
                + `?geometry=${lon},${lat}&geometryType=esriGeometryPoint&sr=4326&layers=all&tolerance=1`
                + `&mapExtent=${lon - 0.01},${lat - 0.01},${lon + 0.01},${lat + 0.01}`
                + '&imageDisplay=600,600,96&returnGeometry=false&f=json';

            try {
                const response = await fetch(url, { signal: AbortSignal.timeout(8000) });
                const body = await response.json();
                const attributes = (body.results && body.results[0] && body.results[0].attributes) || {};
                const date = attributes['SRC_DATE2'] || attributes['DATE (YYYYMMDD)'];
                const resolution = attributes['RESOLUTION (M)'];
                if (!cancelled) onDate(date ? { date: String(date), resolution } : null);
            } catch (e) {
                // Offline, slow, or the service changed its shape. Say nothing.
                if (!cancelled) onDate(null);
            }
        };

        // Asked once the view settles, not on every frame of a pan.
        const schedule = () => {
            clearTimeout(timer);
            timer = setTimeout(ask, 900);
        };

        schedule();
        map.on('moveend zoomend', schedule);
        return () => {
            cancelled = true;
            clearTimeout(timer);
            map.off('moveend zoomend', schedule);
        };
    }, [map, active, onDate]);

    return null;
}

/** Esri gives either "11/15/2025" or "20251115". Both become a readable month and year. */
function formatImageryDate(raw) {
    const text = String(raw || '');
    let date = null;

    if (/^\d{8}$/.test(text)) {
        date = new Date(Number(text.slice(0, 4)), Number(text.slice(4, 6)) - 1, Number(text.slice(6, 8)));
    } else {
        const parsed = new Date(text);
        if (!Number.isNaN(parsed.getTime())) date = parsed;
    }

    if (!date) return text;

    const months = Math.max(0, Math.round((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24 * 30.44)));
    const when = date.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });

    // The age is the point. A date on its own still reads as recent.
    if (months < 1) return `${when} (this month)`;
    if (months < 24) return `${when} (${months} month${months === 1 ? '' : 's'} ago)`;
    return `${when} (${Math.floor(months / 12)} years ago)`;
}

/**
 * Anything Esri answers with that is smaller than this is not a photograph.
 *
 * Where Esri holds no imagery it still returns HTTP 200 and a JPEG - a grey
 * tile reading "Map data not yet available". Two of them were found, at 1652
 * and 2521 bytes, byte-identical wherever they appear. Real photography of the
 * emptiest desert measured 16KB and the smallest real tile seen was about 5KB,
 * so this threshold separates them with room to spare.
 */
const NO_IMAGERY_BYTES = 3500;

/** A 1x1 transparent GIF, for a tile that is to show nothing at all. */
const TRANSPARENT = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

/**
 * Satellite imagery that never draws a "no data" tile.
 *
 * Imagery coverage is not uniform and cannot be made so: measured across the
 * world, cities reach zoom 19 at 0.15-0.5 m per pixel, deserts and forest stop
 * around 17, and open ocean, Greenland and Antarctica have nothing better than
 * 15 m per pixel and stop at 11. Nobody photographs the open sea at half a
 * metre, so no setting can conjure it.
 *
 * What can be fixed is what happens past the edge of coverage. Esri's reply
 * there is a grey placeholder, and because it arrives as a perfectly valid
 * image with HTTP 200, Leaflet draws it like any other tile. This recognises
 * those replies by size and leaves the tile transparent instead, so the
 * ordinary map layered beneath shows through - coastlines, names, terrain -
 * rather than a grey square saying nothing is here.
 *
 * Esri serve these with Access-Control-Allow-Origin: *, which is what makes
 * inspecting them possible at all.
 */
function ImageryWithFallback({ url, subdomains, maxNativeZoom, maxZoom, keepBuffer }) {
    const map = useMap();

    useEffect(() => {
        const InspectedTileLayer = L.TileLayer.extend({
            createTile(coords, done) {
                const tile = document.createElement('img');
                tile.alt = '';
                tile.setAttribute('role', 'presentation');

                fetch(this.getTileUrl(coords))
                    .then(response => (response.ok ? response.blob() : Promise.reject(new Error(String(response.status)))))
                    .then(blob => {
                        if (blob.size < NO_IMAGERY_BYTES) {
                            // No photography here. Say nothing rather than
                            // drawing a grey square that says nothing.
                            tile.src = TRANSPARENT;
                        } else {
                            tile.src = URL.createObjectURL(blob);
                            // Released once drawn; the browser keeps its own copy.
                            tile.addEventListener('load', () => URL.revokeObjectURL(tile.src), { once: true });
                        }
                        done(null, tile);
                    })
                    .catch(error => {
                        tile.src = TRANSPARENT;
                        done(error, tile);
                    });

                return tile;
            }
        });

        const layer = new InspectedTileLayer(url, {
            subdomains: subdomains || 'abc',
            maxNativeZoom,
            maxZoom,
            keepBuffer,
            noWrap: true,
            updateWhenIdle: false,
            updateWhenZooming: true,
            crossOrigin: true
        });

        layer.addTo(map);
        return () => { map.removeLayer(layer); };
    }, [map, url, subdomains, maxNativeZoom, maxZoom, keepBuffer]);

    return null;
}

/** Reports the current zoom, so the caption can say when detail has run out. */
function ZoomWatcher({ onZoom }) {
    const map = useMap();
    useEffect(() => {
        const report = () => onZoom(map.getZoom());
        report();
        map.on('zoomend', report);
        return () => { map.off('zoomend', report); };
    }, [map, onZoom]);
    return null;
}

function KeepMapSized() {
    const map = useMap();

    React.useEffect(() => {
        const container = map.getContainer();
        // After the current paint, so the panel has settled before measuring.
        const settle = requestAnimationFrame(() => map.invalidateSize({ animate: false }));

        const observer = new ResizeObserver(() => map.invalidateSize({ animate: false }));
        observer.observe(container);

        return () => {
            cancelAnimationFrame(settle);
            observer.disconnect();
        };
    }, [map]);

    return null;
}

export default function GlobalThreatMap({ points = [], coverage }) {
    const severityColours = useSeverityColours();
    const [imagery, setImagery] = useState(null);
    const [zoom, setZoom] = useState(2);
    // Remembered per browser: a basemap is a preference, not a setting worth a
    // round trip, and losing it on every reload is the sort of small friction
    // that makes a panel feel unfinished.
    const [basemapId, setBasemapId] = React.useState(() => {
        try {
            return localStorage.getItem(BASEMAP_STORAGE_KEY) || DEFAULT_BASEMAP;
        } catch (e) {
            return DEFAULT_BASEMAP;
        }
    });

    const basemap = BASEMAPS.find(b => b.id === basemapId) || BASEMAPS[0];

    const chooseBasemap = (id) => {
        setBasemapId(id);
        try {
            localStorage.setItem(BASEMAP_STORAGE_KEY, id);
        } catch (e) {
            // A browser refusing storage is not a reason to refuse the change.
        }
    };


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
                        {zoom > basemap.maxZoom && (
                            /* Past the deepest imagery there is. Saying so stops
                               a magnified picture reading as a sharper one. */
                            <span style={{ display: 'block', marginTop: '3px', color: 'var(--warning)' }}>
                                Magnified past the available detail — no more exists at this place
                            </span>
                        )}
                        {imagery && (
                            /* Photography has a date, and it is rarely recent. Saying so
                               stops a location being read as where something is now. */
                            <span style={{ display: 'block', marginTop: '3px' }}>
                                Photography here taken {formatImageryDate(imagery.date)}
                                {imagery.resolution ? ` · ${imagery.resolution} m per pixel` : ''}
                            </span>
                        )}
                        {basemap.uniformYear && (
                            <span style={{ display: 'block', marginTop: '3px' }}>
                                Photography from {basemap.uniformYear} everywhere · 10 m per pixel, so no buildings
                            </span>
                        )}
                        {/* Two different datasets with two different ages, which
                            one caption used to blur together.

                            Roads, boundaries and place names are vector data and
                            are genuinely current: OpenStreetMap edits appear
                            within days and Esri's reference layers refresh on
                            their own schedule. Aerial photography is not, cannot
                            be made so, and is the thing above that carries a
                            date. Somebody told the map is "recent" deserves to
                            know which half that applies to. */}
                        <span style={{ display: 'block', marginTop: '3px', color: 'var(--text-dim)' }}>
                            Streets, boundaries and place names are kept current. Photography is whenever it was last flown, which varies by place and is stated above.
                        </span>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '14px', fontSize: '0.7rem', alignItems: 'center' }}>
                    <select
                        value={basemap.id}
                        onChange={e => chooseBasemap(e.target.value)}
                        title="Choose the map style"
                        style={{
                            background: 'var(--bg-surface)', border: '1px solid var(--border-strong)',
                            borderRadius: '6px', padding: '4px 8px', fontSize: '0.72rem',
                            color: 'var(--text-secondary)', cursor: 'pointer'
                        }}
                    >
                        {BASEMAPS.map(option => (
                            <option key={option.id} value={option.id}>{option.label}</option>
                        ))}
                    </select>

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
                    // Leaflet's own tile fade, left on.
                    //
                    // It was turned off to save compositing, and what it
                    // actually saved was the thing that hides a tile swap: each
                    // new tile replaced the old one instantly, so a pan or a
                    // zoom looked like the picture breaking apart and
                    // reassembling. The real cost that was worth removing was a
                    // CSS filter over every tile, and that is long gone.
                    // Markers drawn onto one canvas rather than as an SVG node
                    // each. With a few hundred addresses the DOM approach spends
                    // its time in layout rather than drawing.
                    preferCanvas
                    center={[22, 12]}
                    zoom={2}
                    minZoom={2}
                    // Deep enough for individual streets and buildings. OpenStreetMap
                    // publishes tiles to zoom 19; asking for more only stretches the
                    // last real tile and invents detail that is not there.
                    // The ceiling follows whichever basemap is showing.
                    //
                    // A fixed 21 let the map zoom two levels past what
                    // OpenStreetMap publishes, and combined with detectRetina -
                    // which asks for one level deeper again - it requested
                    // tiles that do not exist. OpenStreetMap answers those with
                    // an error rather than a blank, so the map went empty:
                    // "no map data" at exactly the zoom somebody was trying to
                    // look closely.
                    //
                    // detectRetina is gone with it. At a device ratio near 1
                    // the sharpness it buys is slight, it doubles every tile
                    // request, and it moves the real ceiling down a level for
                    // any source without headroom above it - all three of which
                    // were working against what was asked for here.
                    // Fixed, and not keyed to the basemap.
                    //
                    // react-leaflet reads this once, at creation, so keying the
                    // map on the basemap was what made a changed maxZoom take
                    // effect - at the cost of rebuilding the whole map and
                    // throwing away wherever somebody had navigated to. Each
                    // layer's maxNativeZoom already stops it requesting tiles
                    // its source does not publish; past that Leaflet scales the
                    // deepest real one, which is why this can simply be the
                    // deepest any of them reach.
                    maxZoom={DEEPEST_ZOOM}
                    scrollWheelZoom
                    // The world is not repeated sideways.
                    //
                    // Leaflet otherwise pans into a second and third copy of the
                    // globe, so the same country appears more than once and a marker
                    // looks like it exists in several places at the same time.
                    // `worldCopyJump` made it worse by teleporting the view between
                    // copies mid-drag, which is the jump that felt like a glitch.
                    worldCopyJump={false}
                    // The real edge of the projected world, not a number near it.
                    //
                    // These were +/-85, which reads as "the whole world" and is
                    // not: Web Mercator ends at 85.0511287798066, so a bound of
                    // 85 sits inside it. The same figures were also on the tile
                    // layers, where Leaflet takes them as a filter on which
                    // tiles may be requested - and every tile in the top and
                    // bottom rows extends to 85.0511, so none of them were ever
                    // fetched. At low zoom that row is the whole of Russia,
                    // Scandinavia, Canada and Alaska, drawn as nothing at all.
                    //
                    // The tile layers have no bounds now: noWrap already stops
                    // the world repeating sideways, which was the only thing
                    // they were there for.
                    maxBounds={[[-85.0511287798066, -180], [85.0511287798066, 180]]}
                    maxBoundsViscosity={1.0}
                    style={{ height: '100%', width: '100%', backgroundColor: 'var(--bg-code)' }}
                >
                    <KeepMapSized />
                    <ZoomWatcher onZoom={setZoom} />
                    <ImageryDate active={basemap.id === 'satellite'} onDate={setImagery} />

                    {/* A map beneath the photography, so nowhere is blank where
                        imagery stops. Only the photographic basemap needs it. */}
                    {basemap.fallbackUrl && (
                        <TileLayer
                            key={`${basemap.id}-fallback`}
                            url={basemap.fallbackUrl}
                            maxZoom={DEEPEST_ZOOM}
                            maxNativeZoom={basemap.fallbackMaxZoom}
                            noWrap
                            updateWhenIdle={false}
                            updateWhenZooming
                            keepBuffer={3}
                        />
                    )}
                    {basemap.inspectTiles ? (
                        <ImageryWithFallback
                            key={`${basemap.id}-imagery`}
                            url={basemap.url}
                            subdomains={basemap.subdomains || 'abc'}
                            maxNativeZoom={basemap.maxZoom}
                            maxZoom={DEEPEST_ZOOM}
                            keepBuffer={3}
                        />
                    ) : (
                    <TileLayer
                        // Remounted when the basemap changes, so Leaflet builds
                        // a fresh layer rather than swapping URLs underneath the
                        // tiles it has already drawn.
                        key={basemap.id}
                        attribution={basemap.attribution}
                        url={basemap.url}
                        subdomains={basemap.subdomains || 'abc'}
                        // Each service publishes to its own depth. Asking past it
                        // stretches the last real tile and invents detail that is
                        // not there; maxNativeZoom lets the map keep zooming while
                        // reusing the deepest tile that actually exists.
                        // The map stops where the imagery does, plus one.
                        //
                        // Leaflet fills a level past maxNativeZoom by scaling
                        // the deepest real tile. Beyond that there is nothing
                        // to scale.
                        maxZoom={DEEPEST_ZOOM}
                        maxNativeZoom={basemap.maxZoom}
                        // Tiles stop at the edge of the world rather than repeating.
                        noWrap
                        // Tiles load while the map is still moving.
                        //
                        // updateWhenIdle held every request until panning
                        // stopped, which is a real saving on a slow connection
                        // and reads as the map refusing to show where you just
                        // went. Waiting to be certain what to fetch is the
                        // wrong trade when somebody is looking for a street.
                        updateWhenIdle={false}
                        // Tiles follow the zoom as it animates. Holding them
                        // back left the previous level stretched across the
                        // screen until the animation finished, which is the
                        // other half of what looked like pixels breaking up.
                        updateWhenZooming
                        // Enough ring to stay ahead of a drag without keeping
                        // five screens of tiles composited. At 2 a quick pan
                        // outran the tiles and showed the background through
                        // the gap; 4 was the setting that made every frame
                        // expensive.
                        keepBuffer={3}
                    />
                    )}

                    {/*
                      * Roads and place names drawn over the imagery.
                      *
                      * Only the imagery basemap has these: a drawn map already
                      * carries its own labels, and a second set on top of them
                      * would collide.
                      */}
                    {(basemap.overlays || []).map(overlay => (
                        <TileLayer
                            key={`${basemap.id}-${overlay.id}`}
                            url={overlay.url}
                            minZoom={overlay.minZoom || 0}
                            maxZoom={DEEPEST_ZOOM}
                            maxNativeZoom={overlay.maxZoom}
                            noWrap
                            updateWhenIdle={false}
                            updateWhenZooming
                            keepBuffer={3}
                        />
                    ))}
                    {ordered.map(point => {
                        const meta = SEVERITY[point.severity] || SEVERITY.LOW;
                        const messages = point.messages || [];
                        return (
                            <CircleMarker
                                key={point.ip}
                                center={[point.latitude, point.longitude]}
                                radius={radiusFor(point.observations)}
                                pathOptions={{
                                    // Resolved values, never var(...): see useSeverityColours.
                                    color: severityColours[point.severity] || severityColours.LOW,
                                    fillColor: severityColours[point.severity] || severityColours.LOW,
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

                                        {/* A contacted destination is not a place a
                                            message came from, and saying "sent from
                                            here" over it would invert its meaning:
                                            this is somewhere this machine went after
                                            being warned about it. */}
                                        {point.role === 'CONTACTED' ? (
                                            <div style={{ marginBottom: '5px' }}>
                                                <div style={{ fontWeight: 700, fontSize: '0.74rem', color: '#b3261e' }}>
                                                    This machine connected here
                                                </div>
                                                <div style={{ fontSize: '0.7rem', color: '#555', marginTop: '2px' }}>
                                                    {point.observed_host ? `${point.observed_host}` : point.ip}
                                                    {point.port ? ` · port ${point.port}` : ''}
                                                    {point.protocol ? ` · ${point.protocol}` : ''}
                                                    {point.observed_at ? ` · ${new Date(point.observed_at).toLocaleString()}` : ''}
                                                </div>
                                                <div style={{ fontSize: '0.67rem', color: '#777', marginTop: '3px', lineHeight: 1.4 }}>
                                                    Observed by packet capture on this machine. It records that the
                                                    destination was reached, not who reached it.
                                                </div>
                                            </div>
                                        ) : (
                                            <div style={{ fontWeight: 700, fontSize: '0.74rem', marginBottom: '5px' }}>
                                                {point.observations} message{point.observations === 1 ? '' : 's'} sent from here
                                            </div>
                                        )}

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
