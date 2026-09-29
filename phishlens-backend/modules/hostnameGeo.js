/**
 * Location read out of a router's own name.
 *
 * Network operators name their infrastructure after where it is. A hostname
 * like `ae-1.r00.londen12.uk.bb.gin.ntt.net` says London, in the UK, in an
 * operator's own naming scheme; `xe-0-0-0.sin-b1` says Singapore. CAIDA's Hoiho
 * work is the rigorous form of this - it learns each operator's convention from
 * their whole address space and generates regular expressions per operator.
 *
 * This is the modest version of the same idea: a dictionary of the codes that
 * recur across operators, matched only where they appear as a whole label or a
 * delimited segment.
 *
 * ## Why it is worth having despite being modest
 *
 * It is the only source here that is free, instant, needs no third party, and
 * describes the *specific router* rather than the address block. A commercial
 * database will place an entire prefix in one city; a hostname says which of an
 * operator's sites this particular interface sits in.
 *
 * ## Why it is never trusted alone
 *
 * Three failure modes, and all of them are common:
 *
 *   - **Most addresses have no PTR at all.** Measured while building this: of
 *     four sample addresses, one had a PTR. An absent hostname is not evidence
 *     of anything.
 *   - **Names go stale.** Hardware is moved and renamed later, or never. A name
 *     is a claim by an operator about their own kit, with no obligation to
 *     stay true.
 *   - **Codes collide with ordinary words.** `sin` is Singapore and also sits
 *     inside "single" and "using"; `ord` is Chicago and also "order". Matching
 *     a bare substring would place a great deal of the internet in Illinois.
 *
 * So a match here is a *constraint offered to the fusion*, weighted below a
 * measured source, and it must agree with something else before it moves a
 * location.
 */

/**
 * Codes that recur across operators, with coordinates.
 *
 * Mostly IATA airport codes, which is the convention most backbones use, plus
 * the longer spellings that appear in a few schemes. Deliberately limited to
 * places large enough to be unambiguous: a short code for a small town is far
 * more likely to be a coincidence than a location.
 */
const LOCATION_CODES = {
    // Europe
    lon: { city: 'London', country: 'GB', lat: 51.5074, lon: -0.1278 },
    lhr: { city: 'London', country: 'GB', lat: 51.4700, lon: -0.4543 },
    londen: { city: 'London', country: 'GB', lat: 51.5074, lon: -0.1278 },
    ldn: { city: 'London', country: 'GB', lat: 51.5074, lon: -0.1278 },
    ams: { city: 'Amsterdam', country: 'NL', lat: 52.3676, lon: 4.9041 },
    amst: { city: 'Amsterdam', country: 'NL', lat: 52.3676, lon: 4.9041 },
    fra: { city: 'Frankfurt', country: 'DE', lat: 50.1109, lon: 8.6821 },
    frank: { city: 'Frankfurt', country: 'DE', lat: 50.1109, lon: 8.6821 },
    par: { city: 'Paris', country: 'FR', lat: 48.8566, lon: 2.3522 },
    cdg: { city: 'Paris', country: 'FR', lat: 49.0097, lon: 2.5479 },
    mad: { city: 'Madrid', country: 'ES', lat: 40.4168, lon: -3.7038 },
    mil: { city: 'Milan', country: 'IT', lat: 45.4642, lon: 9.1900 },
    mxp: { city: 'Milan', country: 'IT', lat: 45.6306, lon: 8.7281 },
    sto: { city: 'Stockholm', country: 'SE', lat: 59.3293, lon: 18.0686 },
    arn: { city: 'Stockholm', country: 'SE', lat: 59.6519, lon: 17.9186 },
    cph: { city: 'Copenhagen', country: 'DK', lat: 55.6761, lon: 12.5683 },
    dub: { city: 'Dublin', country: 'IE', lat: 53.3498, lon: -6.2603 },
    zrh: { city: 'Zurich', country: 'CH', lat: 47.3769, lon: 8.5417 },
    vie: { city: 'Vienna', country: 'AT', lat: 48.2082, lon: 16.3738 },
    waw: { city: 'Warsaw', country: 'PL', lat: 52.2297, lon: 21.0122 },

    // North America
    nyc: { city: 'New York', country: 'US', lat: 40.7128, lon: -74.0060 },
    jfk: { city: 'New York', country: 'US', lat: 40.6413, lon: -73.7781 },
    ewr: { city: 'Newark', country: 'US', lat: 40.6895, lon: -74.1745 },
    iad: { city: 'Ashburn', country: 'US', lat: 39.0438, lon: -77.4874 },
    ash: { city: 'Ashburn', country: 'US', lat: 39.0438, lon: -77.4874 },
    dca: { city: 'Washington', country: 'US', lat: 38.9072, lon: -77.0369 },
    ord: { city: 'Chicago', country: 'US', lat: 41.8781, lon: -87.6298 },
    chi: { city: 'Chicago', country: 'US', lat: 41.8781, lon: -87.6298 },
    dfw: { city: 'Dallas', country: 'US', lat: 32.7767, lon: -96.7970 },
    lax: { city: 'Los Angeles', country: 'US', lat: 34.0522, lon: -118.2437 },
    sjc: { city: 'San Jose', country: 'US', lat: 37.3382, lon: -121.8863 },
    sfo: { city: 'San Francisco', country: 'US', lat: 37.7749, lon: -122.4194 },
    pao: { city: 'Palo Alto', country: 'US', lat: 37.4419, lon: -122.1430 },
    sea: { city: 'Seattle', country: 'US', lat: 47.6062, lon: -122.3321 },
    mia: { city: 'Miami', country: 'US', lat: 25.7617, lon: -80.1918 },
    atl: { city: 'Atlanta', country: 'US', lat: 33.7490, lon: -84.3880 },
    den: { city: 'Denver', country: 'US', lat: 39.7392, lon: -104.9903 },
    phx: { city: 'Phoenix', country: 'US', lat: 33.4484, lon: -112.0740 },
    bos: { city: 'Boston', country: 'US', lat: 42.3601, lon: -71.0589 },
    yyz: { city: 'Toronto', country: 'CA', lat: 43.6532, lon: -79.3832 },
    yul: { city: 'Montreal', country: 'CA', lat: 45.5017, lon: -73.5673 },

    // Asia-Pacific
    sin: { city: 'Singapore', country: 'SG', lat: 1.3521, lon: 103.8198 },
    hkg: { city: 'Hong Kong', country: 'HK', lat: 22.3193, lon: 114.1694 },
    nrt: { city: 'Tokyo', country: 'JP', lat: 35.7720, lon: 140.3929 },
    tyo: { city: 'Tokyo', country: 'JP', lat: 35.6762, lon: 139.6503 },
    icn: { city: 'Seoul', country: 'KR', lat: 37.4602, lon: 126.4407 },
    syd: { city: 'Sydney', country: 'AU', lat: -33.8688, lon: 151.2093 },
    mel: { city: 'Melbourne', country: 'AU', lat: -37.8136, lon: 144.9631 },
    bom: { city: 'Mumbai', country: 'IN', lat: 19.0760, lon: 72.8777 },
    mum: { city: 'Mumbai', country: 'IN', lat: 19.0760, lon: 72.8777 },
    del: { city: 'Delhi', country: 'IN', lat: 28.6139, lon: 77.2090 },
    blr: { city: 'Bengaluru', country: 'IN', lat: 12.9716, lon: 77.5946 },
    maa: { city: 'Chennai', country: 'IN', lat: 13.0827, lon: 80.2707 },
    hyd: { city: 'Hyderabad', country: 'IN', lat: 17.3850, lon: 78.4867 },
    dxb: { city: 'Dubai', country: 'AE', lat: 25.2048, lon: 55.2708 },
    tlv: { city: 'Tel Aviv', country: 'IL', lat: 32.0853, lon: 34.7818 },

    // South America and Africa
    gru: { city: 'Sao Paulo', country: 'BR', lat: -23.5505, lon: -46.6333 },
    eze: { city: 'Buenos Aires', country: 'AR', lat: -34.6037, lon: -58.3816 },
    jnb: { city: 'Johannesburg', country: 'ZA', lat: -26.2041, lon: 28.0473 },
    cpt: { city: 'Cape Town', country: 'ZA', lat: -33.9249, lon: 18.4241 }
};


/**
 * The same places spelled out, which several large operators prefer.
 *
 * `ae7.edge4.Frankfurt1.Level3.net` is a real shape and the three-letter table
 * above misses it entirely: stripping the site number leaves "frankfurt", not
 * "fra". Long names are also safer than codes - a whole city name is far less
 * likely to be a coincidence than three letters.
 */
const SPELLED_OUT = {
    london: 'lon', amsterdam: 'ams', frankfurt: 'fra', paris: 'par', madrid: 'mad',
    milan: 'mil', stockholm: 'sto', copenhagen: 'cph', dublin: 'dub', zurich: 'zrh',
    vienna: 'vie', warsaw: 'waw',
    newyork: 'nyc', newark: 'ewr', ashburn: 'iad', washington: 'dca', chicago: 'ord',
    dallas: 'dfw', losangeles: 'lax', sanjose: 'sjc', sanfrancisco: 'sfo',
    paloalto: 'pao', seattle: 'sea', miami: 'mia', atlanta: 'atl', denver: 'den',
    phoenix: 'phx', boston: 'bos', toronto: 'yyz', montreal: 'yul',
    singapore: 'sin', hongkong: 'hkg', tokyo: 'tyo', seoul: 'icn', sydney: 'syd',
    melbourne: 'mel', mumbai: 'bom', delhi: 'del', bengaluru: 'blr', bangalore: 'blr',
    chennai: 'maa', hyderabad: 'hyd', dubai: 'dxb', telaviv: 'tlv',
    saopaulo: 'gru', buenosaires: 'eze', johannesburg: 'jnb', capetown: 'cpt'
};

// Folded into the main table, so everything below has one place to look.
for (const [name, code] of Object.entries(SPELLED_OUT)) {
    if (LOCATION_CODES[code]) LOCATION_CODES[name] = LOCATION_CODES[code];
}

/**
 * Two-letter country labels that appear as their own segment in operator
 * naming, as in `...londen12.uk.bb.gin.ntt.net`.
 *
 * A country is a weak constraint on its own, but it is a real one: it can
 * contradict a city claim from elsewhere, which is worth knowing.
 */
const COUNTRY_LABELS = new Set([
    'uk', 'gb', 'de', 'fr', 'nl', 'es', 'it', 'se', 'dk', 'no', 'fi', 'ie', 'ch',
    'at', 'pl', 'cz', 'pt', 'be', 'ru', 'ua', 'us', 'ca', 'mx', 'br', 'ar', 'cl',
    'sg', 'hk', 'jp', 'kr', 'cn', 'tw', 'au', 'nz', 'in', 'ae', 'sa', 'il', 'tr',
    'za', 'ng', 'ke', 'eg'
]);

/** Roughly how far apart two coordinates are, in kilometres. */
function distanceKm(a, b) {
    const R = 6371;
    const toRad = d => (d * Math.PI) / 180;
    const dLat = toRad(b.lat - a.lat);
    const dLon = toRad(b.lon - a.lon);
    const lat1 = toRad(a.lat);
    const lat2 = toRad(b.lat);
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

class HostnameGeo {
    /**
     * Reads a location out of a hostname, if one is plainly there.
     *
     * Splits on the delimiters operators actually use - dots, hyphens and
     * underscores - and matches whole segments only. A segment may also carry a
     * trailing number, as in `londen12` or `sin-b1`, which is how a site
     * distinguishes its racks.
     */
    locate(hostname) {
        const name = String(hostname || '').trim().toLowerCase();
        if (!name || name.length > 253) return this.nothing('No hostname to read.');

        const segments = name.split(/[.\-_]/).filter(Boolean);
        if (!segments.length) return this.nothing('The hostname has no readable segments.');

        const cityMatches = [];
        const countries = new Set();

        for (const segment of segments) {
            if (COUNTRY_LABELS.has(segment)) countries.add(segment.toUpperCase());

            // The segment itself, or the segment with a trailing site number
            // removed: `londen12` is London's twelfth something.
            const candidates = [segment, segment.replace(/\d+$/, '')];

            for (const candidate of candidates) {
                if (candidate.length < 3) continue;
                const place = LOCATION_CODES[candidate];
                if (!place) continue;
                if (cityMatches.some(m => m.code === candidate)) continue;
                cityMatches.push({ code: candidate, ...place, segment });
                break;
            }
        }

        if (!cityMatches.length) {
            return this.nothing(
                countries.size
                    ? `The hostname names a country (${[...countries].join(', ')}) but no place this recognises.`
                    : 'The hostname carries no location code this recognises. Most operator names do not, and many have no pattern at all.'
            );
        }

        // More than one code in one name is usually a link between two sites, as
        // in a `lon-fra` trunk. Which end this interface is on cannot be told
        // from the name, so both are offered and the radius covers them.
        const spreadKm = cityMatches.length > 1
            ? Math.max(...cityMatches.slice(1).map(m => distanceKm(cityMatches[0], m)))
            : 0;

        const chosen = cityMatches[0];
        const countryConflict = countries.size > 0 && !countries.has(chosen.country)
            ? `The hostname also names ${[...countries].join(', ')}, which does not match ${chosen.city}.`
            : null;

        return {
            status: 'AVAILABLE',
            hostname: name,
            city: chosen.city,
            country_code: chosen.country,
            latitude: chosen.lat,
            longitude: chosen.lon,
            // A city code means the site, not a street. Fifty kilometres covers
            // a metropolitan area and the several facilities an operator may
            // have in one; claiming less would be inventing precision.
            radius_km: Math.max(50, Math.round(spreadKm / 2)),
            matched_codes: cityMatches.map(m => `${m.segment} -> ${m.city}`),
            ambiguous: cityMatches.length > 1,
            country_labels: [...countries],
            conflict: countryConflict,
            basis: cityMatches.length > 1
                ? `The hostname names more than one place (${cityMatches.map(m => m.city).join(', ')}), which usually means a link between two sites. The first is used and the radius covers the rest.`
                : `The hostname segment "${chosen.segment}" is an operator's code for ${chosen.city}.`,
            limitation: 'A hostname is a claim an operator makes about their own equipment. It can be stale, copied from another site, or simply wrong, and nothing obliges it to be updated when hardware moves.'
        };
    }

    nothing(reason) {
        return { status: 'UNAVAILABLE', reason, latitude: null, longitude: null };
    }
}

module.exports = new HostnameGeo();
module.exports.HostnameGeo = HostnameGeo;
module.exports.LOCATION_CODES = LOCATION_CODES;
module.exports.distanceKm = distanceKm;
