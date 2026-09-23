import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// This package is ESM, so __dirname has to be derived.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Static checks over the console's source.
 *
 * There is no browser here and no component is rendered. These exist because
 * two faults shipped through a clean `vite build`, an installer and an install,
 * and both were visible in the source the whole time:
 *
 *   - a panel called api.get(...), which does not exist on that object. It threw
 *     during render, and with no error boundary above it the entire application
 *     unmounted. Every page went blank, not just that panel.
 *
 *   - the map asked a canvas to paint with "var(--danger)". A canvas context
 *     cannot resolve CSS custom properties, so the assignment was rejected and
 *     the markers were drawn with nothing. The heading above the map went on
 *     correctly reporting how many addresses it had.
 *
 * A build succeeding says nothing about either. Both are cheap to check by
 * reading, so they are checked by reading.
 */

const SOURCE = path.join(__dirname, '..', 'src');
const COMPONENTS = path.join(SOURCE, 'components');

const read = file => fs.readFileSync(file, 'utf8');
const componentFiles = () => fs.readdirSync(COMPONENTS).filter(name => name.endsWith('.jsx')).map(name => path.join(COMPONENTS, name));

test('every api.* method a component calls actually exists', () => {
    const api = read(path.join(SOURCE, 'services', 'api.js'));

    // The methods defined on the exported object, e.g. "  getOverview: async () =>".
    const defined = new Set([...api.matchAll(/^\s{2}([a-zA-Z_][a-zA-Z0-9_]*)\s*:/gm)].map(m => m[1]));
    assert.ok(defined.size > 10, 'the api surface should have been parsed');

    const missing = [];
    for (const file of componentFiles()) {
        const source = read(file);
        for (const call of source.matchAll(/\bapi\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g)) {
            if (!defined.has(call[1])) missing.push(`${path.basename(file)} calls api.${call[1]}()`);
        }
    }

    assert.deepStrictEqual(missing, [],
        'api is a set of named methods, not an axios instance; calling one that does not exist throws during render');
});

test('canvas markers are painted with resolved colours, not CSS variables', () => {
    const map = read(path.join(COMPONENTS, 'GlobalThreatMap.jsx'));

    // Only meaningful while the map draws to a canvas; in SVG mode var() resolves.
    assert.match(map, /preferCanvas/, 'this check assumes canvas rendering');

    const options = map.match(/pathOptions=\{\{[\s\S]*?\}\}/g) || [];
    assert.ok(options.length, 'the marker path options should have been found');

    for (const block of options) {
        // Asserted positively. An earlier version of this test only looked for a
        // literal var(--) inside the block, and passed happily when the colour
        // came in through a name that held one - which is exactly how the bug
        // was written in the first place.
        assert.match(block, /severityColours\[/,
            'marker colours must come from the resolved theme values');
        assert.doesNotMatch(block, /var\(--/,
            'a canvas context cannot resolve CSS custom properties');
        assert.doesNotMatch(block, /meta\.colour|SEVERITY\[/,
            'the SEVERITY table holds var(--...) strings, which paint nothing on a canvas');
    }

    // The table itself may keep CSS variables: the legend renders in the DOM,
    // where they resolve. This documents that the two uses differ.
    assert.match(map, /const SEVERITY = \{[\s\S]*?var\(--/,
        'the legend is DOM-rendered and may use variables');

    assert.match(map, /getComputedStyle\(document\.documentElement\)/,
        'severity colours must be resolved from the theme');
    assert.match(map, /MutationObserver/,
        'switching theme must repaint the markers');
});

test('every React hook a component uses is imported', () => {
    const hooks = ['useState', 'useEffect', 'useMemo', 'useRef', 'useCallback', 'useReducer'];
    const problems = [];

    for (const file of componentFiles()) {
        const source = read(file);

        // Every import from react, in whatever form it takes.
        //
        // Matching only `import React, { ... }` got this wrong in both
        // directions: it reported a file using the named-only form - which is
        // valid and common under the modern JSX transform - as broken, and,
        // worse, it could never have caught a hook genuinely missing from such
        // a file, because the line it searched came back empty. A check that
        // cannot fail on a whole class of file is not checking it.
        const importLine = (source.match(/^import\s[^;]*from\s+['"]react['"];/gm) || []).join(' ');

        for (const hook of hooks) {
            // Bare usage only: React.useMemo(...) needs no named import.
            const bare = new RegExp(`(^|[^.\\w])${hook}\\s*\\(`, 'm');
            if (!bare.test(source)) continue;
            if (!new RegExp(`\\b${hook}\\b`).test(importLine)) {
                problems.push(`${path.basename(file)} uses ${hook} without importing it`);
            }
        }
    }

    assert.deepStrictEqual(problems, [],
        'an unimported hook is a ReferenceError at render, which a build does not catch');
});

test('the page switch is wrapped so one panel cannot blank the console', () => {
    const dashboard = read(path.join(COMPONENTS, 'Dashboard.jsx'));

    assert.match(dashboard, /import PanelBoundary/, 'the boundary must be in use');
    assert.match(dashboard, /<PanelBoundary[^>]*key=\{activeNav\}/,
        'the page switch must be inside a boundary, keyed so an error does not follow you between pages');

    const boundary = read(path.join(COMPONENTS, 'PanelBoundary.jsx'));
    assert.match(boundary, /getDerivedStateFromError/, 'it must actually be an error boundary');
    assert.match(boundary, /console\.error/, 'a contained failure must still be reported, not swallowed');
});

test('a backlog-scanned case does not read like a live one', () => {
    // The backend already refuses to score a check it could not honestly
    // perform on old mail - domain age, indicator feeds, address reputation,
    // DNS, live DKIM. That is only half the job.
    //
    // If the console then renders the result identically to a live case, a SAFE
    // resting on five fewer checks looks exactly like a SAFE resting on all of
    // them, and somebody reads it as the same reassurance. The whole point of
    // not scoring those checks is lost at the last step.
    const notice = fs.readFileSync(path.join(SOURCE, 'components', 'AnalysisModeNotice.jsx'), 'utf8');
    const caseView = fs.readFileSync(path.join(SOURCE, 'components', 'CaseInvestigationView.jsx'), 'utf8');

    assert.match(caseView, /import AnalysisModeNotice/, 'the case view must carry the notice');
    assert.match(caseView, /<AnalysisModeNotice analysisMode=\{selectedCase\.analysis_mode\}/);
    assert.match(caseView, /<AnalysisModeBadge analysisMode=\{selectedCase\.analysis_mode\}/,
        'and a badge beside the verdict, which is where the eye lands');

    // Above the score, not below it. A qualification printed after the number
    // is read after the number has already been believed.
    const noticeAt = caseView.indexOf('<AnalysisModeNotice');
    const cardAt = caseView.indexOf('<ConfidenceCard');
    assert.ok(noticeAt > -1 && cardAt > -1 && noticeAt < cardAt,
        'the caveat must appear before the confidence score, not after it');

    // It has to name which checks were skipped and why, not merely say the
    // case is old. "Not applicable" with no reason is the same dead end as a
    // silent skip.
    assert.match(notice, /checks_not_applicable/);
    assert.match(notice, /entry\.reason/, 'each skipped check must show its reason');
    assert.match(notice, /verdict_caveat/);

    // And it must render nothing at all for live mail, or every ordinary case
    // grows a warning that means nothing.
    assert.match(notice, /analysisMode\.mode !== 'HISTORICAL'\) return null/);
});
