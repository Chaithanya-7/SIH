import fs from 'node:fs';
import path from 'node:path';
import { JSDOM } from 'jsdom';

const EXT = 'E:/SIH/SIH/phishlens-extension';
const dom = new JSDOM('<!doctype html><html><body><table><tbody></tbody></table></body></html>', {
    runScripts: 'outside-only',
    url: 'https://mail.google.com/mail/u/0/'
});
const { window } = dom;
const errors = [];
window.onerror = m => errors.push(String(m));
window.addEventListener('error', e => errors.push(String(e.message || e)));

const noop = () => {};
window.chrome = {
    runtime: {
        lastError: null,
        sendMessage: (m, cb) => { if (typeof cb === 'function') cb(undefined); },
        onMessage: { addListener: noop }
    },
    storage: { local: { get: (d, cb) => cb({}), set: (v, cb) => cb && cb() } }
};

// Loaded together, in the manifest's order, as a content script is.
const sources = ['mail-providers.js', 'content-gmail.js'];
const combined = sources.map(f => `//# ${f}\n` + fs.readFileSync(path.join(EXT, f), 'utf8'))
    .join(String.fromCharCode(10) + ';' + String.fromCharCode(10));

try {
    window.eval(combined);
} catch (e) {
    errors.push('THREW AT LOAD: ' + e.message);
}

await new Promise(r => setTimeout(r, 300));

console.log('errors at load:', errors.length ? errors : 'none');
console.log('watcher flag set:', !!window.__phishlensWatcherRunning);
console.log('providers exported:', typeof window.PhishLensMailProviders);
