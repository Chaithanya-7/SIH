/**
 * Theme for the extension's own pages, matching the desktop console.
 *
 * Loaded from <head> and run immediately rather than on DOMContentLoaded: the
 * attribute has to be on <html> before the first paint, or the popup shows a
 * flash of the wrong theme every single time it is opened. A popup is opened
 * dozens of times a day, so that flash would be the most-seen thing in the
 * product.
 *
 * localStorage is used rather than the extension storage API for the same
 * reason - it is synchronous. Extension storage is asynchronous, so reading the
 * preference from it could not happen before paint. Extension pages share one
 * origin, so the popup and the settings page see the same value.
 */
(function () {
    const STORAGE_KEY = 'phishlens_theme';

    function stored() {
        try {
            const value = localStorage.getItem(STORAGE_KEY);
            return value === 'light' || value === 'dark' ? value : null;
        } catch (e) {
            // Private browsing or blocked storage. Fall through to the system
            // preference; a theme that cannot be remembered still applies now.
            return null;
        }
    }

    function systemPreference() {
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
            ? 'light'
            : 'dark';
    }

    /**
     * Anything that displays the current theme registers here.
     *
     * Every route that changes the theme goes through apply(), so a label can
     * never disagree with what is on screen. Without this the button rendered
     * its label once and went stale whenever the theme changed by any other
     * route - most realistically the system-preference listener below firing
     * while the popup is open.
     */
    const observers = new Set();

    function apply(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        observers.forEach(fn => fn(theme));
    }

    // An explicit choice always wins. Without one, follow the operating system.
    apply(stored() || systemPreference());

    // Keep following the system until the person picks a theme themselves.
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', event => {
            if (!stored()) apply(event.matches ? 'light' : 'dark');
        });
    }

    globalThis.PhishLensTheme = {
        current() {
            return document.documentElement.getAttribute('data-theme') || 'dark';
        },

        set(theme) {
            apply(theme);
            try {
                localStorage.setItem(STORAGE_KEY, theme);
            } catch (e) {
                // Applied for this session even where it cannot be persisted.
            }
        },

        toggle() {
            const next = this.current() === 'dark' ? 'light' : 'dark';
            this.set(next);
            return next;
        },

        /**
         * Wires an icon-only button to the toggle and keeps its label correct.
         * The label names the theme being switched *to*, which is what a person
         * reading a tooltip wants to know.
         */
        attach(button) {
            if (!button) return;
            const render = theme => {
                const isDark = (theme || this.current()) === 'dark';
                button.textContent = isDark ? '☀' : '☾';
                const target = isDark ? 'light' : 'dark';
                button.title = `Switch to ${target} theme`;
                button.setAttribute('aria-label', `Switch to ${target} theme`);
            };
            button.addEventListener('click', () => this.toggle());
            observers.add(render);
            render();
        }
    };
})();
