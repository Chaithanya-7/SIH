import { useEffect, useState, useCallback } from 'react';

const STORAGE_KEY = 'phishlens_theme';

/**
 * Theme preference, persisted per browser.
 *
 * An explicit choice always wins. With no stored choice the operating system
 * preference is followed, and the console keeps following it if the OS switches
 * — until the analyst picks a theme themselves, at which point their choice is
 * respected and system changes are ignored.
 *
 * The attribute is applied to <html> rather than a React wrapper so that
 * scrollbars, form controls and Leaflet's own surfaces pick it up too.
 */
export function useTheme() {
    const [theme, setThemeState] = useState(() => {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored === 'light' || stored === 'dark') return stored;
        } catch (e) {
            // Private browsing or blocked storage; fall through to the system preference.
        }
        if (typeof window !== 'undefined' && window.matchMedia) {
            return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        }
        return 'dark';
    });

    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme);
    }, [theme]);

    useEffect(() => {
        if (!window.matchMedia) return undefined;
        const query = window.matchMedia('(prefers-color-scheme: light)');

        const onSystemChange = event => {
            let hasExplicitChoice = false;
            try {
                hasExplicitChoice = !!localStorage.getItem(STORAGE_KEY);
            } catch (e) {
                hasExplicitChoice = false;
            }
            if (!hasExplicitChoice) setThemeState(event.matches ? 'light' : 'dark');
        };

        query.addEventListener('change', onSystemChange);
        return () => query.removeEventListener('change', onSystemChange);
    }, []);

    const setTheme = useCallback(next => {
        setThemeState(next);
        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch (e) {
            // A theme that cannot be persisted still applies for this session.
        }
    }, []);

    const toggleTheme = useCallback(() => {
        setTheme(theme === 'dark' ? 'light' : 'dark');
    }, [theme, setTheme]);

    return { theme, setTheme, toggleTheme };
}
