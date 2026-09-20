import React from 'react';
import { Sun, Moon } from 'lucide-react';

/**
 * Switches between the light and dark console themes. Labelled for assistive
 * technology, since the control is icon-only.
 */
export default function ThemeToggle({ theme, onToggle, collapsed }) {
    const goingTo = theme === 'dark' ? 'light' : 'dark';

    return (
        <button
            onClick={onToggle}
            title={`Switch to ${goingTo} theme`}
            aria-label={`Switch to ${goingTo} theme`}
            style={{
                backgroundColor: 'transparent',
                border: '1px solid var(--border-strong)',
                color: 'var(--text-muted)',
                borderRadius: '6px',
                padding: collapsed ? '6px' : '6px 10px',
                fontSize: '0.72rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '7px',
                width: '100%',
                transition: 'color 0.15s ease, border-color 0.15s ease'
            }}
            onMouseEnter={e => {
                e.currentTarget.style.color = 'var(--text-primary)';
                e.currentTarget.style.borderColor = 'var(--accent)';
            }}
            onMouseLeave={e => {
                e.currentTarget.style.color = 'var(--text-muted)';
                e.currentTarget.style.borderColor = 'var(--border-strong)';
            }}
        >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
            {!collapsed && <span>{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>}
        </button>
    );
}
