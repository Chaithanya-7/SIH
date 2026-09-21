import React from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * Keeps one broken panel from taking the whole console with it.
 *
 * There was no error boundary anywhere in this application, which meant any
 * component that threw during render unmounted everything. One panel calling a
 * method that did not exist emptied the entire window - no navigation, no map,
 * no cases, no message. From the outside that is indistinguishable from the
 * application failing to start, and it is exactly what "nothing works" looked
 * like.
 *
 * A security console going blank is worse than one showing a broken panel,
 * because a blank window tells the person nothing about what is still being
 * watched. So a panel that fails says so in place, and everything around it
 * keeps working.
 *
 * What it does not do is hide the failure. The error is kept on screen and
 * re-thrown to the console, because a panel that quietly renders nothing is how
 * this went unnoticed through a build, a package and an install.
 */
export default class PanelBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { error: null };
    }

    static getDerivedStateFromError(error) {
        return { error };
    }

    componentDidCatch(error, info) {
        // Still reported, so it appears in the developer console and in any log
        // being collected, rather than being swallowed by the boundary.
        console.error(`[PhishLens] The "${this.props.name || 'panel'}" panel failed to render.`, error, info);
    }

    render() {
        if (!this.state.error) return this.props.children;

        return (
            <div style={{
                background: 'var(--bg-panel)',
                border: '1px solid var(--danger)',
                borderRadius: '12px',
                padding: '18px 20px',
                display: 'flex',
                gap: '13px',
                alignItems: 'flex-start'
            }}>
                <AlertTriangle size={18} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: '2px' }} />
                <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: '0.88rem', color: 'var(--text-primary)', fontWeight: 500 }}>
                        This part of the page could not be shown
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: 1.55 }}>
                        {this.props.name ? `The ${this.props.name} panel failed. ` : ''}
                        Everything else on this page is still working, and mail is still being
                        examined — this is a fault in displaying the result, not in producing it.
                    </div>
                    <code style={{
                        display: 'block', marginTop: '9px', fontSize: '0.72rem',
                        color: 'var(--text-dim)', whiteSpace: 'pre-wrap', wordBreak: 'break-word'
                    }}>
                        {String(this.state.error?.message || this.state.error)}
                    </code>
                </div>
            </div>
        );
    }
}
