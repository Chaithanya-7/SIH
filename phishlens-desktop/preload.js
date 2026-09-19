const { contextBridge, ipcRenderer } = require('electron');

/**
 * Minimal, explicitly enumerated bridge. The dashboard runs with context
 * isolation and no Node integration; this is the only surface it can reach.
 */
contextBridge.exposeInMainWorld('phishlens', {
    isDesktopApp: true,

    getConfig: () => ipcRenderer.invoke('phishlens:get-config'),

    /**
     * Called by the dashboard to react to a phishlens:// deep link, e.g. the
     * extension's "More info" button. The callback receives { route, caseId? }.
     */
    onNavigate: (callback) => {
        if (typeof callback !== 'function') return () => {};
        const listener = (_event, target) => callback(target);
        ipcRenderer.on('phishlens:navigate', listener);
        return () => ipcRenderer.removeListener('phishlens:navigate', listener);
    }
});
