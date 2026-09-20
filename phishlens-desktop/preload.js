const { contextBridge, ipcRenderer } = require('electron');

/**
 * Minimal, explicitly enumerated bridge. The console runs with context
 * isolation and no Node integration; this is the only surface it can reach.
 */
contextBridge.exposeInMainWorld('phishlens', {
    isDesktopApp: true,

    /** Backend URL and the local API key, so the console authenticates itself. */
    getConfig: () => ipcRenderer.invoke('phishlens:get-config'),

    getBackendStatus: () => ipcRenderer.invoke('phishlens:get-backend-status'),
    restartBackend: () => ipcRenderer.invoke('phishlens:restart-backend'),

    /**
     * Reacts to a phishlens:// deep link, e.g. the extension's "More info"
     * button. The callback receives { route, caseId? }.
     */
    onNavigate: (callback) => {
        if (typeof callback !== 'function') return () => {};
        const listener = (_event, target) => callback(target);
        ipcRenderer.on('phishlens:navigate', listener);
        return () => ipcRenderer.removeListener('phishlens:navigate', listener);
    },

    /** Backend lifecycle updates, used by the startup screen. */
    onBackendStatus: (callback) => {
        if (typeof callback !== 'function') return () => {};
        const listener = (_event, state) => callback(state);
        ipcRenderer.on('phishlens:backend-status', listener);
        return () => ipcRenderer.removeListener('phishlens:backend-status', listener);
    },

    onBackendLog: (callback) => {
        if (typeof callback !== 'function') return () => {};
        const listener = (_event, line) => callback(line);
        ipcRenderer.on('phishlens:backend-log', listener);
        return () => ipcRenderer.removeListener('phishlens:backend-log', listener);
    }
});
