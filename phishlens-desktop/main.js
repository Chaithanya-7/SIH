const { app, BrowserWindow, shell, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');

/**
 * PhishLens desktop application.
 *
 * This is the installed counterpart to the browser extension. The extension
 * popup shows only headline counts; its "More info" button opens a
 * phishlens:// deep link, which the operating system routes to this
 * application, which then presents the full SOC investigation console.
 *
 * The console itself is the same PhishLens dashboard build - the desktop app
 * is a shell around it, not a second implementation of it.
 */

const PROTOCOL = 'phishlens';
const DEV_DASHBOARD_URL = process.env.PHISHLENS_DASHBOARD_URL || 'http://localhost:3005';
const BACKEND_URL = process.env.PHISHLENS_API_URL || 'http://localhost:3001';
const DEV_MODE = process.env.PHISHLENS_DEV === '1' || process.argv.includes('--dev');

let mainWindow = null;
/** Route requested by a deep link before the window existed, replayed once it is ready. */
let pendingRoute = null;

/** Packaged builds ship the dashboard build output in resources/dashboard. */
function packagedDashboardIndex() {
    const packaged = path.join(process.resourcesPath || '', 'dashboard', 'index.html');
    if (fs.existsSync(packaged)) return packaged;

    // Running unpackaged from the repo: use the dashboard's local build output.
    const local = path.join(__dirname, '..', 'phishlens-dashboard', 'dist', 'index.html');
    return fs.existsSync(local) ? local : null;
}

/**
 * Parses phishlens://<route> deep links.
 *   phishlens://dashboard        -> { route: 'dashboard' }
 *   phishlens://case/SM-2026-123 -> { route: 'case', caseId: 'SM-2026-123' }
 */
function parseDeepLink(url) {
    if (typeof url !== 'string' || !url.startsWith(`${PROTOCOL}://`)) return null;

    const withoutScheme = url.slice(`${PROTOCOL}://`.length).replace(/\/+$/, '');
    const [route, ...rest] = withoutScheme.split('/');
    if (route === 'case' && rest[0]) {
        // Only allow the known case-id shape through; never interpolate arbitrary
        // deep-link text into the loaded URL.
        const caseId = rest[0];
        return /^[A-Za-z0-9-]{1,64}$/.test(caseId) ? { route: 'case', caseId } : { route: 'dashboard' };
    }
    return { route: route || 'dashboard' };
}

function deepLinkFromArgv(argv) {
    const match = (argv || []).find(arg => typeof arg === 'string' && arg.startsWith(`${PROTOCOL}://`));
    return match ? parseDeepLink(match) : null;
}

function sendRoute(target) {
    if (!target) return;
    if (mainWindow && !mainWindow.webContents.isLoading()) {
        mainWindow.webContents.send('phishlens:navigate', target);
    } else {
        pendingRoute = target;
    }
}

function createWindow(initialRoute) {
    mainWindow = new BrowserWindow({
        width: 1440,
        height: 900,
        minWidth: 1024,
        minHeight: 680,
        backgroundColor: '#0a0a0f',
        title: 'PhishLens',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true
        }
    });

    pendingRoute = initialRoute || null;

    const dashboardIndex = packagedDashboardIndex();
    if (DEV_MODE || !dashboardIndex) {
        mainWindow.loadURL(DEV_DASHBOARD_URL).catch(() => mainWindow.loadFile(path.join(__dirname, 'setup.html')));
    } else {
        mainWindow.loadFile(dashboardIndex);
    }

    mainWindow.webContents.on('did-finish-load', () => {
        if (pendingRoute) {
            mainWindow.webContents.send('phishlens:navigate', pendingRoute);
            pendingRoute = null;
        }
    });

    mainWindow.webContents.on('did-fail-load', (_event, _code, description) => {
        mainWindow.loadFile(path.join(__dirname, 'setup.html'), {
            query: { reason: description || 'unreachable', dashboard: DEV_DASHBOARD_URL, backend: BACKEND_URL }
        });
    });

    // The console only ever renders its own content; anything else opens in the
    // user's real browser rather than inside a privileged application window.
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.webContents.on('will-navigate', (event, url) => {
        const allowed = url.startsWith(DEV_DASHBOARD_URL) || url.startsWith('file://');
        if (!allowed) {
            event.preventDefault();
            shell.openExternal(url);
        }
    });

    mainWindow.on('closed', () => { mainWindow = null; });
}

function focusExistingWindow(route) {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
    sendRoute(route);
}

// A second launch (which is what a deep link from the browser triggers) must
// surface the window already running rather than starting a second instance.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
    app.quit();
} else {
    app.on('second-instance', (_event, argv) => {
        focusExistingWindow(deepLinkFromArgv(argv) || { route: 'dashboard' });
    });

    // macOS delivers deep links as an event rather than through argv.
    app.on('open-url', (event, url) => {
        event.preventDefault();
        const target = parseDeepLink(url);
        if (mainWindow) focusExistingWindow(target);
        else pendingRoute = target;
    });

    app.whenReady().then(() => {
        if (process.defaultApp && process.argv.length >= 2) {
            // Unpackaged dev run: the executable is electron itself.
            app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
        } else {
            app.setAsDefaultProtocolClient(PROTOCOL);
        }

        createWindow(deepLinkFromArgv(process.argv) || { route: 'dashboard' });

        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createWindow({ route: 'dashboard' });
        });
    });

    app.on('window-all-closed', () => {
        if (process.platform !== 'darwin') app.quit();
    });
}

ipcMain.handle('phishlens:get-config', () => ({
    backendUrl: BACKEND_URL,
    dashboardUrl: DEV_DASHBOARD_URL,
    version: app.getVersion()
}));
