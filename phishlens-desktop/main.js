const { app, BrowserWindow, shell, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const BackendSupervisor = require('./backendSupervisor');

/**
 * PhishLens desktop application.
 *
 * This is the installed counterpart to the browser extension. The extension
 * popup shows only headline counts; its "More info" button opens a
 * phishlens:// deep link, which the operating system routes here, and this
 * window presents the full SOC console.
 *
 * The application also runs and watches the backend, so installing PhishLens
 * means one thing to launch rather than a set of services to start by hand.
 * The console is not shown until the backend is actually answering, because a
 * dashboard rendering empty panels is indistinguishable from a healthy one
 * with no mail in it.
 */

const PROTOCOL = 'phishlens';
const DEV_DASHBOARD_URL = process.env.PHISHLENS_DASHBOARD_URL || 'http://localhost:3005';
const BACKEND_PORT = parseInt(process.env.PHISHLENS_API_PORT || '3001', 10);
const DEV_MODE = process.env.PHISHLENS_DEV === '1' || process.argv.includes('--dev');

let mainWindow = null;
let pendingRoute = null;
const supervisor = new BackendSupervisor({ port: BACKEND_PORT });

function packagedDashboardIndex() {
    const packaged = path.join(process.resourcesPath || '', 'dashboard', 'index.html');
    if (fs.existsSync(packaged)) return packaged;

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
        const caseId = rest[0];
        return /^[A-Za-z0-9-]{1,64}$/.test(caseId) ? { route: 'case', caseId } : { route: 'dashboard' };
    }
    return { route: route || 'dashboard' };
}

function deepLinkFromArgv(argv) {
    const match = (argv || []).find(arg => typeof arg === 'string' && arg.startsWith(`${PROTOCOL}://`));
    return match ? parseDeepLink(match) : null;
}

function showStartupScreen() {
    if (!mainWindow) return;
    mainWindow.loadFile(path.join(__dirname, 'startup.html'));
}

/** Loads the console itself, once the backend can answer it. */
function loadConsole() {
    if (!mainWindow) return;

    const dashboardIndex = packagedDashboardIndex();
    if (DEV_MODE || !dashboardIndex) {
        mainWindow.loadURL(DEV_DASHBOARD_URL).catch(() => showStartupScreen());
    } else {
        mainWindow.loadFile(dashboardIndex);
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
    showStartupScreen();

    mainWindow.webContents.on('did-finish-load', () => {
        // The startup screen is told where things stand as soon as it can listen.
        mainWindow.webContents.send('phishlens:backend-status', supervisor.state());

        if (pendingRoute && supervisor.status === 'READY') {
            mainWindow.webContents.send('phishlens:navigate', pendingRoute);
            pendingRoute = null;
        }
    });

    mainWindow.webContents.on('did-fail-load', (_event, _code, description) => {
        supervisor.record(`The console failed to load: ${description}`);
        showStartupScreen();
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

    if (supervisor.status === 'READY') mainWindow.webContents.send('phishlens:navigate', route);
    else pendingRoute = route;
}

// Status changes are pushed to whichever screen is showing, and the console is
// loaded the moment the backend can actually answer it.
supervisor.on('status', state => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('phishlens:backend-status', state);
    }
    if (state.status === 'READY' && mainWindow && !mainWindow.isDestroyed()) {
        loadConsole();
    }
});

supervisor.on('log', line => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('phishlens:backend-log', line);
    }
});

// A deep link from the browser launches a second copy of the app; that copy
// must hand its request to the running window rather than start a second
// backend over the same data directory.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
    app.quit();
} else {
    app.on('second-instance', (_event, argv) => {
        focusExistingWindow(deepLinkFromArgv(argv) || { route: 'dashboard' });
    });

    app.on('open-url', (event, url) => {
        event.preventDefault();
        const target = parseDeepLink(url);
        if (mainWindow) focusExistingWindow(target);
        else pendingRoute = target;
    });

    app.whenReady().then(async () => {
        if (process.defaultApp && process.argv.length >= 2) {
            app.setAsDefaultProtocolClient(PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
        } else {
            app.setAsDefaultProtocolClient(PROTOCOL);
        }

        createWindow(deepLinkFromArgv(process.argv) || { route: 'dashboard' });
        await supervisor.start();

        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createWindow({ route: 'dashboard' });
        });
    });

    app.on('window-all-closed', () => {
        if (process.platform !== 'darwin') app.quit();
    });
}

// An orphaned backend would hold the port and stop the app starting next time,
// so every exit path stops the child this process started.
app.on('before-quit', () => supervisor.stop());
process.on('exit', () => supervisor.stop());
process.on('SIGINT', () => { supervisor.stop(); app.quit(); });
process.on('SIGTERM', () => { supervisor.stop(); app.quit(); });

ipcMain.handle('phishlens:get-config', () => ({
    backendUrl: supervisor.baseUrl,
    // Supplied to the console so a desktop install authenticates without the
    // user being asked to invent and paste a key.
    apiKey: supervisor.apiKey,
    dashboardUrl: DEV_DASHBOARD_URL,
    version: app.getVersion()
}));

ipcMain.handle('phishlens:get-backend-status', () => supervisor.state());
ipcMain.handle('phishlens:restart-backend', async () => {
    supervisor.stop();
    supervisor.stopping = false;
    supervisor.restarts = 0;
    await supervisor.start();
    return supervisor.state();
});
