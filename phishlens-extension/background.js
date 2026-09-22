/**
 * PhishLens Extension background worker.
 *
 * Its only job is to keep the toolbar badge showing the current number of
 * high-risk detections, so the icon itself carries the "limited required
 * information" and the popup/desktop app carry everything else. It performs
 * no detection locally - all analysis happens in the PhishLens backend.
 */
const ext = globalThis.browser || globalThis.chrome;

// Settings the desktop application wrote when it published this copy. Absent in
// a plain checkout, in which case nothing changes and the options page asks.
try {
    importScripts('provisioned.js');
} catch (e) {
    // A build without the file, or a browser loading this as a module rather
    // than a classic worker. Either way the options page still works.
}

const DEFAULTS = {
  apiBaseUrl: 'http://localhost:3001',
  dashboardUrl: 'http://localhost:3005',
  apiKey: ''
};

const REFRESH_ALARM = 'phishlens-refresh-badge';

/** The most recent sweep reported by a content script, or null if none ever has. */
let lastWatchStatus = null;

/**
 * What the extension should use, in order of who decided it.
 *
 * Anything saved in the browser wins: somebody typing a value on the options
 * page must not be overruled by a default. Below that sits whatever the desktop
 * application provisioned, and below that the built-in addresses.
 *
 * The stored value is only allowed to win when it is actually set - Chrome
 * returns the defaults object's empty string for a key that was never saved,
 * and spreading that over a provisioned key would blank it.
 */
function readSettings() {
  return new Promise(resolve => {
    const provisioned = globalThis.PHISHLENS_PROVISIONED || {};
    ext.storage.local.get(DEFAULTS, stored => {
      const settled = { ...DEFAULTS };
      if (provisioned.apiBaseUrl) settled.apiBaseUrl = provisioned.apiBaseUrl;
      if (provisioned.apiKey) settled.apiKey = provisioned.apiKey;
      Object.entries(stored || {}).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') settled[key] = value;
      });
      resolve(settled);
    });
  });
}

async function refreshBadge() {
  const settings = await readSettings();
  if (!settings.apiKey) {
    await setBadge('', '#64748b');
    return;
  }

  try {
    const response = await fetch(`${settings.apiBaseUrl}/api/summary`, {
      headers: { 'x-api-key': settings.apiKey }
    });
    if (!response.ok) {
      await setBadge('!', '#f59e0b');
      return;
    }

    const data = await response.json();
    const highRisk = data.counts?.high_risk || 0;
    await setBadge(highRisk ? String(highRisk) : '', '#ef4444');
  } catch (err) {
    await setBadge('!', '#f59e0b');
  }
}

async function setBadge(text, color) {
  if (!ext.action) return;
  try {
    await ext.action.setBadgeText({ text });
    await ext.action.setBadgeBackgroundColor({ color });
  } catch (err) {
    // Badge APIs are unavailable in some browsers/contexts; the popup still works.
  }
}

ext.runtime.onInstalled.addListener(() => {
  ext.alarms?.create(REFRESH_ALARM, { periodInMinutes: 5 });
  refreshBadge();
});

ext.runtime.onStartup?.addListener(refreshBadge);
ext.alarms?.onAlarm.addListener(alarm => {
  if (alarm.name === REFRESH_ALARM) refreshBadge();
});

/**
 * Submits a message the browser watcher found, on its behalf.
 *
 * The content script cannot make this request itself: its fetch carries the
 * mail site's origin, so the browser treats a call to localhost as cross-origin
 * and blocks it. The service worker holds the host permission for the backend
 * and is not bound by the page's CORS, so the request belongs here. It also
 * keeps the API key out of a script injected into a page.
 */
async function examineFromBrowser(payload) {
  const settings = await readSettings();
  if (!settings.apiKey) {
    return { ok: false, error: 'PhishLens has no API key configured. Open the extension options.' };
  }

  try {
    const base = settings.apiBaseUrl.replace(/\/$/, '');
    const response = await fetch(`${base}/api/ingest/browser`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': settings.apiKey },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      // The backend puts the reason in the body. Reporting only the status code
      // turned a diagnosable fault into "returned 500", which says nothing about
      // which message failed or why - and the status is the one thing already
      // obvious from the request failing.
      let detail = '';
      try {
        const body = await response.json();
        if (body && body.error) detail = String(body.error).slice(0, 300);
      } catch (e) {
        // Not JSON, or already consumed. The status alone will have to do.
      }
      return {
        ok: false,
        error: `PhishLens returned ${response.status}${detail ? ': ' + detail : '.'}`
      };
    }
    const result = await response.json();
    // A verdict changes the badge, so it is refreshed rather than left stale.
    refreshBadge();
    return { ok: true, result };
  } catch (e) {
    return { ok: false, error: `PhishLens is not reachable (${e.message}).` };
  }
}

// The popup asks for an immediate refresh after settings change.
ext.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request?.type === 'REFRESH_BADGE') {
    refreshBadge().then(() => sendResponse({ success: true }));
    return true;
  }
  if (request?.type === 'phishlens:examine') {
    examineFromBrowser(request.payload).then(sendResponse);
    return true;
  }
  // The popup and the options page cannot see what the desktop application
  // provisioned: that file is imported into this worker, not into a page, and
  // the values are deliberately not copied into storage - storage is where a
  // person's own choice lives, and writing provisioned values there would
  // overwrite it on the next start. So they ask here instead, and there stays
  // one place that knows the precedence.
  // What the page watcher last saw. Kept in the worker rather than in storage:
  // it is a live fact about this browsing session, not a setting, and it should
  // not survive as a stale reassurance after the browser is closed.
  if (request?.type === 'phishlens:watch-status') {
    lastWatchStatus = request.status || null;
    sendResponse({ ok: true });
    return false;
  }
  if (request?.type === 'phishlens:get-watch-status') {
    sendResponse(lastWatchStatus);
    return false;
  }
  if (request?.type === 'phishlens:get-settings') {
    readSettings().then(settings => sendResponse({
      ...settings,
      // Says where the key came from, so the options page can show it as
      // supplied rather than presenting an empty box over a working key.
      provisioned: Boolean(globalThis.PHISHLENS_PROVISIONED?.apiKey)
    }));
    return true;
  }
});
