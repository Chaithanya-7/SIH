/**
 * PhishLens Extension background worker.
 *
 * Its only job is to keep the toolbar badge showing the current number of
 * high-risk detections, so the icon itself carries the "limited required
 * information" and the popup/desktop app carry everything else. It performs
 * no detection locally - all analysis happens in the PhishLens backend.
 */
const ext = globalThis.browser || globalThis.chrome;

const DEFAULTS = {
  apiBaseUrl: 'http://localhost:3001',
  dashboardUrl: 'http://localhost:3005',
  apiKey: ''
};

const REFRESH_ALARM = 'phishlens-refresh-badge';

function readSettings() {
  return new Promise(resolve => {
    ext.storage.local.get(DEFAULTS, stored => resolve({ ...DEFAULTS, ...stored }));
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
      return { ok: false, error: `PhishLens returned ${response.status}.` };
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
});
