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

/** The webmail this extension watches. Used for injecting and for nudging. */
const MAIL_HOSTS = [
  'https://mail.google.com/*',
  'https://outlook.live.com/*',
  'https://outlook.office.com/*',
  'https://outlook.office365.com/*'
];

/** The most recent sweep reported by a content script, or null if none ever has. */
let lastWatchStatus = null;

/** The last thing a backlog scan said, kept so the popup can be closed without losing it. */
let lastBacklogStatus = null;

/** The tab a backlog scan is running in, so it can be asked for progress or told to stop. */
let backlogTabId = null;

/**
 * Starts a backlog scan in a tab of its own.
 *
 * A tab of its own because the scan walks the mail list page by page, and doing
 * that in the tab somebody is reading would yank the page out from under them
 * for however many hours it takes. The new tab opens in the background, so the
 * scan starts without taking over the screen.
 */
async function startBacklogScan(startPage) {
  if (!ext.tabs?.create || !ext.scripting?.executeScript) {
    return { ok: false, error: 'This browser build cannot open a tab for the scan.' };
  }

  // Already running somewhere: say so rather than starting a second one, which
  // would double the request rate at the mail provider - the one thing the
  // pacing exists to avoid.
  const existing = await forwardToBacklogTab({ type: 'phishlens:backlog-status' });
  if (existing?.ok && existing.backlog?.running) {
    return { ok: false, error: 'A backlog scan is already running.', backlog: existing.backlog };
  }

  try {
    const tab = await ext.tabs.create({ url: 'https://mail.google.com/mail/u/0/#inbox', active: false });
    backlogTabId = tab.id;

    // Wait for the page to be far enough along to inject into. A mail client
    // is a large application; injecting the instant the tab exists lands in a
    // document that has not started rendering the list yet.
    await new Promise(resolve => setTimeout(resolve, 6000));

    await ext.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['mail-providers.js', 'content-gmail.js']
    });

    const started = await sendToTab(tab.id, { type: 'phishlens:backlog-start', startPage });
    if (!started?.ok) {
      return { ok: false, error: started?.error || 'The scan did not start in the new tab.' };
    }

    return {
      ok: true,
      tabId: tab.id,
      pace_ms: started.pace_ms,
      note: 'Running in a background tab. It is paced deliberately, so a full mailbox takes hours; closing that tab stops it and the next run resumes from the last completed page.'
    };
  } catch (e) {
    return { ok: false, error: String(e && e.message || e).slice(0, 300) };
  }
}

function sendToTab(tabId, message) {
  return new Promise(resolve => {
    try {
      ext.tabs.sendMessage(tabId, message, answer => {
        // A tab that has been closed, or never had the script, sets
        // lastError rather than throwing.
        void ext.runtime.lastError;
        resolve(answer || null);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

/** Asks the scanning tab something, or reports that there is no longer one. */
async function forwardToBacklogTab(message) {
  if (backlogTabId === null) return null;
  const answer = await sendToTab(backlogTabId, message);
  // The tab was closed, so the scan is over whatever the last report said.
  if (!answer) backlogTabId = null;
  return answer;
}

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

/**
 * Starts watching tabs that were already open.
 *
 * A content script is injected when a page loads. Loading or reloading an
 * extension does not re-run it in tabs that are already there - so somebody who
 * reloads the extension with Gmail open in another tab gets nothing at all, and
 * the only hint is a popup saying the watcher has not reported. Expecting a
 * person to know they must also reload the mail tab is expecting them to know
 * how extensions are loaded.
 *
 * So the worker finds those tabs and injects into them itself, on install, on
 * update and on browser startup.
 */
async function watchAlreadyOpenTabs(reason) {
  if (!ext.scripting?.executeScript || !ext.tabs?.query) return;

  let tabs = [];
  try {
    tabs = await ext.tabs.query({ url: MAIL_HOSTS });
  } catch (e) {
    return;
  }

  for (const tab of tabs) {
    try {
      await ext.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['mail-providers.js', 'content-gmail.js']
      });
      console.log(`[PhishLens] Started watching an already-open mail tab (${reason}).`);
    } catch (e) {
      // The tab may have navigated away, or be one the browser will not let an
      // extension touch. Nothing to do but leave it to the normal injection.
    }
  }
}

ext.runtime.onInstalled.addListener(() => {
  watchAlreadyOpenTabs('installed or updated');
});
ext.runtime.onStartup?.addListener(() => watchAlreadyOpenTabs('browser started'));

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
    // A backlog sweep reports through the same channel, and its progress has to
    // survive the popup closing - which is most of the hours it runs for.
    if (request.status?.backlog) {
      lastBacklogStatus = { ...request.status.backlog, host: request.status.host, at: request.status.at };
    }
    sendResponse({ ok: true });
    return false;
  }

  // ---- The backlog scan -------------------------------------------------
  //
  // Driven from here rather than from the popup, for two reasons. The popup
  // closes the moment somebody clicks elsewhere, and this runs for hours. And
  // the scan navigates the tab it runs in through page after page of the list,
  // which is intolerable in the tab somebody is reading their mail in - so it
  // gets a tab of its own.
  if (request?.type === 'phishlens:backlog-start') {
    startBacklogScan(request.startPage).then(sendResponse);
    return true;
  }

  if (request?.type === 'phishlens:backlog-stop') {
    forwardToBacklogTab({ type: 'phishlens:backlog-stop' })
      .then(answer => sendResponse(answer || { ok: false, error: 'No tab is running a backlog scan.' }));
    return true;
  }

  if (request?.type === 'phishlens:backlog-status') {
    // The live answer if the tab is still there, and the last thing it said if
    // it is not - marked as stale, because "the scan stopped when you closed
    // the tab" and "the scan is still going" must not look the same.
    forwardToBacklogTab({ type: 'phishlens:backlog-status' })
      .then(live => sendResponse(live?.ok ? live : { ok: true, backlog: lastBacklogStatus, stale: true }));
    return true;
  }
  /**
   * Why nothing is being watched, in terms somebody can act on.
   *
   * "The page watcher has not reported yet" is true and useless: it does not
   * say whether a mail tab is even open, whether the watcher is in it, or
   * whether the extension lacks the permission to put one there. Those need
   * three different things done about them.
   */
  if (request?.type === 'phishlens:diagnose') {
    (async () => {
      const diagnosis = {
        canQueryTabs: Boolean(ext.tabs?.query),
        canInject: Boolean(ext.scripting?.executeScript),
        mailTabs: 0,
        watchedTabs: 0
      };

      if (!diagnosis.canQueryTabs) { sendResponse(diagnosis); return; }

      let tabs = [];
      try { tabs = await ext.tabs.query({ url: MAIL_HOSTS }); } catch (e) { tabs = []; }
      diagnosis.mailTabs = tabs.length;

      // A watcher answers this; a tab with none does not.
      for (const tab of tabs) {
        try {
          const reply = await ext.tabs.sendMessage(tab.id, { type: 'phishlens:ping' });
          if (reply && reply.ok) diagnosis.watchedTabs++;
        } catch (e) {
          // Nothing listening in that tab.
        }
      }

      sendResponse(diagnosis);
    })();
    return true;
  }

  if (request?.type === 'phishlens:get-watch-status') {
    sendResponse(lastWatchStatus);
    return false;
  }
  // "Check my mail now", from the popup's refresh button.
  //
  // Two things have to happen, because either can be the reason nothing is
  // being examined: a tab that was open before the extension loaded has no
  // watcher in it at all, and a tab that does have one is between polls.
  if (request?.type === 'phishlens:sweep-now') {
    (async () => {
      await watchAlreadyOpenTabs('asked from the popup');

      let nudged = 0;
      try {
        const tabs = await ext.tabs.query({ url: MAIL_HOSTS });
        for (const tab of tabs) {
          try {
            await ext.tabs.sendMessage(tab.id, { type: 'phishlens:sweep-now' });
            nudged++;
          } catch (e) {
            // No watcher listening in that tab yet. The injection above will
            // have started one, and it sweeps as soon as it comes up.
          }
        }
      } catch (e) {
        // No tabs permission, or no mail tabs. Nothing to nudge.
      }

      await refreshBadge();
      sendResponse({ ok: true, tabs: nudged });
    })();
    return true;
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
