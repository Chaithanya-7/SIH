/**
 * PhishLens popup: a thin client.
 *
 * It shows only headline verdict counts and the most recent detections. All
 * deep investigation happens in the installed PhishLens desktop application
 * (or, as a fallback, the web console) - the popup never duplicates detection
 * logic or renders full case data.
 */
document.addEventListener('DOMContentLoaded', () => {
  const ext = globalThis.browser || globalThis.chrome;

  globalThis.PhishLensTheme?.attach(document.getElementById('btn-theme'));

  const connectionState = document.getElementById('connection-state');
  const setupNotice = document.getElementById('setup-notice');
  const watchState = document.getElementById('watch-state');
  const drawer = document.getElementById('details-drawer');
  const drawerTitle = document.getElementById('drawer-title');

  /** The most recent summary, kept so filtering need not ask the backend again. */
  let lastSummary = null;
  /** Which verdict the list is filtered to, or null for all of them. */
  let filterVerdict = null;
  const setupMessage = document.getElementById('setup-message');
  const summary = document.getElementById('summary');
  const recentList = document.getElementById('recent-list');

  const defaults = {
    apiBaseUrl: PHISHLENS_CONFIG.API_BASE_URL,
    dashboardUrl: PHISHLENS_CONFIG.DASHBOARD_URL,
    apiKey: ''
  };

  /**
   * Asks the background worker what the settings actually are.
   *
   * Reading storage directly was wrong: the key the desktop application writes
   * lives in provisioned.js, which is imported into the worker and not into
   * this page, so a fully configured extension reported "Not configured" here
   * while the worker was using the key perfectly well.
   *
   * Storage is still the fallback, for the case where the worker is asleep and
   * cannot be woken.
   */
  function readSettings() {
    return new Promise(resolve => {
      const fromStorage = () => {
        if (!ext?.storage?.local) return resolve(defaults);
        ext.storage.local.get(defaults, stored => resolve({ ...defaults, ...stored }));
      };

      if (!ext?.runtime?.sendMessage) return fromStorage();

      try {
        ext.runtime.sendMessage({ type: 'phishlens:get-settings' }, response => {
          // A sleeping or missing worker sets lastError; touching it also stops
          // the browser logging it as unchecked.
          if (ext.runtime.lastError || !response) return fromStorage();
          resolve({ ...defaults, ...response });
        });
      } catch (e) {
        fromStorage();
      }
    });
  }

  function openUrl(url) {
    if (ext?.tabs?.create) ext.tabs.create({ url });
    else window.open(url, '_blank');
  }

  function openOptions() {
    if (ext?.runtime?.openOptionsPage) ext.runtime.openOptionsPage();
    else openUrl('options.html');
  }

  /**
   * Says what the watcher is doing on the mail tab, in plain terms.
   *
   * Three situations look identical from the counts alone: the watcher never
   * ran, it ran and recognised nothing on the page, and it ran with nothing new
   * to examine. Only the first two are faults, and only this tells them apart.
   */
  function showWatchState() {
    if (!watchState || !ext?.runtime?.sendMessage) return;

    try {
      ext.runtime.sendMessage({ type: 'phishlens:get-watch-status' }, status => {
        // Touching lastError also stops the browser logging it as unchecked.
        if (ext.runtime.lastError) return;

        if (!status) {
          watchState.textContent = 'The page watcher has not reported yet. Open Gmail or Outlook Web in a tab, then reopen this.';
          watchState.classList.remove('hidden');
          return;
        }

        const ago = Math.max(0, Math.round((Date.now() - new Date(status.at).getTime()) / 1000));
        const seen = Number(status.rowsSeen || 0);

        if (status.phase === 'error') {
          watchState.textContent = `Watching ${status.host}, but the last sweep stopped: ${status.error}`;
        } else if (seen === 0) {
          // Nothing on the page the reader recognises as a message row.
          watchState.textContent = `Running on ${status.host} but found no messages in the list ${ago}s ago. If mail is on screen, this reader no longer matches that page.`;
        } else if (Number(status.identified ?? seen) === 0) {
          // Rows were found and none could be identified. A different fault
          // from the one above, and it used to look exactly like it.
          watchState.textContent = `Running on ${status.host}: ${seen} rows on the page, but none carried a message id ${ago}s ago. The list is being read; the identifier has moved.`;
        } else {
          const identified = Number(status.identified ?? seen);
          watchState.textContent = `Watching ${status.host}: ${identified} message${identified === 1 ? '' : 's'} in view, ${status.examined ?? 0} examined ${ago}s ago.`;
        }
        watchState.classList.remove('hidden');
      });
    } catch (e) {
      // The worker is unavailable. The rest of the popup still works.
    }
  }

  function showSetupNotice(message) {
    setupMessage.textContent = message;
    setupNotice.classList.remove('hidden');
    summary.classList.add('hidden');
  }

  /** Shown when the list is filtered, so the drawer title says what it is showing. */
  const LABELS = { high: 'High risk', suspicious: 'Suspicious', safe: 'Legitimate' };

  function verdictClass(verdict) {
    if (verdict === 'HIGH_RISK') return 'high';
    if (verdict === 'SUSPICIOUS') return 'suspicious';
    return 'safe';
  }

  function renderSummary(data) {
    document.getElementById('count-high').textContent = data.counts.high_risk;
    document.getElementById('count-suspicious').textContent = data.counts.suspicious;
    document.getElementById('count-safe').textContent = data.counts.safe;
    document.getElementById('count-quarantined').textContent = data.quarantined;
    document.getElementById('count-review').textContent = data.awaiting_review;

    // Said plainly rather than left to be inferred from a zero: a quarantine
    // count of nought means something quite different when the installation is
    // not configured to move mail at all.
    const modeNote = document.getElementById('mode-note');
    if (modeNote) {
      const acting = data.remediation?.can_act_on_mail;
      modeNote.textContent = acting
        ? 'Live: confirmed high-risk mail is moved out of the inbox.'
        : 'Simulation: threats are detected and recorded, but no mail is moved.';
      modeNote.className = acting ? 'mode-note live' : 'mode-note simulated';
    }

    lastSummary = data;
    renderRecent();

    setupNotice.classList.add('hidden');
    summary.classList.remove('hidden');
    connectionState.textContent = `${data.total} message${data.total === 1 ? '' : 's'} analyzed`;
  }

  /**
   * The recent list, showing either everything or one verdict.
   *
   * Pressing a count filters to it. The counts were three numbers that looked
   * pressable and were not, and the question they raise - which messages are
   * those - had no answer in the popup at all.
   */
  function renderRecent() {
    const data = lastSummary;
    if (!data) return;

    const items = (data.recent || []).filter(item =>
      !filterVerdict || verdictClass(item.verdict) === filterVerdict);

    drawerTitle.textContent = filterVerdict
      ? `${LABELS[filterVerdict]} — ${items.length} shown`
      : 'Recent detections';

    recentList.innerHTML = '';
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = filterVerdict
        ? `Nothing in the recent list is ${LABELS[filterVerdict].toLowerCase()}.`
        : 'No messages analyzed yet.';
      recentList.appendChild(li);
    } else {
      items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'recent-item';

        const subject = document.createElement('span');
        subject.className = 'recent-subject';
        subject.textContent = item.subject;

        const badge = document.createElement('span');
        badge.className = `badge ${verdictClass(item.verdict)}`;
        badge.textContent = item.verdict.replace('_', ' ');

        li.appendChild(subject);
        li.appendChild(badge);
        recentList.appendChild(li);
      });
    }
  }

  /**
   * Pressing a count shows only those messages.
   *
   * Pressing the same one again clears the filter, so there is always a way back
   * without knowing which of the three was pressed. The drawer opens on a
   * filter, because filtering a list nobody can see would do nothing visible.
   */
  ['high', 'suspicious', 'safe'].forEach(verdict => {
    const button = document.getElementById(`filter-${verdict}`);
    if (!button) return;

    button.addEventListener('click', () => {
      filterVerdict = filterVerdict === verdict ? null : verdict;

      ['high', 'suspicious', 'safe'].forEach(other => {
        const el = document.getElementById(`filter-${other}`);
        if (el) {
          el.setAttribute('aria-pressed', String(filterVerdict === other));
          el.classList.toggle('active', filterVerdict === other);
        }
      });

      renderRecent();
      if (filterVerdict && drawer) drawer.open = true;
    });
  });

  /**
   * "Check my mail now".
   *
   * Asks the worker to start a watcher in any mail tab that has none, nudge the
   * ones that have, then re-reads the summary. The button says what happened
   * while it is happening, because a button that looks identical before and
   * after leaves somebody pressing it again.
   */
  const refreshButton = document.getElementById('btn-refresh');
  if (refreshButton) {
    refreshButton.addEventListener('click', () => {
      if (refreshButton.disabled) return;

      refreshButton.disabled = true;
      refreshButton.classList.add('spinning');
      const restore = () => {
        refreshButton.disabled = false;
        refreshButton.classList.remove('spinning');
      };

      const done = () => { loadSummary().finally(restore); };

      if (!ext?.runtime?.sendMessage) { done(); return; }

      try {
        ext.runtime.sendMessage({ type: 'phishlens:sweep-now' }, () => {
          // Touched so the browser does not log it as unchecked; a sleeping
          // worker is not a failure worth reporting here.
          void ext.runtime.lastError;
          // A sweep has to fetch and examine before anything changes, so the
          // summary is re-read a moment later rather than immediately.
          setTimeout(done, 1200);
        });
      } catch (e) {
        done();
      }
    });
  }

  async function loadSummary() {
    // Always, and before anything else that can return early. Whether the page
    // watcher is running is independent of whether the backend answers, and it
    // matters most in the cases below where this function gives up.
    showWatchState();

    const settings = await readSettings();

    if (!settings.apiKey) {
      connectionState.textContent = 'Not configured';
      showSetupNotice('An API key is required before the extension can read detections from your PhishLens backend.');
      return;
    }

    try {
      const response = await fetch(`${settings.apiBaseUrl}/api/summary`, {
        headers: { 'x-api-key': settings.apiKey }
      });

      if (response.status === 401 || response.status === 403) {
        connectionState.textContent = 'Not authorized';
        showSetupNotice('The configured API key was rejected by the PhishLens backend.');
        return;
      }
      if (!response.ok) {
        connectionState.textContent = 'Unavailable';
        showSetupNotice(`PhishLens backend returned HTTP ${response.status}.`);
        return;
      }

      renderSummary(await response.json());
    } catch (err) {
      connectionState.textContent = 'Offline';
      showSetupNotice(`Could not reach the PhishLens backend at ${settings.apiBaseUrl}.`);
    }
  }

  // "More info" hands off to the installed desktop application via the
  // phishlens:// scheme it registers with the operating system. If the app is
  // not installed the browser cannot open the scheme, so an explicit web
  // console fallback is always offered rather than guessing with a timer.
  document.getElementById('btn-more-info').addEventListener('click', async () => {
    openUrl(`${PHISHLENS_CONFIG.DESKTOP_APP_SCHEME}dashboard`);
  });

  document.getElementById('btn-web-console').addEventListener('click', async () => {
    const settings = await readSettings();
    openUrl(settings.dashboardUrl);
  });

  document.getElementById('btn-settings').addEventListener('click', openOptions);
  document.getElementById('btn-open-settings').addEventListener('click', openOptions);

  loadSummary();
});
