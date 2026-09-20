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

  const connectionState = document.getElementById('connection-state');
  const setupNotice = document.getElementById('setup-notice');
  const setupMessage = document.getElementById('setup-message');
  const summary = document.getElementById('summary');
  const recentList = document.getElementById('recent-list');

  const defaults = {
    apiBaseUrl: PHISHLENS_CONFIG.API_BASE_URL,
    dashboardUrl: PHISHLENS_CONFIG.DASHBOARD_URL,
    apiKey: ''
  };

  function readSettings() {
    return new Promise(resolve => {
      if (!ext?.storage?.local) return resolve(defaults);
      ext.storage.local.get(defaults, stored => resolve({ ...defaults, ...stored }));
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

  function showSetupNotice(message) {
    setupMessage.textContent = message;
    setupNotice.classList.remove('hidden');
    summary.classList.add('hidden');
  }

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

    recentList.innerHTML = '';
    if (!data.recent.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = 'No messages analyzed yet.';
      recentList.appendChild(li);
    } else {
      data.recent.forEach(item => {
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

    setupNotice.classList.add('hidden');
    summary.classList.remove('hidden');
    connectionState.textContent = `${data.total} message${data.total === 1 ? '' : 's'} analyzed`;
  }

  async function loadSummary() {
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
