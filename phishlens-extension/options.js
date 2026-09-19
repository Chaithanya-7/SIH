document.addEventListener('DOMContentLoaded', () => {
  const ext = globalThis.browser || globalThis.chrome;

  const apiBaseInput = document.getElementById('api-base-url');
  const dashboardInput = document.getElementById('dashboard-url');
  const apiKeyInput = document.getElementById('api-key');
  const status = document.getElementById('status');

  const defaults = {
    apiBaseUrl: PHISHLENS_CONFIG.API_BASE_URL,
    dashboardUrl: PHISHLENS_CONFIG.DASHBOARD_URL,
    apiKey: ''
  };

  function setStatus(message, kind) {
    status.textContent = message;
    status.className = `status ${kind}`;
  }

  ext.storage.local.get(defaults, stored => {
    const settings = { ...defaults, ...stored };
    apiBaseInput.value = settings.apiBaseUrl;
    dashboardInput.value = settings.dashboardUrl;
    apiKeyInput.value = settings.apiKey;
  });

  function currentSettings() {
    return {
      apiBaseUrl: (apiBaseInput.value || defaults.apiBaseUrl).replace(/\/+$/, ''),
      dashboardUrl: (dashboardInput.value || defaults.dashboardUrl).replace(/\/+$/, ''),
      apiKey: apiKeyInput.value.trim()
    };
  }

  document.getElementById('btn-save').addEventListener('click', () => {
    ext.storage.local.set(currentSettings(), () => setStatus('Settings saved.', 'ok'));
  });

  document.getElementById('btn-test').addEventListener('click', async () => {
    const settings = currentSettings();
    if (!settings.apiKey) return setStatus('Enter an API key first.', 'error');

    setStatus('Testing…', '');
    try {
      const response = await fetch(`${settings.apiBaseUrl}/api/summary`, {
        headers: { 'x-api-key': settings.apiKey }
      });

      if (response.status === 401 || response.status === 403) {
        return setStatus('Backend reachable, but the API key was rejected.', 'error');
      }
      if (!response.ok) {
        return setStatus(`Backend returned HTTP ${response.status}.`, 'error');
      }

      const data = await response.json();
      setStatus(`Connected. ${data.total} message(s) analyzed so far.`, 'ok');
    } catch (err) {
      setStatus(`Could not reach ${settings.apiBaseUrl}.`, 'error');
    }
  });
});
