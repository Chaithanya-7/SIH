// PhishLens Chrome/Firefox Extension Configuration
const PHISHLENS_CONFIG = {
  API_BASE_URL: 'http://localhost:3001',
  DASHBOARD_URL: 'http://localhost:3005',

  // Deep link handled by the installed PhishLens desktop application, which
  // registers this scheme with the operating system at install time. The
  // popup is intentionally a thin summary; "More info" hands off to the
  // installed app for the full SOC investigation view.
  DESKTOP_APP_SCHEME: 'phishlens://'
};

// Chrome, Edge, Brave and Opera expose `chrome`; Firefox exposes `browser`.
// Using whichever exists keeps one codebase working across all of them.
const phishlensExt = (typeof globalThis !== 'undefined' && (globalThis.browser || globalThis.chrome)) || undefined;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PHISHLENS_CONFIG;
}
