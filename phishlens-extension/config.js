// PhishLens Chrome Extension Configuration
const PHISHLENS_CONFIG = {
  API_BASE_URL: 'http://localhost:3001',
  DASHBOARD_URL: 'http://localhost:3005'
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PHISHLENS_CONFIG;
}
