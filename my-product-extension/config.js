// SecureMail AI Chrome Extension Configuration
const SECUREMAIL_CONFIG = {
  API_BASE_URL: 'http://localhost:3001',
  DASHBOARD_URL: 'http://localhost:3005'
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SECUREMAIL_CONFIG;
}
