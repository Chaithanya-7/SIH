import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL ? `${import.meta.env.VITE_API_BASE_URL}/api` : 'http://localhost:3001/api';

let currentSessionToken = localStorage.getItem('sm_session_token') || '';

axios.interceptors.request.use((config) => {
  if (currentSessionToken) {
    config.headers['Authorization'] = `Bearer ${currentSessionToken}`;
  }
  return config;
}, (error) => Promise.reject(error));

export const api = {
  setSessionToken: (token) => {
    currentSessionToken = token;
    if (token) localStorage.setItem('sm_session_token', token);
    else localStorage.removeItem('sm_session_token');
  },
  getSessionToken: () => currentSessionToken,

  // Google Authentication APIs
  verifyGoogleAuth: async (payload) => {
    const res = await axios.post(`${API_BASE}/auth/google/verify`, payload);
    if (res.data?.sessionToken) {
      api.setSessionToken(res.data.sessionToken);
    }
    return res.data;
  },
  getCurrentUser: async () => {
    const res = await axios.get(`${API_BASE}/auth/me`);
    return res.data;
  },

  // Organization Management APIs
  createOrganization: async (name, approvedDomain) => {
    const res = await axios.post(`${API_BASE}/org/create`, { name, approvedDomain });
    return res.data;
  },
  joinOrganization: async (inviteCode) => {
    const res = await axios.post(`${API_BASE}/org/join`, { inviteCode });
    return res.data;
  },
  getCurrentOrganization: async () => {
    const res = await axios.get(`${API_BASE}/org/current`);
    return res.data;
  },
  rotateInviteCode: async () => {
    const res = await axios.post(`${API_BASE}/org/rotate-invite`);
    return res.data;
  },

  // Gmail Connection & Sync APIs
  getGmailAuthUrl: async () => {
    const res = await axios.get(`${API_BASE}/auth/gmail/url`);
    return res.data;
  },
  exchangeGmailCode: async (code) => {
    const res = await axios.post(`${API_BASE}/auth/gmail/exchange`, { code });
    return res.data;
  },
  getMailboxStatus: async () => {
    const res = await axios.get(`${API_BASE}/mailbox/status`);
    return res.data;
  },
  syncMailbox: async () => {
    const res = await axios.post(`${API_BASE}/mailbox/sync`);
    return res.data;
  },
  disconnectMailbox: async () => {
    const res = await axios.post(`${API_BASE}/mailbox/disconnect`);
    return res.data;
  },

  // Core SOC APIs
  getHealth: async () => {
    const res = await axios.get(`${API_BASE}/health`);
    return res.data;
  },
  getCases: async () => {
    const res = await axios.get(`${API_BASE}/cases`);
    return res.data;
  },
  getCaseById: async (id) => {
    const res = await axios.get(`${API_BASE}/cases/${id}`);
    return res.data;
  },
  getGraph: async () => {
    const res = await axios.get(`${API_BASE}/graph`);
    return res.data;
  },
  getVips: async () => {
    const res = await axios.get(`${API_BASE}/vips`);
    return res.data;
  },
  getAuditLogs: async () => {
    const res = await axios.get(`${API_BASE}/audit`);
    return res.data;
  },

  // Ingestion coverage, adaptive learning and threat-intelligence state
  getOverview: async () => {
    const res = await axios.get(`${API_BASE}/overview`);
    return res.data;
  },
  getIngestionCoverage: async () => {
    const res = await axios.get(`${API_BASE}/ingestion`);
    return res.data;
  },
  getLearningState: async () => {
    const res = await axios.get(`${API_BASE}/learning`);
    return res.data;
  },
  getThreatIntelligence: async () => {
    const res = await axios.get(`${API_BASE}/threat-intelligence`);
    return res.data;
  },
  syncThreatIntelligence: async () => {
    const res = await axios.post(`${API_BASE}/threat-intelligence/sync`);
    return res.data;
  },
  getDetectionConfig: async () => {
    const res = await axios.get(`${API_BASE}/detection-config`);
    return res.data;
  },
  getRemediationActions: async () => {
    const res = await axios.get(`${API_BASE}/remediate/actions`);
    return res.data;
  },
  approveRemediationAction: async (actionId, analystUser = 'SOC_ANALYST', reason = 'Approved') => {
    const res = await axios.post(`${API_BASE}/remediate/approve`, { actionId, analystUser, reason });
    return res.data;
  },
  rollbackRemediationAction: async (actionId, analystUser = 'SOC_ANALYST', reason = 'Rollback') => {
    const res = await axios.post(`${API_BASE}/remediate/rollback`, { actionId, analystUser, reason });
    return res.data;
  },
  getIocResponseList: async () => {
    const res = await axios.get(`${API_BASE}/remediate/iocs`);
    return res.data;
  },
  getCampaignResponsePlan: async (campaignId) => {
    const res = await axios.get(`${API_BASE}/remediate/campaign/${campaignId}`);
    return res.data;
  },
  overrideRemediation: async (caseId, action, adminUser = 'SOC_ANALYST') => {
    const res = await axios.post(`${API_BASE}/remediate/override`, { caseId, action, adminUser });
    return res.data;
  },
  analyzeEmail: async (emailContent) => {
    const res = await axios.post(`${API_BASE}/analyze`, { emailContent });
    return res.data;
  },
  getReportPdfUrl: (caseId) => `${API_BASE}/reports/pdf/${caseId}`,

  // Admin Quarantine Queue & Scope APIs
  getScopeStatus: async () => {
    const res = await axios.get(`${API_BASE}/auth/gmail/scope-status`);
    return res.data;
  },
  getQuarantineQueue: async () => {
    const res = await axios.get(`${API_BASE}/admin/quarantine`);
    return res.data;
  },
  releaseCase: async (caseId, decisionReason, note = '') => {
    const res = await axios.post(`${API_BASE}/admin/quarantine/${caseId}/release`, { decisionReason, note });
    return res.data;
  },
  confirmThreat: async (caseId, decisionReason = 'CONFIRMED_THREAT', note = '') => {
    const res = await axios.post(`${API_BASE}/admin/quarantine/${caseId}/confirm-threat`, { decisionReason, note });
    return res.data;
  }
};
