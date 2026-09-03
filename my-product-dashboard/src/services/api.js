import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL ? `${import.meta.env.VITE_API_BASE_URL}/api` : 'http://localhost:3001/api';

export const api = {
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
  getReportPdfUrl: (caseId) => `${API_BASE}/reports/pdf/${caseId}`
};
