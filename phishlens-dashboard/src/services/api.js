import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL ? `${import.meta.env.VITE_API_BASE_URL}/api` : 'http://localhost:3001/api';

let currentSessionToken = localStorage.getItem('sm_session_token') || '';

/**
 * Inside the installed desktop application the backend is started by the app
 * itself, which owns a locally generated key. Adopting it here is what lets a
 * desktop install work without asking the user to invent and paste a secret.
 * In a browser this does nothing and the normal session token is used.
 */
export const desktopReady = (async () => {
  if (!window.phishlens?.getConfig) return false;
  try {
    const config = await window.phishlens.getConfig();
    if (config?.apiKey) {
      currentSessionToken = config.apiKey;
      return true;
    }
  } catch (e) {
    // Fall back to whatever token the browser already had.
  }
  return false;
})();

/**
 * Every request waits for the key to be settled before it goes out.
 *
 * Adopting the desktop key is asynchronous - it crosses to the main process and
 * back - while the screens start loading the moment they mount. Whichever
 * happened to win decided whether a request carried a credential, and when the
 * screens won, the console reported "Authentication required" for a key it was
 * about to receive. It recovered on the next poll, which made it look
 * intermittent rather than ordered.
 *
 * Awaiting here rather than in each screen means no caller has to remember, and
 * no request can be the one that goes out early. In a browser the promise
 * resolves immediately and nothing waits.
 */
axios.interceptors.request.use(async (config) => {
  await desktopReady.catch(() => false);

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
  // Every message as a transport flow, for the packet-analyser view. A
  // projection of the same cases, computed server-side so there is one
  // implementation of what each column means.
  getFlow: async () => {
    const res = await axios.get(`${API_BASE}/flow`);
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
  getSecurityTools: async () => {
    const res = await axios.get(`${API_BASE}/security-tools`);
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
  // Who is acting comes from the authenticated session on the server, not from
  // this payload. Sending a name here never determined the audit record and no
  // longer pretends to.
  approveRemediationAction: async (actionId, reason = 'Approved') => {
    const res = await axios.post(`${API_BASE}/remediate/approve`, { actionId, reason });
    return res.data;
  },
  rollbackRemediationAction: async (actionId, reason = 'Rollback') => {
    const res = await axios.post(`${API_BASE}/remediate/rollback`, { actionId, reason });
    return res.data;
  },
  /**
   * Submit a saved message file for analysis.
   *
   * The bytes are sent as the request body rather than as a form field,
   * because the server hashes exactly what it is given. Posted as a form, the
   * multipart envelope is what would be parsed - which yields a message with
   * no headers and one attachment, and a confident verdict of SAFE. The server
   * refuses that shape now, and this is the shape it wants.
   */
  uploadMessageFile: async (file) => {
    const text = await file.text();
    const res = await axios.post(
      `${API_BASE}/ingest/file?filename=${encodeURIComponent(file.name)}`,
      text,
      { headers: { 'Content-Type': 'message/rfc822' } }
    );
    return res.data;
  },

  // ---- Signing in with Google ----
  //
  // The OAuth client belongs to whoever runs this copy. These read and write
  // that registration; beginGoogleSignIn returns a URL that must be opened in
  // the real browser, because Google refuses consent inside an embedded view.
  getGoogleClient: async () => {
    const res = await axios.get(`${API_BASE}/auth/google/client`);
    return res.data;
  },
  saveGoogleClient: async (clientId, clientSecret) => {
    const res = await axios.post(`${API_BASE}/auth/google/client`, { clientId, clientSecret });
    return res.data;
  },
  forgetGoogleClient: async () => {
    const res = await axios.delete(`${API_BASE}/auth/google/client`);
    return res.data;
  },
  beginGoogleSignIn: async (folder) => {
    const res = await axios.post(`${API_BASE}/auth/google/begin`, { folder });
    return res.data;
  },

  getConnections: async () => {
    const res = await axios.get(`${API_BASE}/connections`);
    return res.data;
  },
  testConnection: async (payload) => {
    const res = await axios.post(`${API_BASE}/connections/test`, payload);
    return res.data;
  },
  addConnection: async (payload) => {
    const res = await axios.post(`${API_BASE}/connections`, payload);
    return res.data;
  },
  removeConnection: async (id) => {
    const res = await axios.delete(`${API_BASE}/connections/${id}`);
    return res.data;
  },

  getRemediationPosture: async () => {
    const res = await axios.get(`${API_BASE}/remediation/posture`);
    return res.data;
  },
  getPendingApprovals: async () => {
    const res = await axios.get(`${API_BASE}/remediation/pending`);
    return res.data;
  },
  getDomainPosture: async () => {
    const res = await axios.get(`${API_BASE}/remediation/domain-posture`);
    return res.data;
  },
  getNeverContain: async () => {
    const res = await axios.get(`${API_BASE}/remediation/never-contain`);
    return res.data;
  },
  addNeverContain: async (entry) => {
    const res = await axios.post(`${API_BASE}/remediation/never-contain`, { entry });
    return res.data;
  },
  removeNeverContain: async (entry) => {
    const res = await axios.delete(`${API_BASE}/remediation/never-contain/${encodeURIComponent(entry)}`);
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
  overrideRemediation: async (caseId, action) => {
    const res = await axios.post(`${API_BASE}/remediate/override`, { caseId, action });
    return res.data;
  },
  analyzeEmail: async (emailContent) => {
    const res = await axios.post(`${API_BASE}/analyze`, { emailContent });
    return res.data;
  },
  getReportPdfUrl: (caseId) => `${API_BASE}/reports/pdf/${caseId}`,

  /**
   * Fetches the forensic report and hands the browser a file to save.
   *
   * The button used to be an ordinary link to the endpoint, which cannot work:
   * a plain <a href> carries no Authorization header, so every download hit the
   * API unauthenticated and came back 401. The failure was silent - a new tab
   * that showed nothing. Verified: the same URL returns 401 as a link and a
   * 14 KB PDF when the key is sent.
   */
  downloadReportPdf: async (caseId) => {
    const response = await axios.get(`${API_BASE}/reports/pdf/${caseId}`, { responseType: 'blob' });
    const blobUrl = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `PhishLens_Report_${caseId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Released on the next tick so the download has taken the reference.
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    return true;
  },


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
