import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, CheckCircle, XCircle, AlertTriangle, RefreshCw, Key, ArrowRight, Lock, Check } from 'lucide-react';
import { api } from '../services/api';

export default function AdminQuarantineQueue({ currentUser, currentOrg, onRefresh }) {
  const [cases, setCases] = useState([]);
  const [filter, setFilter] = useState('pending'); // pending | high_risk | confirmed | released | failed | all
  const [loading, setLoading] = useState(false);
  const [scopeStatus, setScopeStatus] = useState({ hasModifyScope: true, reauthUrl: null });
  const [selectedCase, setSelectedCase] = useState(null);

  // Modal States
  const [releaseModalOpen, setReleaseModalOpen] = useState(false);
  const [confirmModalOpen, setConfirmModalOpen] = useState(false);
  const [decisionReason, setDecisionReason] = useState('FALSE_POSITIVE');
  const [adminNote, setAdminNote] = useState('');
  const [actionProgress, setActionProgress] = useState(null); // 'REQUESTING' | 'VERIFYING' | 'SUCCESS' | 'FAILED'
  const [actionError, setActionError] = useState(null);

  const fetchQueueData = async () => {
    setLoading(true);
    try {
      const [queueRes, scopeRes] = await Promise.all([
        api.getQuarantineQueue().catch(e => ({ cases: [] })),
        api.getScopeStatus().catch(e => ({ hasModifyScope: true }))
      ]);
      setCases(queueRes.cases || []);
      setScopeStatus(scopeRes);
    } catch (err) {
      console.error('[AdminQuarantineQueue] Fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueueData();
  }, []);

  const filteredCases = cases.filter(c => {
    if (filter === 'pending') return c.review?.status === 'PENDING_ADMIN' || c.mailbox?.status === 'CONTAINMENT_REQUESTED';
    if (filter === 'high_risk') return c.detection?.verdict === 'HIGH_RISK';
    if (filter === 'confirmed') return c.review?.status === 'CONFIRMED_THREAT';
    if (filter === 'released') return c.mailbox?.status === 'RELEASED' || c.review?.status === 'RELEASED_BY_ADMIN';
    if (filter === 'failed') return c.mailbox?.status === 'ACTION_FAILED' || c.provider_action?.status === 'FAILED';
    return true;
  });

  const handleOpenRelease = (caseObj) => {
    setSelectedCase(caseObj);
    setDecisionReason('FALSE_POSITIVE');
    setAdminNote('');
    setActionError(null);
    setActionProgress(null);
    setReleaseModalOpen(true);
  };

  const handleOpenConfirm = (caseObj) => {
    setSelectedCase(caseObj);
    setDecisionReason('MALICIOUS_PHISH');
    setAdminNote('');
    setActionError(null);
    setActionProgress(null);
    setConfirmModalOpen(true);
  };

  const handleExecuteRelease = async () => {
    if (!selectedCase) return;
    setActionProgress('REQUESTING');
    setActionError(null);

    try {
      setActionProgress('VERIFYING');
      const res = await api.releaseCase(selectedCase.case_id, decisionReason, adminNote);

      if (res.success && res.case?.mailbox?.status === 'RELEASED') {
        setActionProgress('SUCCESS');
        setTimeout(() => {
          setReleaseModalOpen(false);
          fetchQueueData();
          if (onRefresh) onRefresh();
        }, 1200);
      } else {
        setActionProgress('FAILED');
        setActionError(res.error || 'Provider state verification failed.');
      }
    } catch (err) {
      setActionProgress('FAILED');
      setActionError(err.response?.data?.error || err.message);
    }
  };

  const handleExecuteConfirmThreat = async () => {
    if (!selectedCase) return;
    setActionProgress('REQUESTING');
    setActionError(null);

    try {
      const res = await api.confirmThreat(selectedCase.case_id, decisionReason, adminNote);
      if (res.success) {
        setActionProgress('SUCCESS');
        setTimeout(() => {
          setConfirmModalOpen(false);
          fetchQueueData();
          if (onRefresh) onRefresh();
        }, 1200);
      } else {
        setActionProgress('FAILED');
        setActionError(res.error || 'Threat confirmation failed.');
      }
    } catch (err) {
      setActionProgress('FAILED');
      setActionError(err.response?.data?.error || err.message);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Lock size={18} color="var(--danger)" /> Admin Quarantine & Review Queue
          </h2>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
            Organization-isolated threat containment queue and evidence-backed decision center ({currentOrg?.name || 'My Org'}).
          </div>
        </div>

        <button
          onClick={fetchQueueData}
          disabled={loading}
          style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-muted)', borderRadius: '4px', padding: '6px 12px', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh Queue
        </button>
      </div>

      {/* Scope Authorization Alert Banner */}
      {!scopeStatus.hasModifyScope && scopeStatus.reauthUrl && (
        <div style={{ backgroundColor: 'var(--tint-warning)', border: '1px solid var(--warning)', borderRadius: '6px', padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Key size={18} color="var(--warning)" />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.82rem', color: 'var(--text-primary)' }}>Gmail Modify Permission Required</div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>PhishLens needs permission to contain and restore high-risk messages in your connected Gmail mailbox.</div>
            </div>
          </div>
          <a
            href={scopeStatus.reauthUrl}
            style={{ backgroundColor: 'var(--warning)', color: '#000', textDecoration: 'none', fontWeight: 700, padding: '6px 12px', borderRadius: '4px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            Upgrade Scope <ArrowRight size={13} />
          </a>
        </div>
      )}

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
        {[
          { id: 'pending', label: `Pending Review (${cases.filter(c => c.review?.status === 'PENDING_ADMIN').length})` },
          { id: 'high_risk', label: 'High Risk' },
          { id: 'confirmed', label: 'Confirmed Threat' },
          { id: 'released', label: 'Released' },
          { id: 'failed', label: 'Action Failed' },
          { id: 'all', label: `All (${cases.length})` }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setFilter(tab.id)}
            style={{
              backgroundColor: filter === tab.id ? 'var(--border)' : 'transparent',
              color: filter === tab.id ? 'var(--accent)' : 'var(--text-muted)',
              border: filter === tab.id ? '1px solid var(--accent)' : '1px solid transparent',
              borderRadius: '4px',
              padding: '6px 12px',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Queue Table */}
      <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '6px', border: '1px solid var(--border)', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem', color: 'var(--text-muted)', textAlign: 'left' }}>
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', color: 'var(--text-dim)', textTransform: 'uppercase', fontSize: '0.68rem', fontWeight: 600 }}>
              <th style={{ padding: '10px 14px' }}>Case ID</th>
              <th style={{ padding: '10px 14px' }}>Sender</th>
              <th style={{ padding: '10px 14px' }}>Subject</th>
              <th style={{ padding: '10px 14px' }}>Verdict</th>
              <th style={{ padding: '10px 14px' }}>Mailbox Status</th>
              <th style={{ padding: '10px 14px' }}>Review Status</th>
              <th style={{ padding: '10px 14px' }}>Provider Verification</th>
              <th style={{ padding: '10px 14px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredCases.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-dim)' }}>
                  No cases found in this queue section.
                </td>
              </tr>
            ) : (
              filteredCases.map(c => {
                const isQuarantined = c.mailbox?.status === 'QUARANTINED';
                const isReleased = c.mailbox?.status === 'RELEASED';
                const isConfirmed = c.review?.status === 'CONFIRMED_THREAT';
                const isFailed = c.mailbox?.status === 'ACTION_FAILED';

                return (
                  <tr key={c.case_id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--accent)' }} className="font-mono">{c.case_id}</td>
                    <td style={{ padding: '10px 14px', color: 'var(--text-primary)' }}>{c.message?.sender}</td>
                    <td style={{ padding: '10px 14px', color: 'var(--text-secondary)' }}>{c.message?.subject}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        backgroundColor: c.detection?.verdict === 'HIGH_RISK' ? 'var(--tint-danger)' : 'var(--tint-warning)',
                        color: c.detection?.verdict === 'HIGH_RISK' ? 'var(--danger)' : 'var(--warning)',
                        fontWeight: 700, padding: '2px 6px', borderRadius: '4px', fontSize: '0.65rem'
                      }}>
                        {c.detection?.verdict}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        backgroundColor: isQuarantined ? 'var(--tint-danger)' : isReleased ? 'var(--tint-success)' : isFailed ? 'var(--tint-warning)' : 'var(--tint-neutral)',
                        color: isQuarantined ? 'var(--danger)' : isReleased ? 'var(--success)' : isFailed ? 'var(--warning)' : 'var(--text-muted)',
                        fontWeight: 700, padding: '2px 6px', borderRadius: '4px', fontSize: '0.65rem'
                      }}>
                        {c.mailbox?.status || 'INBOX'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ color: isConfirmed ? 'var(--danger)' : isReleased ? 'var(--success)' : 'var(--warning)', fontWeight: 600 }}>
                        {c.review?.status}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ color: c.provider_action?.status === 'PROVIDER_CONFIRMED' ? 'var(--success)' : 'var(--text-dim)', fontSize: '0.7rem' }}>
                        {c.provider_action?.status || 'NOT_REQUESTED'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '6px', justifyContent: 'flex-end' }}>
                        {!isReleased && (
                          <button
                            onClick={() => handleOpenRelease(c)}
                            style={{ backgroundColor: 'var(--success)', color: '#fff', border: 'none', borderRadius: '4px', padding: '4px 8px', fontSize: '0.68rem', fontWeight: 700, cursor: 'pointer' }}
                          >
                            Release
                          </button>
                        )}
                        {!isConfirmed && (
                          <button
                            onClick={() => handleOpenConfirm(c)}
                            style={{ backgroundColor: 'var(--danger)', color: '#fff', border: 'none', borderRadius: '4px', padding: '4px 8px', fontSize: '0.68rem', fontWeight: 700, cursor: 'pointer' }}
                          >
                            Confirm Threat
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* RELEASE MODAL */}
      {releaseModalOpen && selectedCase && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}>
          <div style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', width: '100%', maxWidth: '480px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle size={18} color="var(--success)" /> Release Quarantined Email
            </h3>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              This will instruct Gmail to remove the quarantine label and restore the email to the recipient's INBOX. Provider state will be verified upon completion.
            </div>

            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Release Decision Reason (Required)</label>
              <select
                value={decisionReason}
                onChange={(e) => setDecisionReason(e.target.value)}
                style={{ width: '100%', backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: '4px', padding: '8px', fontSize: '0.78rem' }}
              >
                <option value="FALSE_POSITIVE">False Positive - Legitimate Sender</option>
                <option value="TRUSTED_SENDER">Trusted Partner / Sender Address</option>
                <option value="BUSINESS_APPROVED">Business Approved Wire / Process</option>
                <option value="OTHER">Other / Custom Reason</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Analyst Notes (Optional)</label>
              <textarea
                value={adminNote}
                onChange={(e) => setAdminNote(e.target.value)}
                placeholder="Enter justification notes for audit log..."
                style={{ width: '100%', height: '60px', backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: '4px', padding: '8px', fontSize: '0.78rem' }}
              />
            </div>

            {actionProgress && (
              <div style={{ fontSize: '0.74rem', fontWeight: 600, color: actionProgress === 'FAILED' ? 'var(--danger)' : 'var(--accent)', backgroundColor: 'var(--bg-panel)', padding: '8px', borderRadius: '4px' }}>
                {actionProgress === 'REQUESTING' && 'Sending release request to Gmail API...'}
                {actionProgress === 'VERIFYING' && 'Verifying Gmail provider read-back state...'}
                {actionProgress === 'SUCCESS' && '✓ Release verified! Message restored to INBOX.'}
                {actionProgress === 'FAILED' && `✕ Action Failed: ${actionError}`}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '10px' }}>
              <button
                onClick={() => setReleaseModalOpen(false)}
                disabled={actionProgress === 'REQUESTING' || actionProgress === 'VERIFYING'}
                style={{ backgroundColor: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '6px 12px', borderRadius: '4px', fontSize: '0.75rem', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteRelease}
                disabled={actionProgress === 'REQUESTING' || actionProgress === 'VERIFYING'}
                style={{ backgroundColor: 'var(--success)', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer' }}
              >
                {actionProgress ? 'Processing...' : 'Confirm & Release'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* CONFIRM THREAT MODAL */}
      {confirmModalOpen && selectedCase && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}>
          <div style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', width: '100%', maxWidth: '480px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} color="var(--danger)" /> Confirm Malicious Threat
            </h3>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              This confirms the email as a malicious threat. The message will remain in verified Gmail quarantine and review status will be updated to CONFIRMED_THREAT.
            </div>

            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '4px' }}>Threat Classification Reason</label>
              <select
                value={decisionReason}
                onChange={(e) => setDecisionReason(e.target.value)}
                style={{ width: '100%', backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: '4px', padding: '8px', fontSize: '0.78rem' }}
              >
                <option value="MALICIOUS_PHISH">Credential Phishing Attack</option>
                <option value="BEC_EXECUTIVE_IMPERSONATION">BEC / Executive Impersonation</option>
                <option value="FINANCIAL_FRAUD">Financial Wire Fraud</option>
                <option value="MALWARE_ATTACHMENT">Malicious Attachment / Payload</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '4px' }}>SOC Notes (Optional)</label>
              <textarea
                value={adminNote}
                onChange={(e) => setAdminNote(e.target.value)}
                placeholder="Enter threat analysis summary for audit log..."
                style={{ width: '100%', height: '60px', backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: '4px', padding: '8px', fontSize: '0.78rem' }}
              />
            </div>

            {actionProgress && (
              <div style={{ fontSize: '0.74rem', fontWeight: 600, color: actionProgress === 'FAILED' ? 'var(--danger)' : 'var(--success)', backgroundColor: 'var(--bg-panel)', padding: '8px', borderRadius: '4px' }}>
                {actionProgress === 'REQUESTING' && 'Updating review status...'}
                {actionProgress === 'SUCCESS' && '✓ Threat confirmed! Case review status updated.'}
                {actionProgress === 'FAILED' && `✕ Action Failed: ${actionError}`}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '10px' }}>
              <button
                onClick={() => setConfirmModalOpen(false)}
                style={{ backgroundColor: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '6px 12px', borderRadius: '4px', fontSize: '0.75rem', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteConfirmThreat}
                style={{ backgroundColor: 'var(--danger)', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer' }}
              >
                {actionProgress ? 'Processing...' : 'Confirm Threat'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
