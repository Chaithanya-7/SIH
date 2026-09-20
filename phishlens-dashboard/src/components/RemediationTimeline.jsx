import React, { useState, useEffect } from 'react';
import { ShieldCheck, Zap, AlertTriangle, RefreshCw, CheckCircle2, RotateCcw, Lock, X, ChevronRight } from 'lucide-react';
import { api } from '../services/api';

export default function RemediationTimeline({ selectedCase, onRefresh }) {
  const [actionsList, setActionsList] = useState([]);
  const [iocList, setIocList] = useState([]);
  const [selectedAction, setSelectedAction] = useState(null);
  const [approvalReason, setApprovalReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('actions');

  const loadRemediationData = async () => {
    try {
      const actRes = await api.getRemediationActions();
      setActionsList(actRes.actions || []);
      const iocRes = await api.getIocResponseList();
      setIocList(iocRes.iocs || []);
    } catch (e) {
      console.error('[RemediationUI] Error loading actions:', e);
    }
  };

  useEffect(() => {
    loadRemediationData();
    const interval = setInterval(loadRemediationData, 4000);
    return () => clearInterval(interval);
  }, []);

  const pendingApprovals = actionsList.filter(a => a.status === 'ACTION_REQUESTED' || a.authorization?.mode === 'REQUIRE_APPROVAL');
  const succeededActions = actionsList.filter(a => a.status === 'ACTION_SUCCEEDED');
  const failedActions = actionsList.filter(a => a.status === 'ACTION_FAILED' || a.status === 'VERIFICATION_FAILED');
  const reversedActions = actionsList.filter(a => a.status === 'REVERSED');

  const handleApprove = async (actionId) => {
    setLoading(true);
    try {
      await api.approveRemediationAction(actionId, 'SOC_ANALYST', approvalReason || 'Analyst approval');
      alert(`Action ${actionId} approved and executed.`);
      setApprovalReason('');
      loadRemediationData();
      if (onRefresh) onRefresh();
    } catch (e) {
      alert('Approval failed: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRollback = async (actionId) => {
    if (!window.confirm(`Are you sure you want to restore the message for Action ${actionId}? This will move the message back to INBOX.`)) return;
    setLoading(true);
    try {
      await api.rollbackRemediationAction(actionId, 'SOC_ANALYST', 'False positive rollback requested');
      alert(`Action ${actionId} rolled back successfully.`);
      loadRemediationData();
      if (onRefresh) onRefresh();
    } catch (e) {
      alert('Rollback failed: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="animate-fade-in" style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Header & Remediation Mode Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '1.05rem', color: 'var(--text-primary)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={18} color="var(--accent)" /> Active Disruption & Real Remediation Center
          </h3>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
            Decision lifecycle, provider verification, authorization policy & persistent rollback controls.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ backgroundColor: 'var(--tint-accent)', color: 'var(--accent)', border: '1px solid var(--tint-accent)', fontSize: '0.7rem', fontWeight: 600, padding: '3px 8px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Lock size={12} /> MODE: SIMULATION / GMAIL
          </span>
          <button
            onClick={loadRemediationData}
            style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', color: 'var(--text-muted)', borderRadius: '4px', padding: '4px 8px', fontSize: '0.72rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
          >
            <RefreshCw size={12} /> Sync
          </button>
        </div>
      </div>

      {/* 2. Compact Response Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Total Actions Today</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>{actionsList.length}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Pending Approval</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--warning)', marginTop: '2px' }}>{pendingApprovals.length}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Successfully Contained</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--success)', marginTop: '2px' }}>{succeededActions.length}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Failed Actions</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--danger)', marginTop: '2px' }}>{failedActions.length}</div>
        </div>
        <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px' }}>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)' }}>Reversed (Restored)</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--violet)', marginTop: '2px' }}>{reversedActions.length}</div>
        </div>
      </div>

      {/* 3. Pending Approvals Section (If any exist) */}
      {pendingApprovals.length > 0 && (
        <div style={{ backgroundColor: 'var(--tint-warning)', borderRadius: '6px', border: '1px solid var(--tint-warning)', padding: '14px' }}>
          <h4 style={{ margin: '0 0 10px 0', fontSize: '0.85rem', color: 'var(--warning)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={15} /> Awaiting Analyst Authorization ({pendingApprovals.length})
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {pendingApprovals.map((act, idx) => (
              <div key={idx} style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '10px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem' }}>
                <div>
                  <div><strong className="font-mono" style={{ color: 'var(--accent)' }}>{act.action_id}</strong> • <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{act.action_type}</span></div>
                  <div style={{ color: 'var(--text-muted)', marginTop: '2px' }}>Case: {act.case_id} | Mailbox: {act.target?.mailbox}</div>
                  <div style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>Reason: {act.reason}</div>
                </div>

                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <input
                    type="text"
                    placeholder="Approval reason..."
                    value={approvalReason}
                    onChange={(e) => setApprovalReason(e.target.value)}
                    style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-primary)', borderRadius: '4px', padding: '4px 8px', fontSize: '0.7rem', outline: 'none', width: '160px' }}
                  />
                  <button
                    onClick={() => handleApprove(act.action_id)}
                    disabled={loading}
                    style={{ backgroundColor: 'var(--success)', color: '#fff', border: 'none', borderRadius: '4px', padding: '5px 10px', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Approve & Execute
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. Sub-Tabs Header */}
      <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
        <button
          onClick={() => setActiveTab('actions')}
          style={{ backgroundColor: activeTab === 'actions' ? 'var(--border)' : 'transparent', color: activeTab === 'actions' ? 'var(--accent)' : 'var(--text-muted)', border: 'none', borderRadius: '4px', padding: '5px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}
        >
          Response Action Log ({actionsList.length})
        </button>
        <button
          onClick={() => setActiveTab('iocs')}
          style={{ backgroundColor: activeTab === 'iocs' ? 'var(--border)' : 'transparent', color: activeTab === 'iocs' ? 'var(--accent)' : 'var(--text-muted)', border: 'none', borderRadius: '4px', padding: '5px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}
        >
          Internal IOC Response List ({iocList.length})
        </button>
      </div>

      {/* 5. Actions Table */}
      {activeTab === 'actions' && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-dim)' }}>
                <th style={{ padding: '8px' }}>Status</th>
                <th style={{ padding: '8px' }}>Action ID</th>
                <th style={{ padding: '8px' }}>Action Type</th>
                <th style={{ padding: '8px' }}>Case ID</th>
                <th style={{ padding: '8px' }}>Target Mailbox</th>
                <th style={{ padding: '8px' }}>Authorization</th>
                <th style={{ padding: '8px' }}>Timestamp</th>
                <th style={{ padding: '8px' }}>Control</th>
              </tr>
            </thead>
            <tbody>
              {actionsList.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    No response actions logged. Ingest a high-risk email to trigger policy evaluation.
                  </td>
                </tr>
              ) : (
                actionsList.slice().reverse().map((act, idx) => {
                  let statusColor = 'var(--text-muted)';
                  if (act.status === 'ACTION_SUCCEEDED') statusColor = 'var(--success)';
                  else if (act.status === 'ACTION_FAILED' || act.status === 'VERIFICATION_FAILED') statusColor = 'var(--danger)';
                  else if (act.status === 'ACTION_REQUESTED') statusColor = 'var(--warning)';
                  else if (act.status === 'REVERSED') statusColor = 'var(--violet)';

                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }} onClick={() => setSelectedAction(act)}>
                      <td style={{ padding: '8px' }}>
                        <span style={{ color: statusColor, fontWeight: 700 }}>{act.status}</span>
                      </td>
                      <td className="font-mono" style={{ padding: '8px', color: 'var(--accent)' }}>{act.action_id}</td>
                      <td style={{ padding: '8px', color: 'var(--text-primary)', fontWeight: 600 }}>{act.action_type}</td>
                      <td className="font-mono" style={{ padding: '8px', color: 'var(--text-muted)' }}>{act.case_id}</td>
                      <td style={{ padding: '8px', color: 'var(--text-muted)' }}>{act.target?.mailbox || 'N/A'}</td>
                      <td style={{ padding: '8px', color: 'var(--text-muted)' }}>{act.authorization?.mode}</td>
                      <td className="font-mono" style={{ padding: '8px', color: 'var(--text-dim)', fontSize: '0.68rem' }}>{new Date(act.requested_at).toLocaleTimeString()}</td>
                      <td style={{ padding: '8px' }}>
                        {act.status === 'ACTION_SUCCEEDED' && act.reversible && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleRollback(act.action_id); }}
                            style={{ backgroundColor: 'var(--tint-accent)', color: 'var(--violet)', border: '1px solid var(--tint-accent)', borderRadius: '4px', padding: '3px 8px', fontSize: '0.68rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
                          >
                            <RotateCcw size={12} /> Rollback
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 6. IOC Response List */}
      {activeTab === 'iocs' && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-dim)' }}>
                <th style={{ padding: '8px' }}>Indicator</th>
                <th style={{ padding: '8px' }}>Type</th>
                <th style={{ padding: '8px' }}>Status</th>
                <th style={{ padding: '8px' }}>Source Case</th>
                <th style={{ padding: '8px' }}>Campaign</th>
                <th style={{ padding: '8px' }}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {iocList.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    No IOC block recommendations logged yet.
                  </td>
                </tr>
              ) : (
                iocList.map((item, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td className="font-mono" style={{ padding: '8px', color: 'var(--text-primary)', fontWeight: 600 }}>{item.ioc}</td>
                    <td style={{ padding: '8px', color: 'var(--accent)' }}>{item.type}</td>
                    <td style={{ padding: '8px', color: 'var(--danger)', fontWeight: 700 }}>{item.status}</td>
                    <td className="font-mono" style={{ padding: '8px', color: 'var(--text-muted)' }}>{item.source_case}</td>
                    <td className="font-mono" style={{ padding: '8px', color: 'var(--violet)' }}>{item.campaign_id || 'N/A'}</td>
                    <td style={{ padding: '8px', color: 'var(--text-muted)' }}>{item.reason}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* 7. Action Details Modal / Drawer */}
      {selectedAction && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', width: '560px', maxWidth: '90%', padding: '20px', position: 'relative' }}>
            <button onClick={() => setSelectedAction(null)} style={{ position: 'absolute', top: '16px', right: '16px', backgroundColor: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
              <X size={18} />
            </button>

            <h3 style={{ margin: '0 0 10px 0', fontSize: '1.1rem', color: 'var(--text-primary)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={20} color="var(--accent)" /> Action Details & Provenance Trace
            </h3>

            <div style={{ backgroundColor: 'var(--bg-panel)', borderRadius: '6px', border: '1px solid var(--border)', padding: '14px', fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
              <div><strong>Action ID:</strong> <span className="font-mono" style={{ color: 'var(--accent)' }}>{selectedAction.action_id}</span></div>
              <div><strong>Status:</strong> <span style={{ color: selectedAction.status === 'ACTION_SUCCEEDED' ? 'var(--success)' : 'var(--danger)', fontWeight: 700 }}>{selectedAction.status}</span></div>
              <div><strong>Action Type:</strong> {selectedAction.action_type}</div>
              <div><strong>Case ID:</strong> <span className="font-mono">{selectedAction.case_id}</span></div>
              <div><strong>Policy Trigger:</strong> {selectedAction.trigger?.policy_id}</div>
              <div><strong>Reason:</strong> {selectedAction.reason}</div>
              <div><strong>Authorization:</strong> {selectedAction.authorization?.mode} (By: {selectedAction.authorization?.authorized_by})</div>
              <div><strong>Provider Result:</strong> {selectedAction.provider_result?.message}</div>
              <div><strong>Target Mailbox:</strong> {selectedAction.target?.mailbox}</div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              {selectedAction.status === 'ACTION_SUCCEEDED' && selectedAction.reversible && (
                <button
                  onClick={() => { handleRollback(selectedAction.action_id); setSelectedAction(null); }}
                  style={{ backgroundColor: 'var(--violet)', color: '#fff', border: 'none', borderRadius: '4px', padding: '6px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}
                >
                  Restore Message (Rollback)
                </button>
              )}
              <button
                onClick={() => setSelectedAction(null)}
                style={{ backgroundColor: 'var(--bg-panel)', color: 'var(--text-muted)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 12px', fontSize: '0.75rem', cursor: 'pointer' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
