import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Network, UserCheck, Zap, History, FileText, Activity, LayoutDashboard, Menu, ChevronLeft, Search, RefreshCw, AlertTriangle, CheckCircle2, Sliders } from 'lucide-react';
import { api } from '../services/api';

import ThreatFeed from './ThreatFeed';
import CaseInvestigationView from './CaseInvestigationView';
import EvidenceGraphView from './EvidenceGraphView';
import ExecutiveView from './ExecutiveView';
import RemediationTimeline from './RemediationTimeline';
import AuditTimeline from './AuditTimeline';
import ForensicReportModal from './ForensicReportModal';
import AuthModal from './AuthModal';
import AdminQuarantineQueue from './AdminQuarantineQueue';
import { User, Building, Mail, Lock } from 'lucide-react';

export default function Dashboard() {
  const [activeNav, setActiveNav] = useState('investigations');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [vips, setVips] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [systemHealth, setSystemHealth] = useState({
    status: 'OPERATIONAL',
    services: { backend: 'READY', detection: 'READY', database: 'READY', ingestion: 'ACTIVE', remediation: 'SIMULATION' }
  });
  const [currentUser, setCurrentUser] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [mailboxConn, setMailboxConn] = useState(null);
  const [showAuthModal, setShowAuthModal] = useState(false);

  const loadData = async () => {
    try {
      try {
        const userRes = await api.getCurrentUser();
        if (userRes && userRes.user) {
          setCurrentUser(userRes.user);
          setCurrentOrg(userRes.organization);
          setMailboxConn(userRes.mailboxConnection);
        }
      } catch (e) {
        // Guest/Dev mode
      }

      try {
        const healthRes = await api.getHealth();
        if (healthRes && healthRes.status) {
          setSystemHealth(healthRes);
        }
      } catch (err) {
        setSystemHealth({ status: 'DEGRADED', services: { backend: 'READY', detection: 'UNAVAILABLE' } });
      }

      const casesRes = await api.getCases();
      const casesList = casesRes.cases || [];
      setCases(casesList);

      setSelectedCase(prev => {
        if (!prev && casesList.length > 0) {
          return casesList[casesList.length - 1] || casesList[0];
        }
        if (prev) {
          const matching = casesList.find(c => c.case_id === prev.case_id);
          return matching || prev;
        }
        return null;
      });

      const graphRes = await api.getGraph();
      setGraphData(graphRes.graph || { nodes: [], edges: [] });

      const vipsRes = await api.getVips();
      setVips(vipsRes.vips || []);

      const auditRes = await api.getAuditLogs();
      setAuditLogs(auditRes.events || []);

    } catch (e) {
      console.error('[PhishLens SOC] Telemetry sync error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const totalThreats = cases.length;
  const highRiskCount = cases.filter(c => c.detection?.verdict === 'HIGH_RISK').length;
  const vipAttacksCount = cases.filter(c => c.executive_context?.is_targeted || c.executive_context?.is_impersonated).length;
  const quarantinedCount = cases.filter(c => c.remediation?.status === 'QUARANTINED').length;
  const activeCampaignsCount = Array.from(new Set(cases.map(c => c.campaign?.campaign_id).filter(Boolean))).length;

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'investigations', label: 'Investigations', icon: ShieldAlert },
    { id: 'quarantine', label: 'Quarantine Queue', icon: Lock },
    { id: 'campaigns', label: 'Campaigns', icon: Network },
    { id: 'graph', label: 'Intelligence Graph', icon: Network },
    { id: 'executive', label: 'Executive Protection', icon: UserCheck },
    { id: 'remediation', label: 'Response', icon: Zap },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'audit', label: 'Audit', icon: History }
  ];

  return (
    <div className="dashboard-container">
      {/* 1. Desktop Persistent Sidebar */}
      <aside
        className="sidebar-responsive"
        style={{
          width: sidebarCollapsed ? '64px' : '230px',
          backgroundColor: '#0d1322',
          borderRight: '1px solid #1e293b',
          display: 'flex',
          flexDirection: 'column',
          transition: 'width 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
          zIndex: 100,
          flexShrink: 0
        }}
      >
        {/* Header Branding */}
        <div style={{ padding: '16px 14px', display: 'flex', alignItems: 'center', justifyContent: sidebarCollapsed ? 'center' : 'space-between', borderBottom: '1px solid #1e293b' }}>
          {!sidebarCollapsed && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ backgroundColor: '#3b82f6', width: '28px', height: '28px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield size={16} color="#ffffff" />
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#f8fafc', letterSpacing: '-0.02em' }}>PhishLens</div>
                <div style={{ fontSize: '0.62rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Enterprise SOC</div>
              </div>
            </div>
          )}
          {sidebarCollapsed && (
            <div style={{ backgroundColor: '#3b82f6', width: '28px', height: '28px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={16} color="#ffffff" />
            </div>
          )}

          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            style={{ backgroundColor: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '4px', display: 'flex', alignItems: 'center' }}
            title="Toggle Sidebar Navigation"
          >
            {sidebarCollapsed ? <Menu size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        {/* Sidebar Items */}
        <nav style={{ padding: '10px 8px', flex: 1, display: 'flex', flexDirection: 'column', gap: '2px' }}>
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveNav(item.id)}
                title={sidebarCollapsed ? item.label : undefined}
                style={{
                  backgroundColor: isActive ? '#1e293b' : 'transparent',
                  color: isActive ? '#3b82f6' : '#94a3b8',
                  border: 'none',
                  borderRadius: '5px',
                  padding: sidebarCollapsed ? '10px' : '8px 10px',
                  fontSize: '0.8rem',
                  fontWeight: isActive ? 600 : 500,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  justifyContent: sidebarCollapsed ? 'center' : 'flex-start',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={16} color={isActive ? '#3b82f6' : '#94a3b8'} />
                {!sidebarCollapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Footer Status */}
        {!sidebarCollapsed && (
          <div style={{ padding: '12px 14px', borderTop: '1px solid #1e293b', fontSize: '0.68rem', color: '#64748b' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
              <Activity size={12} color={systemHealth.status === 'OPERATIONAL' ? '#10b981' : '#f59e0b'} />
              <span style={{ color: systemHealth.status === 'OPERATIONAL' ? '#10b981' : '#f59e0b', fontWeight: 600 }}>
                {systemHealth.status === 'OPERATIONAL' ? 'Systems Operational' : `System Degraded (${systemHealth.services?.detection || 'Degraded'})`}
              </span>
            </div>
            <div>Automated Threat Engine</div>
          </div>
        )}
      </aside>

      {/* 2. Main Content Workspace */}
      <main className="main-content">
        {/* Minimal Top Bar */}
        <header style={{ backgroundColor: '#0d1322', borderBottom: '1px solid #1e293b', padding: '10px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: '#64748b' }}>PhishLens</span>
            <span style={{ color: '#334155' }}>/</span>
            <span style={{ color: '#f8fafc', fontWeight: 600, textTransform: 'capitalize' }}>{activeNav}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: systemHealth.status === 'OPERATIONAL' ? '#10b981' : '#f59e0b' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: systemHealth.status === 'OPERATIONAL' ? '#10b981' : '#f59e0b' }}></span>
              <span>{systemHealth.status === 'OPERATIONAL' ? 'Systems Operational' : `System Degraded (${systemHealth.services?.detection || 'Degraded'})`}</span>
            </div>

            <button
              onClick={loadData}
              style={{ backgroundColor: '#131b2e', border: '1px solid #1e293b', color: '#94a3b8', borderRadius: '4px', padding: '5px 10px', fontSize: '0.72rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={13} /> Sync
            </button>
          </div>
        </header>

        {/* Workspace Content View */}
        <div style={{ padding: '20px', flex: 1, overflowY: 'auto' }}>
          {/* OVERVIEW NAV */}
          {activeNav === 'overview' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc' }}>Security Overview</h2>
                <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '2px' }}>
                  Monitor active threats, campaigns and protected identities.
                </div>
              </div>

              {/* Compact Metrics */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '10px' }}>
                <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Total Cases</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f8fafc', marginTop: '2px' }}>{totalThreats}</div>
                </div>
                <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>High Risk</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ef4444', marginTop: '2px' }}>{highRiskCount}</div>
                </div>
                <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Active Campaigns</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#8b5cf6', marginTop: '2px' }}>{activeCampaignsCount}</div>
                </div>
                <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>VIP Threats</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f59e0b', marginTop: '2px' }}>{vipAttacksCount}</div>
                </div>
                <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', border: '1px solid #1e293b', padding: '12px' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Response Actions</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: '#10b981', marginTop: '2px' }}>{quarantinedCount}</div>
                </div>
              </div>

              {/* Main 2-column view */}
              <div className="desktop-grid" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
                <ThreatFeed cases={cases} selectedCase={selectedCase} onSelectCase={setSelectedCase} />
                <CaseInvestigationView selectedCase={selectedCase} onOpenReport={() => setIsReportModalOpen(true)} />
              </div>
            </div>
          )}

          {/* INVESTIGATIONS NAV */}
          {activeNav === 'investigations' && (
            <div className="desktop-grid animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
              <ThreatFeed cases={cases} selectedCase={selectedCase} onSelectCase={setSelectedCase} />
              <CaseInvestigationView selectedCase={selectedCase} onOpenReport={() => setIsReportModalOpen(true)} />
            </div>
          )}

          {/* CAMPAIGNS NAV */}
          {activeNav === 'campaigns' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <EvidenceGraphView graphData={graphData} currentCaseId={selectedCase?.case_id} />
            </div>
          )}

          {/* GRAPH NAV */}
          {activeNav === 'graph' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <EvidenceGraphView graphData={graphData} currentCaseId={selectedCase?.case_id} />
            </div>
          )}

          {/* EXECUTIVE PROTECTION NAV */}
          {activeNav === 'executive' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <ExecutiveView vips={vips} cases={cases} />
            </div>
          )}

          {/* RESPONSE NAV */}
          {activeNav === 'remediation' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <RemediationTimeline selectedCase={selectedCase} onRefresh={loadData} />
            </div>
          )}

          {/* REPORTS NAV */}
          {activeNav === 'reports' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <CaseInvestigationView selectedCase={selectedCase} onOpenReport={() => setIsReportModalOpen(true)} />
            </div>
          )}

          {/* AUDIT NAV */}
          {activeNav === 'audit' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <AuditTimeline events={auditLogs} />
            </div>
          )}

          {/* QUARANTINE QUEUE NAV */}
          {activeNav === 'quarantine' && (
            <AdminQuarantineQueue currentUser={currentUser} currentOrg={currentOrg} onRefresh={loadData} />
          )}
        </div>
      </main>

      {/* PDF Forensic Export Modal */}
      {isReportModalOpen && (
        <ForensicReportModal selectedCase={selectedCase} onClose={() => setIsReportModalOpen(false)} />
      )}
    </div>
  );
}
