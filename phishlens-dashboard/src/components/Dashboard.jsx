import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Network, UserCheck, Zap, History, FileText, Activity, LayoutDashboard, Menu, ChevronLeft, Search, RefreshCw, AlertTriangle, CheckCircle2, Sliders } from 'lucide-react';
import { api, desktopReady } from '../services/api';

import ThreatFeed from './ThreatFeed';
import CaseInvestigationView from './CaseInvestigationView';
import EvidenceGraphView from './EvidenceGraphView';
import ExecutiveView from './ExecutiveView';
import RemediationTimeline from './RemediationTimeline';
import ResponsePosture from './ResponsePosture';
import MailboxConnections from './MailboxConnections';
import AuditTimeline from './AuditTimeline';
import ForensicReportModal from './ForensicReportModal';
import AuthModal from './AuthModal';
import AdminQuarantineQueue from './AdminQuarantineQueue';
import IngestionCoverageView from './IngestionCoverageView';
import OperationsOverview from './OperationsOverview';
import IntelligenceStateView from './IntelligenceStateView';
import ThemeToggle from './ThemeToggle';
import { useTheme } from '../hooks/useTheme';
import { User, Building, Mail, Lock, Inbox, Brain } from 'lucide-react';

export default function Dashboard() {
  const { theme, toggleTheme } = useTheme();
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

  const [deepLinkCaseId, setDeepLinkCaseId] = useState(null);

  useEffect(() => {
    // In the desktop app the API key arrives asynchronously from the main
    // process, so the first load waits for it rather than firing
    // unauthenticated requests and rendering an empty console.
    let interval;
    let cancelled = false;

    desktopReady.catch(() => false).then(() => {
      if (cancelled) return;
      loadData();
      interval = setInterval(loadData, 4000);
    });

    return () => { cancelled = true; if (interval) clearInterval(interval); };
  }, []);

  // When running inside the installed PhishLens desktop application, a
  // phishlens:// deep link (e.g. the browser extension's "More info" button)
  // arrives here and selects what the analyst asked to see.
  useEffect(() => {
    if (!window.phishlens?.onNavigate) return undefined;
    return window.phishlens.onNavigate(target => {
      if (target?.route === 'case' && target.caseId) {
        setActiveNav('investigations');
        setDeepLinkCaseId(target.caseId);
      } else {
        setActiveNav('overview');
      }
    });
  }, []);

  // The deep link can arrive before the case list has loaded, so resolve it
  // against cases as soon as they are available.
  useEffect(() => {
    if (!deepLinkCaseId) return;
    const match = cases.find(c => c.case_id === deepLinkCaseId);
    if (match) {
      setSelectedCase(match);
      setDeepLinkCaseId(null);
    }
  }, [cases, deepLinkCaseId]);

  const totalThreats = cases.length;
  const highRiskCount = cases.filter(c => c.detection?.verdict === 'HIGH_RISK').length;
  const vipAttacksCount = cases.filter(c => c.executive_context?.is_targeted || c.executive_context?.is_impersonated).length;
  // Counts where the message actually is, not what was decided about it, so a
  // simulated run can never inflate it.
  const quarantinedCount = cases.filter(c => c.mailbox?.status === 'QUARANTINED').length;
  const activeCampaignsCount = Array.from(new Set(cases.map(c => c.campaign?.campaign_id).filter(Boolean))).length;

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'connections', label: 'Mailboxes', icon: Inbox },
    { id: 'investigations', label: 'Investigations', icon: ShieldAlert },
    { id: 'coverage', label: 'Mail Coverage', icon: Inbox },
    { id: 'intelligence', label: 'Intelligence State', icon: Brain },
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
          backgroundColor: 'var(--bg-panel)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          transition: 'width 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
          zIndex: 100,
          flexShrink: 0
        }}
      >
        {/* Header Branding */}
        <div style={{ padding: '16px 14px', display: 'flex', alignItems: 'center', justifyContent: sidebarCollapsed ? 'center' : 'space-between', borderBottom: '1px solid var(--border)' }}>
          {!sidebarCollapsed && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ backgroundColor: 'var(--accent)', width: '28px', height: '28px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Shield size={16} color="var(--text-on-accent)" />
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>PhishLens</div>
                <div style={{ fontSize: '0.62rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Enterprise SOC</div>
              </div>
            </div>
          )}
          {sidebarCollapsed && (
            <div style={{ backgroundColor: 'var(--accent)', width: '28px', height: '28px', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={16} color="var(--text-on-accent)" />
            </div>
          )}

          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            style={{ backgroundColor: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', padding: '4px', display: 'flex', alignItems: 'center' }}
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
                  backgroundColor: isActive ? 'var(--border)' : 'transparent',
                  color: isActive ? 'var(--accent)' : 'var(--text-muted)',
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
                <Icon size={16} color={isActive ? 'var(--accent)' : 'var(--text-muted)'} />
                {!sidebarCollapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Footer: status and appearance */}
        <div style={{ padding: sidebarCollapsed ? '10px 8px' : '12px 14px', borderTop: '1px solid var(--border)', fontSize: '0.68rem', color: 'var(--text-dim)' }}>
          {!sidebarCollapsed && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                <Activity size={12} color={systemHealth.status === 'OPERATIONAL' ? 'var(--success)' : 'var(--warning)'} />
                <span style={{ color: systemHealth.status === 'OPERATIONAL' ? 'var(--success)' : 'var(--warning)', fontWeight: 600 }}>
                  {systemHealth.status === 'OPERATIONAL' ? 'Systems Operational' : `System Degraded (${systemHealth.services?.detection || 'Degraded'})`}
                </span>
              </div>
              <div style={{ marginBottom: '10px' }}>Automated Threat Engine</div>
            </>
          )}
          <ThemeToggle theme={theme} onToggle={toggleTheme} collapsed={sidebarCollapsed} />
        </div>
      </aside>

      {/* 2. Main Content Workspace */}
      <main className="main-content">
        {/* Minimal Top Bar */}
        <header style={{ backgroundColor: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', padding: '10px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--text-dim)' }}>PhishLens</span>
            <span style={{ color: 'var(--border-strong)' }}>/</span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 600, textTransform: 'capitalize' }}>{activeNav}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: systemHealth.status === 'OPERATIONAL' ? 'var(--success)' : 'var(--warning)' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: systemHealth.status === 'OPERATIONAL' ? 'var(--success)' : 'var(--warning)' }}></span>
              <span>{systemHealth.status === 'OPERATIONAL' ? 'Systems Operational' : `System Degraded (${systemHealth.services?.detection || 'Degraded'})`}</span>
            </div>

            <button
              onClick={loadData}
              style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-muted)', borderRadius: '4px', padding: '5px 10px', fontSize: '0.72rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={13} /> Sync
            </button>
          </div>
        </header>

        {/* Workspace Content View */}
        <div style={{ padding: '20px', flex: 1, overflowY: 'auto' }}>
          {/* OVERVIEW NAV */}
          {activeNav === 'overview' && (
            <div className="animate-fade-in">
              <OperationsOverview />
            </div>
          )}

          {/* INVESTIGATIONS NAV */}
          {activeNav === 'investigations' && (
            <div className="desktop-grid animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
              <ThreatFeed cases={cases} selectedCase={selectedCase} onSelectCase={setSelectedCase} />
              <CaseInvestigationView selectedCase={selectedCase} onOpenReport={() => setIsReportModalOpen(true)} />
            </div>
          )}

          {/* MAIL COVERAGE NAV */}
          {activeNav === 'coverage' && (
            <div className="animate-fade-in">
              <IngestionCoverageView />
            </div>
          )}

          {/* INTELLIGENCE STATE NAV */}
          {activeNav === 'intelligence' && (
            <div className="animate-fade-in">
              <IntelligenceStateView />
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

          {activeNav === 'connections' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <MailboxConnections />
            </div>
          )}

          {/* RESPONSE NAV */}
          {activeNav === 'remediation' && (
            <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <ResponsePosture />
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
