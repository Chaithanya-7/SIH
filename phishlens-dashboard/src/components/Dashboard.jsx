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
import AdminQuarantineQueue from './AdminQuarantineQueue';
import IngestionCoverageView from './IngestionCoverageView';
import OperationsOverview from './OperationsOverview';
import CheckAnEmail from './CheckAnEmail';
import ReportsView from './ReportsView';
import IntelligenceStateView from './IntelligenceStateView';
import ThemeToggle from './ThemeToggle';
import { useTheme } from '../hooks/useTheme';
import { User, Building, Mail, Lock, Inbox, Brain, Upload, Radar } from 'lucide-react';

export default function Dashboard() {
  const { theme, toggleTheme } = useTheme();
  const [activeNav, setActiveNav] = useState('overview');
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

  /**
   * Open one message from anywhere in the console.
   *
   * Selecting a case used to set state that only the page you were already on
   * could see, so clicking a message on the overview, or a marker on the map,
   * appeared to do nothing at all. Selecting and navigating together is what
   * makes those clicks lead somewhere.
   */
  const openCase = (caseOrId) => {
    const id = typeof caseOrId === 'string' ? caseOrId : caseOrId?.case_id;
    const match = cases.find(c => c.case_id === id);
    if (match) setSelectedCase(match);
    else if (id) setDeepLinkCaseId(id);
    setActiveNav('investigations');
  };

  // Grouped, and in the words somebody would use for the thing itself.
  //
  // Twelve flat entries, most of them named after the machinery behind them
  // ("Intelligence State", "Mail Coverage"), gave no sense of what the product
  // does or where to start. Two of them - Campaigns and Intelligence Graph -
  // rendered exactly the same component with the same props.
  const navGroups = [
    {
      heading: null,
      items: [{ id: 'overview', label: 'Overview', icon: LayoutDashboard }]
    },
    {
      heading: 'Your mail',
      items: [
        { id: 'upload', label: 'Check an email', icon: Upload },
        { id: 'connections', label: 'Mailboxes', icon: Inbox },
        { id: 'investigations', label: 'All emails', icon: Mail },
        { id: 'coverage', label: 'What is being watched', icon: Radar }
      ]
    },
    {
      heading: 'What was found',
      items: [
        { id: 'campaigns', label: 'Linked attacks', icon: Network },
        { id: 'intelligence', label: 'Threat data', icon: Brain },
        { id: 'executive', label: 'Protected people', icon: UserCheck }
      ]
    },
    {
      heading: 'What was done',
      items: [
        { id: 'quarantine', label: 'Held messages', icon: Lock },
        { id: 'remediation', label: 'Actions taken', icon: Zap },
        { id: 'reports', label: 'Reports', icon: FileText },
        { id: 'audit', label: 'Activity log', icon: History }
      ]
    }
  ];

  const navItems = navGroups.flatMap(group => group.items);
  const activeLabel = navItems.find(item => item.id === activeNav)?.label || 'Overview';

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
          {navGroups.map((group, groupIndex) => (
            <div key={group.heading || 'primary'} style={{ marginBottom: '6px' }}>
              {group.heading && !sidebarCollapsed && (
                <div style={{
                  fontSize: '0.62rem', fontWeight: 700, letterSpacing: '0.07em',
                  textTransform: 'uppercase', color: 'var(--text-dim)',
                  padding: '12px 10px 5px'
                }}>
                  {group.heading}
                </div>
              )}
              {group.heading && sidebarCollapsed && groupIndex > 0 && (
                <div style={{ height: '1px', background: 'var(--border)', margin: '8px 6px' }} />
              )}
              {group.items.map(item => {
                const Icon = item.icon;
                const isActive = activeNav === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveNav(item.id)}
                    title={sidebarCollapsed ? item.label : undefined}
                    style={{
                      width: '100%',
                      backgroundColor: isActive ? 'var(--border)' : 'transparent',
                      color: isActive ? 'var(--accent)' : 'var(--text-muted)',
                      border: 'none',
                      borderRadius: '5px',
                      padding: sidebarCollapsed ? '10px' : '8px 10px',
                      marginBottom: '2px',
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
            </div>
          ))}
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
            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{activeLabel}</span>
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
              <OperationsOverview cases={cases} onOpenCase={openCase} />
            </div>
          )}

          {/* INVESTIGATIONS NAV */}
          {activeNav === 'investigations' && (
            <div className="desktop-grid animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '20px' }}>
              <ThreatFeed cases={cases} selectedCase={selectedCase} onSelectCase={setSelectedCase} />
              <CaseInvestigationView selectedCase={selectedCase} onOpenReport={() => setIsReportModalOpen(true)} />
            </div>
          )}

          {activeNav === 'upload' && (
            <div className="animate-fade-in">
              <CheckAnEmail onOpenCase={openCase} />
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
            <div className="animate-fade-in">
              <ReportsView cases={cases} onOpenCase={openCase} />
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
