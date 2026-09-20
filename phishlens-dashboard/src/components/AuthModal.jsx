import React, { useState } from 'react';
import { Shield, User, Building, Mail, CheckCircle2, AlertCircle, RefreshCw, Key, LogOut } from 'lucide-react';
import { api } from '../services/api';

export default function AuthModal({ currentUser, currentOrg, mailboxConn, onAuthSuccess, onClose }) {
  const [mode, setMode] = useState(!currentUser ? 'login' : (!currentOrg ? 'org' : 'mailbox'));
  const [emailInput, setEmailInput] = useState(currentUser?.email || '');
  const [nameInput, setNameInput] = useState(currentUser?.name || '');
  const [orgName, setOrgName] = useState('');
  const [orgDomain, setOrgDomain] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const handleGoogleSignIn = async (e) => {
    e.preventDefault();
    if (!emailInput || !emailInput.includes('@')) {
      setError('Please enter a valid email address.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const res = await api.verifyGoogleAuth({
        email: emailInput.trim(),
        name: nameInput.trim() || emailInput.split('@')[0],
        googleAccountId: `g_mock_${Date.now()}`
      });

      if (res.success) {
        setMessage('Development demo identity enabled. Configure Google ID-token verification before production use.');
        if (!res.user.organization_id) {
          setMode('org');
        } else {
          setMode('mailbox');
        }
        onAuthSuccess();
      } else {
        setError(res.error || 'Authentication failed.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateOrg = async (e) => {
    e.preventDefault();
    if (!orgName.trim()) {
      setError('Organization name is required.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await api.createOrganization(orgName.trim(), orgDomain.trim());
      if (res.success) {
        setMessage(`Organization '${res.organization.name}' created cleanly. Role assigned: ADMIN.`);
        setMode('mailbox');
        onAuthSuccess();
      } else {
        setError(res.error || 'Failed to create organization.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleJoinOrg = async (e) => {
    e.preventDefault();
    if (!inviteCode.trim()) {
      setError('Admin invite code is required to join an organization.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await api.joinOrganization(inviteCode.trim());
      if (res.success) {
        setMessage(`Joined ${res.organization.name} cleanly. Role assigned: EMPLOYEE.`);
        setMode('mailbox');
        onAuthSuccess();
      } else {
        setError(res.error || 'Failed to join organization.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleConnectGmail = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getGmailAuthUrl();
      if (res.url) {
        window.open(res.url, '_blank');
        setMessage('Gmail OAuth authorization window opened.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSyncMailbox = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.syncMailbox();
      if (res.success) {
        setMessage(`Mailbox synced cleanly. Discovered: ${res.result.discovered}, Processed: ${res.result.processed}`);
        onAuthSuccess();
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnectMailbox = async () => {
    setLoading(true);
    try {
      await api.disconnectMailbox();
      setMessage('Gmail mailbox disconnected.');
      onAuthSuccess();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(11, 15, 25, 0.85)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div style={{
        backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px',
        width: '440px', padding: '24px', color: 'var(--text-primary)', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid var(--border)', pb: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={20} color="var(--accent)" />
            <span style={{ fontWeight: 700, fontSize: '1rem' }}>PhishLens Account & Identity</span>
          </div>
          {onClose && (
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '1.2rem' }}>×</button>
          )}
        </div>

        {error && (
          <div style={{ backgroundColor: 'var(--tint-danger)', border: '1px solid var(--danger)', borderRadius: '4px', padding: '10px', fontSize: '0.75rem', color: 'var(--danger)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div style={{ backgroundColor: 'var(--tint-success)', border: '1px solid var(--success)', borderRadius: '4px', padding: '10px', fontSize: '0.75rem', color: 'var(--success)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={14} />
            <span>{message}</span>
          </div>
        )}

        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: '4px', backgroundColor: 'var(--bg-surface)', padding: '4px', borderRadius: '6px', marginBottom: '18px' }}>
          <button onClick={() => setMode('login')} style={{ flex: 1, padding: '6px', fontSize: '0.75rem', borderRadius: '4px', border: 'none', backgroundColor: mode === 'login' ? 'var(--border)' : 'transparent', color: mode === 'login' ? 'var(--text-primary)' : 'var(--text-dim)', cursor: 'pointer' }}>Demo Identity</button>
          <button onClick={() => setMode('org')} style={{ flex: 1, padding: '6px', fontSize: '0.75rem', borderRadius: '4px', border: 'none', backgroundColor: mode === 'org' ? 'var(--border)' : 'transparent', color: mode === 'org' ? 'var(--text-primary)' : 'var(--text-dim)', cursor: 'pointer' }}>Organization</button>
          <button onClick={() => setMode('mailbox')} style={{ flex: 1, padding: '6px', fontSize: '0.75rem', borderRadius: '4px', border: 'none', backgroundColor: mode === 'mailbox' ? 'var(--border)' : 'transparent', color: mode === 'mailbox' ? 'var(--text-primary)' : 'var(--text-dim)', cursor: 'pointer' }}>Gmail Connection</button>
        </div>

        {/* 1. Google Auth Mode */}
        {mode === 'login' && (
          <form onSubmit={handleGoogleSignIn} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Google Account Email</label>
              <input
                type="email"
                value={emailInput}
                onChange={e => setEmailInput(e.target.value)}
                placeholder="user@company.com"
                style={{ width: '100%', backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '8px 10px', color: 'var(--text-primary)', fontSize: '0.8rem' }}
                required
              />
            </div>
            <div>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Display Name</label>
              <input
                type="text"
                value={nameInput}
                onChange={e => setNameInput(e.target.value)}
                placeholder="User Name"
                style={{ width: '100%', backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '8px 10px', color: 'var(--text-primary)', fontSize: '0.8rem' }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                backgroundColor: 'var(--accent)', color: 'var(--text-on-accent)', border: 'none', borderRadius: '4px',
                padding: '10px', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer', display: 'flex',
                alignItems: 'center', justifyContent: 'center', gap: '8px', marginTop: '6px'
              }}
            >
              <User size={16} /> {loading ? 'Verifying...' : 'Continue with Google Account'}
            </button>
          </form>
        )}

        {/* 2. Organization Mode */}
        {mode === 'org' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Create Org */}
            <form onSubmit={handleCreateOrg} style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Building size={14} color="var(--accent)" /> Create Organization (Becomes ADMIN)
              </div>
              <input
                type="text"
                value={orgName}
                onChange={e => setOrgName(e.target.value)}
                placeholder="Organization Name (e.g. Acme Corp)"
                style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 8px', color: 'var(--text-primary)', fontSize: '0.75rem' }}
              />
              <input
                type="text"
                value={orgDomain}
                onChange={e => setOrgDomain(e.target.value)}
                placeholder="Approved Email Domain (e.g. acme.com)"
                style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 8px', color: 'var(--text-primary)', fontSize: '0.75rem' }}
              />
              <button type="submit" style={{ backgroundColor: 'var(--accent)', color: '#fff', border: 'none', borderRadius: '4px', padding: '6px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>Create & Become ADMIN</button>
            </form>

            {/* Join Org */}
            <form onSubmit={handleJoinOrg} style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Key size={14} color="var(--success)" /> Join Organization with Admin Invite Code
              </div>
              <input
                type="text"
                value={inviteCode}
                onChange={e => setInviteCode(e.target.value)}
                placeholder="Invite Code (e.g. INV-2026-XXXXXX)"
                style={{ backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 8px', color: 'var(--text-primary)', fontSize: '0.75rem' }}
              />
              <button type="submit" style={{ backgroundColor: 'var(--success)', color: '#fff', border: 'none', borderRadius: '4px', padding: '6px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>Join as EMPLOYEE</button>
            </form>
          </div>
        )}

        {/* 3. Gmail Mailbox Connection Mode */}
        {mode === 'mailbox' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '8px' }}>Mailbox Authorization State:</div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Mail size={18} color={mailboxConn?.status === 'CONNECTED' ? 'var(--success)' : 'var(--warning)'} />
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {mailboxConn?.provider_account || 'No Mailbox Connected'}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: mailboxConn?.status === 'CONNECTED' ? 'var(--success)' : 'var(--warning)' }}>
                      Status: {mailboxConn?.status || 'DISCONNECTED'}
                    </div>
                  </div>
                </div>

                {mailboxConn?.status === 'CONNECTED' ? (
                  <button onClick={handleDisconnectMailbox} style={{ backgroundColor: 'var(--tint-danger)', border: '1px solid var(--danger)', color: 'var(--danger)', borderRadius: '4px', padding: '4px 8px', fontSize: '0.72rem', cursor: 'pointer' }}>Disconnect</button>
                ) : (
                  <button onClick={handleConnectGmail} style={{ backgroundColor: 'var(--accent)', color: '#fff', border: 'none', borderRadius: '4px', padding: '6px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>Connect Gmail</button>
                )}
              </div>
            </div>

            {mailboxConn?.status === 'CONNECTED' && (
              <button
                onClick={handleSyncMailbox}
                disabled={loading}
                style={{
                  backgroundColor: 'var(--success)', color: '#fff', border: 'none', borderRadius: '4px',
                  padding: '8px', fontSize: '0.78rem', fontWeight: 600, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px'
                }}
              >
                <RefreshCw size={14} /> {loading ? 'Syncing...' : 'Sync Gmail Messages Now'}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
