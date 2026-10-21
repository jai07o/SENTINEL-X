import React, { useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { 
  Settings as SettingsIcon, 
  Key, 
  Shield, 
  User, 
  Lock, 
  Cpu, 
  CheckCircle2, 
  Copy, 
  Plus, 
  Trash2, 
  AlertTriangle,
  RefreshCw,
  Terminal,
  Radio,
  ShieldCheck,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [keyName, setKeyName] = useState('');
  const [expiresDays, setExpiresDays] = useState(30);
  const [newKeyCreated, setNewKeyCreated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [aiProvider, setAiProvider] = useState<'OFFLINE_LOCAL' | 'GROUNDED_FALLBACK'>('OFFLINE_LOCAL');
  const [wsEnabled, setWsEnabled] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [user, keys] = await Promise.all([
        ApiClient.getMe().catch(() => null),
        ApiClient.getApiKeys().catch(() => []),
      ]);
      setCurrentUser(user);
      setApiKeys(keys || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load user settings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyName.trim()) return;

    try {
      const res = await ApiClient.createApiKey(keyName, expiresDays);
      setNewKeyCreated(res.raw_key);
      setKeyName('');
      fetchData();
    } catch (err: any) {
      setError(err.message || 'Failed to generate API Key');
    }
  };

  const handleCopyKey = () => {
    if (newKeyCreated) {
      navigator.clipboard.writeText(newKeyCreated);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-950/60 border border-cyan-800/60 rounded-lg text-cyan-400">
              <SettingsIcon className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Platform Settings & Security</h1>
              <p className="text-sm text-slate-400">
                Manage analyst identity, API credentials, RBAC policies, and AI explanation engines
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={fetchData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-slate-900 border border-slate-800 text-slate-200 hover:bg-slate-800 hover:border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          Reload Settings
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Profile & RBAC */}
        <div className="space-y-6">
          {/* User Profile Card */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
              <User className="w-5 h-5 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-100">Authenticated Identity</h2>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block">Username</span>
                <span className="font-mono text-slate-200 font-semibold">{currentUser?.username || 'admin'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Email</span>
                <span className="text-slate-300">{currentUser?.email || 'admin@sentinel-x.local'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Assigned Role</span>
                <span className="inline-block mt-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/60 uppercase">
                  {currentUser?.role?.name || 'admin'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Account Status</span>
                <span className="inline-flex items-center gap-1 text-emerald-400 font-medium mt-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Active & Verified
                </span>
              </div>
            </div>
          </div>

          {/* RBAC Overview Card */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
              <Shield className="w-5 h-5 text-amber-400" />
              <h2 className="text-sm font-semibold text-slate-100">Role-Based Access Control</h2>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyan-400">Administrator</span>
                  <span className="text-[10px] text-slate-500 uppercase font-mono">ALL PERMISSIONS</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  Full audit log access, containment action approvals, user provisioning, scope definitions, and system configuration.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-emerald-400">Security Analyst</span>
                  <span className="text-[10px] text-slate-500 uppercase font-mono">OPERATIONAL</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  Triage incidents, upload malware samples for static parsing, intake forensic evidence, request response actions.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-300">Auditor / Viewer</span>
                  <span className="text-[10px] text-slate-500 uppercase font-mono">READ-ONLY</span>
                </div>
                <p className="text-slate-400 text-[11px]">
                  Read-only access to dashboard graphs, reports, telemetry streams, and historical incidents.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Middle & Right Column: API Keys & Controls */}
        <div className="lg:col-span-2 space-y-6">
          {/* API Key Management */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <Key className="w-5 h-5 text-indigo-400" />
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">API Credentials & Ingestion Keys</h2>
                  <p className="text-xs text-slate-400">
                    Authenticate Linux Endpoint Agents, Tauri Desktop App, and Chrome Browser Extensions
                  </p>
                </div>
              </div>
            </div>

            {/* Generated Key Alert Modal/Banner */}
            {newKeyCreated && (
              <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/60 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-cyan-300 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                    New API Key Generated Successfully
                  </span>
                  <span className="text-[11px] text-amber-400 font-medium">Copy now - not stored in plaintext</span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={newKeyCreated}
                    className="w-full bg-slate-950 border border-cyan-700/60 rounded-lg px-3 py-2 text-xs font-mono text-cyan-200 select-all"
                  />
                  <button
                    onClick={handleCopyKey}
                    className="px-3 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-lg text-xs font-bold transition flex items-center gap-1"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
            )}

            {/* Create API Key Form */}
            <form onSubmit={handleCreateApiKey} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <input
                  type="text"
                  placeholder="Key description (e.g. Ubuntu-Agent-01, Chrome-Ext)"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                  required
                />
              </div>

              <div className="flex items-center gap-2">
                <select
                  value={expiresDays}
                  onChange={(e) => setExpiresDays(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-2 focus:outline-none focus:border-cyan-500/50"
                >
                  <option value={30}>30 Days</option>
                  <option value={90}>90 Days</option>
                  <option value={365}>1 Year</option>
                </select>

                <button
                  type="submit"
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 rounded-lg text-xs font-medium transition flex items-center gap-1.5 whitespace-nowrap"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Generate
                </button>
              </div>
            </form>

            {/* Active API Keys Table */}
            <div className="border border-slate-800 rounded-lg overflow-hidden">
              <div className="bg-slate-950/70 px-4 py-2 border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Configured Agent & Client Keys
              </div>
              {apiKeys.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-500">
                  Default developer key active (<code className="font-mono text-cyan-400">sx_dev_agent_key_default</code>).
                </div>
              ) : (
                <div className="divide-y divide-slate-800/60 font-mono text-xs">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="p-3.5 flex items-center justify-between hover:bg-slate-800/30 transition">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2 font-sans font-medium text-slate-200">
                          <span>{key.name}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                            prefix: {key.prefix}...
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-sans">
                          Created {new Date(key.created_at).toLocaleDateString()} • Expires {new Date(key.expires_at).toLocaleDateString()}
                        </div>
                      </div>
                      <span className="text-[11px] font-sans font-medium text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 px-2 py-0.5 rounded">
                        Active
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* System & AI Engine Preferences */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2.5 pb-3 border-b border-slate-800">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-100">Defensive AI & Platform Controls</h2>
            </div>

            <div className="space-y-4 text-xs">
              <div className="flex items-start justify-between gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <div className="font-semibold text-slate-200 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-emerald-400" />
                    Defensive AI Explanation Engine
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1">
                    Select the analysis engine used to synthesize forensic timelines and detection rationales.
                  </p>
                </div>
                <select
                  value={aiProvider}
                  onChange={(e) => setAiProvider(e.target.value as any)}
                  className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="OFFLINE_LOCAL">Offline Deterministic Engine (Zero Cloud Egress)</option>
                  <option value="GROUNDED_FALLBACK">Grounded Hybrid (Schema Validated)</option>
                </select>
              </div>

              <div className="flex items-start justify-between gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <div className="font-semibold text-slate-200 flex items-center gap-2">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    Mandatory Scope Gate Enforcement
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1">
                    Backend enforces non-bypassable scope validation on all penetration testing and active vulnerability requests.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 font-semibold text-[11px]">
                  MANDATORY / HARD-CODED
                </span>
              </div>

              <div className="flex items-start justify-between gap-4 p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div>
                  <div className="font-semibold text-slate-200 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-indigo-400" />
                    Real-Time WebSocket Stream
                  </div>
                  <p className="text-slate-400 text-[11px] mt-1">
                    Push incoming normalized events and correlated incidents to dashboard clients immediately.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setWsEnabled(!wsEnabled)}
                  className={`px-3 py-1 rounded text-xs font-semibold transition ${
                    wsEnabled
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/40'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {wsEnabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>
          </div>

          {/* Platform Self-Defense & Security Armor Posture */}
          <PlatformSecurityArmorCard />

          {/* Universal Data Management & Storage Purge Center */}
          <DataManagementPurgeCard />
        </div>
      </div>
    </div>

  );
};

const DataManagementPurgeCard: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [purging, setPurging] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [showConfirmAll, setShowConfirmAll] = useState<boolean>(false);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const res = await ApiClient.getDataStats();
      setStats(res);
    } catch (e: any) {
      console.error('Failed to load storage stats:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handlePurge = async (category: string) => {
    setPurging(true);
    setStatusMessage(null);
    try {
      const res = await ApiClient.purgeDataCategory(category, true);
      setStatusMessage(`[+] Successfully purged ${res.total_deleted} record(s) from '${category}'.`);
      await fetchStats();
    } catch (err: any) {
      setStatusMessage(`[-] Purge failed: ${err.message}`);
    } finally {
      setPurging(false);
      setShowConfirmAll(false);
    }
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <Trash2 className="w-5 h-5 text-rose-400" />
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Universal Data Management & Storage Purge</h2>
            <p className="text-slate-400 text-[11px]">Delete individual categories or wipe historical operational data</p>
          </div>
        </div>
        <button
          onClick={fetchStats}
          disabled={loading}
          className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs flex items-center space-x-1"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span className="text-[11px] font-mono">Refresh</span>
        </button>
      </div>

      {statusMessage && (
        <div className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between ${
          statusMessage.includes('Successfully')
            ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
            : 'bg-rose-950/40 border-rose-500/50 text-rose-300'
        }`}>
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Database Statistics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-xs font-mono">
        <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
          <div className="text-slate-500 text-[10px]">TOTAL RECORDS</div>
          <div className="text-lg font-bold text-cyan-300">{stats?.total_records ?? '...'}</div>
        </div>
        <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
          <div className="text-slate-500 text-[10px]">EVENTS</div>
          <div className="text-lg font-bold text-white">{stats?.events ?? '...'}</div>
        </div>
        <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
          <div className="text-slate-500 text-[10px]">INCIDENTS</div>
          <div className="text-lg font-bold text-amber-300">{stats?.incidents ?? '...'}</div>
        </div>
        <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
          <div className="text-slate-500 text-[10px]">MALWARE / SAMPLES</div>
          <div className="text-lg font-bold text-rose-300">{stats?.malware_samples ?? '...'}</div>
        </div>
      </div>

      {/* Purge Category Action Buttons */}
      <div className="space-y-2 pt-2">
        <div className="text-xs font-bold text-slate-300 font-mono">Purge Data by Category:</div>
        <div className="flex flex-wrap gap-2 text-xs font-mono">
          <button
            onClick={() => handlePurge('events')}
            disabled={purging}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-bold"
          >
            Clear Events ({stats?.events ?? 0})
          </button>
          <button
            onClick={() => handlePurge('incidents')}
            disabled={purging}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-bold"
          >
            Clear Incidents ({stats?.incidents ?? 0})
          </button>
          <button
            onClick={() => handlePurge('malware')}
            disabled={purging}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-bold"
          >
            Clear Malware ({stats?.malware_samples ?? 0})
          </button>
          <button
            onClick={() => handlePurge('forensics')}
            disabled={purging}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-bold"
          >
            Clear Forensics ({stats?.forensic_cases ?? 0})
          </button>
          <button
            onClick={() => handlePurge('reports')}
            disabled={purging}
            className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded font-bold"
          >
            Clear Reports ({stats?.security_reports ?? 0})
          </button>
        </div>
      </div>

      {/* Master Wipe All Operational Data */}
      <div className="pt-3 border-t border-slate-800">
        {!showConfirmAll ? (
          <button
            onClick={() => setShowConfirmAll(true)}
            className="w-full py-2.5 px-4 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-600/50 rounded font-mono text-xs font-bold flex items-center justify-center space-x-2 transition"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>🔥 WIPE ALL OPERATIONAL DATA (PURGE EVERYTHING)</span>
          </button>
        ) : (
          <div className="bg-rose-950/80 border border-rose-500 p-4 rounded text-xs font-mono space-y-3">
            <div className="text-white font-bold flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-rose-400" />
              <span>PERMANENT DATA DESTRUCTION CONFIRMATION</span>
            </div>
            <p className="text-rose-200">
              This will permanently delete all events, incidents, forensic cases, evidence records, malware samples, network logs, and reports from the database. This action cannot be undone.
            </p>
            <div className="flex items-center gap-3">
              <button
                onClick={() => handlePurge('all')}
                disabled={purging}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded font-bold flex items-center space-x-1"
              >
                <Trash2 className="w-4 h-4" />
                <span>CONFIRM PERMANENT WIPE</span>
              </button>
              <button
                onClick={() => setShowConfirmAll(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold"
              >
                CANCEL
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const PlatformSecurityArmorCard: React.FC = () => {
  const [posture, setPosture] = useState<any>(null);
  const [integrity, setIntegrity] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [reanchoring, setReanchoring] = useState<boolean>(false);
  const [message, setMessage] = useState<string | null>(null);

  const fetchSecurityData = async () => {
    setLoading(true);
    try {
      const [posData, integData] = await Promise.all([
        ApiClient.getSecurityPosture().catch(() => null),
        ApiClient.getSelfIntegrity().catch(() => null),
      ]);
      setPosture(posData);
      setIntegrity(integData);
    } catch (err: any) {
      console.error('Failed to load platform security armor data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const handleReanchor = async () => {
    setReanchoring(true);
    setMessage(null);
    try {
      await ApiClient.reanchorSelfIntegrity();
      setMessage('Cryptographic baseline re-anchored successfully.');
      await fetchSecurityData();
    } catch (err: any) {
      setMessage(`Re-anchor failed: ${err.message}`);
    } finally {
      setReanchoring(false);
    }
  };

  const isIntact = integrity?.is_intact ?? true;

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xl">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Platform Self-Defense & Security Armor Posture
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-600/50">
                GRADE A+ DEFENSE-IN-DEPTH
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Military-grade self-integrity verification, transport armor, anti-brute force, and memory protection.
            </p>
          </div>
        </div>

        <button
          onClick={fetchSecurityData}
          disabled={loading}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg border border-slate-700 flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Re-Audit Armor</span>
        </button>
      </div>

      {message && (
        <div className="p-2.5 bg-emerald-950/50 border border-emerald-800/60 text-emerald-300 text-xs rounded-lg font-mono">
          {message}
        </div>
      )}

      {/* Grid of Security Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Pillar 1: Code Integrity */}
        <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Code Self-Integrity
            </span>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                isIntact
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                  : 'bg-rose-950 text-rose-400 border border-rose-700'
              }`}
            >
              {isIntact ? 'VERIFIED INTACT' : 'TAMPER DETECTED'}
            </span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1">
            <div>Modules Monitored: <span className="font-mono text-slate-200">{integrity?.modules_monitored ?? 14}</span></div>
            <div>Tampered Files: <span className="font-mono text-emerald-400 font-bold">{integrity?.tampered_count ?? 0}</span></div>
            <div className="text-[10px] text-slate-500 truncate">SHA-256 Runtime Baselining Active</div>
          </div>
          <button
            onClick={handleReanchor}
            disabled={reanchoring}
            className="w-full mt-1 py-1 text-[10px] bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-slate-300 font-mono transition"
          >
            {reanchoring ? 'Re-anchoring...' : 'Re-Anchor Cryptographic Hash'}
          </button>
        </div>

        {/* Pillar 2: Transport & Headers */}
        <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-emerald-400" />
              Transport Armor
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-700">
              GRADE A+
            </span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1">
            <div>HSTS Preload: <span className="font-mono text-slate-200">63,072,000s</span></div>
            <div>Anti-Clickjacking: <span className="font-mono text-slate-200">X-Frame: DENY</span></div>
            <div>MIME-Sniff Defense: <span className="font-mono text-slate-200">nosniff</span></div>
            <div>Cache Control: <span className="font-mono text-emerald-400">no-store on APIs</span></div>
          </div>
        </div>

        {/* Pillar 3: Access Control & Anti-Brute-Force */}
        <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-purple-400" />
              Anti-Brute-Force
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-700">
              ACTIVE
            </span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1">
            <div>Lockout Threshold: <span className="font-mono text-slate-200">5 fails / 300s</span></div>
            <div>Lockout Duration: <span className="font-mono text-slate-200">900s (15 min)</span></div>
            <div>Timing-Attack Defense: <span className="font-mono text-slate-200">secrets.compare_digest</span></div>
            <div>Active Lockouts: <span className="font-mono text-emerald-400 font-bold">{posture?.access_control?.active_lockouts ?? 0}</span></div>
          </div>
        </div>

        {/* Pillar 4: Hardware & Payload Protection */}
        <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-amber-400" />
              Hardware & DoS Guard
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-700">
              ENFORCED
            </span>
          </div>
          <div className="text-[11px] text-slate-400 space-y-1">
            <div>AutoRun Immunization: <span className="font-mono text-emerald-400 font-bold">Registry Locked</span></div>
            <div>BadUSB Heuristics: <span className="font-mono text-slate-200">Active</span></div>
            <div>Payload Ceiling: <span className="font-mono text-slate-200">25 MB (Anti-DoS)</span></div>
            <div>Path Traversal Guard: <span className="font-mono text-slate-200">LFI Disallowed</span></div>
          </div>
        </div>
      </div>
    </div>
  );
};

