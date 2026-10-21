import React, { useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { Network, ShieldAlert, ShieldCheck, RefreshCw, Radio, Terminal, AlertTriangle, XCircle, Search, ExternalLink } from 'lucide-react';

export const LiveSocketsPage: React.FC = () => {
  const [sockets, setSockets] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [externalOnly, setExternalOnly] = useState<boolean>(false);
  const [highRiskOnly, setHighRiskOnly] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchSockets = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getSockets(externalOnly, highRiskOnly);
      setSockets(data.sockets || []);
      setSummary(data.summary || {});
    } catch (err) {
      console.error('Failed to load socket telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSockets();
    const interval = setInterval(fetchSockets, 5000);
    return () => clearInterval(interval);
  }, [externalOnly, highRiskOnly]);

  const handleKillProcess = async (pid: number, procName: string) => {
    if (!window.confirm(`Are you sure you want to terminate process '${procName}' (PID: ${pid})?`)) {
      return;
    }
    try {
      const res = await ApiClient.killSocketProcess(pid);
      setActionMessage(res.message);
      fetchSockets();
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: any) {
      setActionMessage(`Error: ${err.message}`);
    }
  };

  const filteredSockets = sockets.filter((s) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      s.process_name?.toLowerCase().includes(term) ||
      s.remote_ip?.toLowerCase().includes(term) ||
      String(s.remote_port).includes(term) ||
      String(s.local_port).includes(term) ||
      String(s.pid).includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            <h1 className="text-xl font-bold tracking-tight text-white">Live Socket & C2 Virus Monitor</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time inspection of inbound and outbound network sockets, foreign C2 connections, and rogue listening backdoors.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchSockets}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-graphite-900 border border-slate-800 text-xs text-slate-300 hover:text-white hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-800/80 rounded-lg text-xs text-cyan-200 flex items-center justify-between">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-white">
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">TOTAL SOCKETS</span>
            <Network className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2 font-mono">{summary?.total_sockets || 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Active TCP/UDP sockets</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">ESTABLISHED WAN</span>
            <ExternalLink className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 mt-2 font-mono">
            {summary?.established_connections || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Active remote sessions</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">LISTENING PORTS</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2 font-mono">{summary?.listening_sockets || 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Bound listeners on host</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">C2 / VIRUS ALERTS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400 animate-bounce" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2 font-mono">{summary?.high_risk_c2_sockets || 0}</div>
          <div className="text-[11px] text-rose-300/80 mt-1">Elevated threat sockets</div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-graphite-900 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center space-x-2 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 ml-1" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by IP, Port, Process Name, or PID..."
            className="w-full bg-graphite-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setExternalOnly(!externalOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              externalOnly
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-graphite-950 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            External WAN Only
          </button>
          <button
            onClick={() => setHighRiskOnly(!highRiskOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              highRiskOnly
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-graphite-950 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            C2 / Virus Risks Only
          </button>
        </div>
      </div>

      {/* Sockets Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-graphite-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Process / PID</th>
                <th className="py-3 px-4">Proto & State</th>
                <th className="py-3 px-4">Local Address</th>
                <th className="py-3 px-4">Remote Target (In/Out)</th>
                <th className="py-3 px-4">C2 Threat Assessment</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredSockets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No active sockets matched filter criteria.
                  </td>
                </tr>
              ) : (
                filteredSockets.map((s, idx) => (
                  <tr key={s.socket_id || idx} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <div>
                          <div className="font-semibold text-white">{s.process_name || 'System'}</div>
                          <div className="text-[10px] text-slate-500">PID: {s.pid || 'N/A'}</div>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                          {s.protocol}
                        </span>
                        <span
                          className={`text-[11px] ${
                            s.status === 'ESTABLISHED'
                              ? 'text-cyan-400'
                              : s.status === 'LISTEN'
                              ? 'text-emerald-400'
                              : 'text-slate-400'
                          }`}
                        >
                          {s.status}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-slate-300">
                      {s.local_ip}:{s.local_port}
                    </td>

                    <td className="py-3 px-4">
                      {s.remote_ip ? (
                        <div>
                          <span
                            className={
                              s.is_external ? 'text-amber-300 font-semibold' : 'text-slate-300'
                            }
                          >
                            {s.remote_ip}:{s.remote_port}
                          </span>
                          {s.is_external && (
                            <span className="ml-1.5 px-1 py-0.2 rounded text-[9px] bg-amber-950/80 border border-amber-800 text-amber-300">
                              WAN
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600">None (Listening)</span>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              s.threat_level === 'CRITICAL'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : s.threat_level === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                : s.threat_level === 'SUSPICIOUS'
                                ? 'bg-amber-900/40 text-amber-300'
                                : 'bg-emerald-950/60 text-emerald-400'
                            }`}
                          >
                            {s.threat_level} ({s.risk_score}%)
                          </span>
                        </div>
                        {s.threat_reasons && s.threat_reasons.length > 0 && (
                          <div className="text-[10px] text-rose-300/90 font-sans">
                            {s.threat_reasons[0]}
                          </div>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      {s.pid && s.pid > 4 ? (
                        <button
                          onClick={() => handleKillProcess(s.pid, s.process_name)}
                          className="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[11px] font-medium transition"
                        >
                          Kill Process
                        </button>
                      ) : (
                        <span className="text-[10px] text-slate-600">Protected</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
