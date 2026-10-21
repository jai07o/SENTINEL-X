import React, { useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { Cpu, Layers, ShieldAlert, AlertTriangle, RefreshCw, XCircle, Search, Terminal, Zap } from 'lucide-react';

export const BackgroundProcessesPage: React.FC = () => {
  const [processes, setProcesses] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [backgroundOnly, setBackgroundOnly] = useState<boolean>(true);
  const [suspiciousOnly, setSuspiciousOnly] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchProcesses = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getProcesses(backgroundOnly, 250);
      setProcesses(data.processes || []);
      setSummary(data.summary || {});
    } catch (err) {
      console.error('Failed to load processes:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchProcesses();
    const interval = setInterval(fetchProcesses, 6000);
    return () => clearInterval(interval);
  }, [backgroundOnly]);

  const handleKillProcess = async (pid: number, procName: string) => {
    if (!window.confirm(`Are you sure you want to terminate process '${procName}' (PID: ${pid})?`)) {
      return;
    }
    try {
      const res = await ApiClient.killProcess(pid);
      setActionMessage(res.message);
      fetchProcesses();
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: any) {
      setActionMessage(`Error: ${err.message}`);
    }
  };

  const filteredProcesses = processes.filter((p) => {
    if (suspiciousOnly && p.threat_level === 'SAFE') return false;
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      p.name?.toLowerCase().includes(term) ||
      p.exe?.toLowerCase().includes(term) ||
      String(p.pid).includes(term) ||
      p.username?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">Background Apps & Process Hunter</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time inspection of background workers, daemons, memory usage, masquerading binaries, and cryptominers.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchProcesses}
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
            <span className="text-xs text-slate-400 font-mono">TOTAL PROCESSES</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2 font-mono">{summary?.total_processes || 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Active OS process handles</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">BACKGROUND APPS</span>
            <Terminal className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-2 font-mono">
            {summary?.background_count || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Headless / background workers</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">ANOMALIES / FLAGGED</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2 font-mono">
            {summary?.suspicious_count || 0}
          </div>
          <div className="text-[11px] text-rose-300/80 mt-1">Elevated risk heuristics</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">TOTAL MEMORY (MB)</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-2 font-mono">
            {summary?.total_memory_used_mb || 0} MB
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Physical RAM committed</div>
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
            placeholder="Search process name, executable path, or PID..."
            className="w-full bg-graphite-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setBackgroundOnly(!backgroundOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              backgroundOnly
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-graphite-950 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            Background Only
          </button>
          <button
            onClick={() => setSuspiciousOnly(!suspiciousOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              suspiciousOnly
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-graphite-950 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            Suspicious / Anomalies Only
          </button>
        </div>
      </div>

      {/* Process Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-graphite-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Process Name / PID</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4">Executable Path</th>
                <th className="py-3 px-4">CPU & Memory</th>
                <th className="py-3 px-4">Threat Risk</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredProcesses.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No active processes matched filter.
                  </td>
                </tr>
              ) : (
                filteredProcesses.map((p) => (
                  <tr key={p.pid} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{p.name}</div>
                      <div className="text-[10px] text-slate-500">PID: {p.pid}</div>
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          p.is_background
                            ? 'bg-amber-950/60 text-amber-300 border border-amber-800/60'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {p.is_background ? 'BACKGROUND' : 'FOREGROUND'}
                      </span>
                    </td>

                    <td className="py-3 px-4 max-w-xs truncate text-slate-400 text-[11px]" title={p.exe}>
                      {p.exe || '<System Kernel Worker>'}
                    </td>

                    <td className="py-3 px-4">
                      <div className="text-slate-200">{p.memory_mb} MB</div>
                      <div className="text-[10px] text-slate-500">{p.cpu_percent}% CPU</div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="space-y-0.5">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            p.threat_level === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : p.threat_level === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : p.threat_level === 'SUSPICIOUS'
                              ? 'bg-amber-900/40 text-amber-300'
                              : 'bg-emerald-950/60 text-emerald-400'
                          }`}
                        >
                          {p.threat_level} ({p.risk_score}%)
                        </span>
                        {p.indicators && p.indicators.length > 0 && (
                          <div className="text-[10px] text-rose-300/90 font-sans">
                            {p.indicators[0]}
                          </div>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      {p.pid > 4 ? (
                        <button
                          onClick={() => handleKillProcess(p.pid, p.name)}
                          className="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[11px] font-medium transition"
                        >
                          Terminate
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
