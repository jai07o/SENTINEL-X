import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { Host } from '../types';
import { Server, RefreshCw, Radio, HardDrive, Cpu, ShieldCheck } from 'lucide-react';

export const HostInventoryPage: React.FC = () => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchHosts = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getHosts();
      setHosts(data || []);
    } catch (err) {
      console.error('Failed to load hosts', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <span>Managed Endpoint Fleet</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-distribution Linux endpoint inventory (Ubuntu, Debian, Kali, Parrot, Fedora) and agent status.
          </p>
        </div>

        <button
          onClick={fetchHosts}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Fleet</span>
        </button>
      </div>

      {/* Fleet Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {hosts.map((h) => (
          <div key={h.id} className="bg-graphite-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 bg-slate-800/80 rounded-lg text-cyan-400 border border-slate-700">
                  <Server className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono">{h.hostname}</h3>
                  <p className="text-xs text-slate-400 font-mono">{h.ip_address}</p>
                </div>
              </div>

              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  h.status === 'ONLINE'
                    ? 'bg-emerald-950/60 text-emerald-300 border-emerald-700/60'
                    : 'bg-rose-950/60 text-rose-300 border-rose-700/60'
                }`}
              >
                {h.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs border-t border-b border-slate-800 py-3">
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-mono">Distribution</span>
                <div className="text-slate-200 font-medium capitalize mt-0.5">
                  {h.os_distro} {h.os_version}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-mono">Kernel</span>
                <div className="text-slate-200 font-mono text-[11px] mt-0.5 truncate">
                  {h.kernel_version || 'Linux 6.x'}
                </div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-mono">Architecture</span>
                <div className="text-slate-200 font-mono mt-0.5">{h.architecture}</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-mono">Agent Version</span>
                <div className="text-cyan-400 font-mono mt-0.5">v{h.agent_version}</div>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
              <span>Heartbeat:</span>
              <span>{new Date(h.last_heartbeat).toLocaleTimeString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
