import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { Host } from '../types';
import { HeartPulse, CheckCircle2, AlertTriangle, XCircle, RefreshCw } from 'lucide-react';

export const EndpointHealthPage: React.FC = () => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchFleetHealth = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getHosts();
      setHosts(data || []);
    } catch (err) {
      console.error('Failed to load fleet health', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFleetHealth();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <HeartPulse className="w-5 h-5 text-emerald-400" />
            <span>Endpoint Telemetry Collector Health</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time status of individual collectors: auth_log, systemd_journal, FIM, and /proc telemetry.
          </p>
        </div>

        <button
          onClick={fetchFleetHealth}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Collectors</span>
        </button>
      </div>

      {/* Collector Tables per Host */}
      <div className="space-y-6">
        {hosts.map((host) => (
          <div key={host.id} className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
            <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-semibold text-white font-mono">{host.hostname}</h3>
                <span className="text-xs text-slate-400 font-mono">{host.ip_address} — {host.os_distro} {host.os_version}</span>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Last Heartbeat: {new Date(host.last_heartbeat).toLocaleTimeString()}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left table-dense">
                <thead>
                  <tr>
                    <th>Subsystem Collector</th>
                    <th>Status</th>
                    <th>Events Ingested</th>
                    <th>Error Count</th>
                    <th>Last Error Diagnostic</th>
                    <th>Health Pulse</th>
                  </tr>
                </thead>
                <tbody>
                  {(host.collectors && host.collectors.length > 0) ? (
                    host.collectors.map((c) => (
                      <tr key={c.id} className="hover:bg-slate-800/30">
                        <td className="font-mono text-xs text-cyan-300 font-semibold">{c.collector_name}</td>
                        <td>
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
                              c.status === 'HEALTHY'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                                : 'bg-rose-950 text-rose-300 border border-rose-800/50'
                            }`}
                          >
                            {c.status}
                          </span>
                        </td>
                        <td className="font-mono text-xs text-slate-200">{c.events_collected}</td>
                        <td className="font-mono text-xs text-slate-300">{c.errors_count}</td>
                        <td className="text-xs text-slate-400 font-mono truncate max-w-xs">
                          {c.last_error_message || 'None (nominal operational status)'}
                        </td>
                        <td>
                          {c.status === 'HEALTHY' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-rose-400 animate-pulse" />
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="text-center py-4 text-xs text-slate-500">
                        Default collectors active (auth_log, fim, journal). Awaiting detailed heartbeat metrics.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
