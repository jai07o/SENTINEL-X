import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { NetworkObservation } from '../types';
import { Network, AlertCircle, RefreshCw, Radio } from 'lucide-react';

export const NetworkMonitoringPage: React.FC = () => {
  const [observations, setObservations] = useState<NetworkObservation[]>([]);
  const [anomaliesSummary, setAnomaliesSummary] = useState<any>(null);
  const [anomalousOnly, setAnomalousOnly] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchNetworkData = async () => {
    setIsLoading(true);
    try {
      const [obsData, summaryData] = await Promise.all([
        ApiClient.getNetworkObservations(anomalousOnly),
        ApiClient.getNetworkAnomalies(),
      ]);
      setObservations(obsData || []);
      setAnomaliesSummary(summaryData);
    } catch (err) {
      console.error('Failed to load network observations', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNetworkData();
  }, [anomalousOnly]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <span>Network Telemetry & Zeek Anomaly Analysis</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingestion of Zeek connection flows, DNS activity, and baseline outbound port anomalies.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <label className="flex items-center space-x-2 text-xs text-slate-300 font-medium cursor-pointer">
            <input
              type="checkbox"
              checked={anomalousOnly}
              onChange={(e) => setAnomalousOnly(e.target.checked)}
              className="rounded bg-graphite-950 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Show Anomalies Only</span>
          </label>

          <button
            onClick={fetchNetworkData}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Anomaly Metrics Overview */}
      {anomaliesSummary && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-graphite-900 border border-slate-800 rounded-lg p-4">
            <span className="text-[10px] text-slate-500 uppercase font-mono">Total Flows Analyzed</span>
            <div className="text-2xl font-bold font-mono text-white mt-1">
              {anomaliesSummary.total_observations}
            </div>
          </div>
          <div className="bg-graphite-900 border border-slate-800 rounded-lg p-4">
            <span className="text-[10px] text-slate-500 uppercase font-mono">Statistical Outliers</span>
            <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
              {anomaliesSummary.anomalous_observations}
            </div>
          </div>
          <div className="bg-graphite-900 border border-slate-800 rounded-lg p-4">
            <span className="text-[10px] text-slate-500 uppercase font-mono">Top Destination Ports</span>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {anomaliesSummary.top_dst_ports?.map((p: any) => (
                <span key={p.port} className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-xs text-cyan-300">
                  :{p.port} ({p.count})
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Network Observation Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto max-h-[calc(100vh-20rem)]">
          <table className="w-full text-left table-dense">
            <thead className="sticky top-0 bg-graphite-950/90 backdrop-blur z-10">
              <tr>
                <th>Timestamp</th>
                <th>Proto</th>
                <th>Source Address</th>
                <th>Destination Address</th>
                <th>Service</th>
                <th>Bytes (Out / In)</th>
                <th>Anomaly Flag</th>
                <th>Anomaly Diagnostic</th>
              </tr>
            </thead>
            <tbody>
              {observations.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-xs text-slate-500">
                    No network observations recorded yet. Ingest Zeek conn.log files to view network flows.
                  </td>
                </tr>
              ) : (
                observations.map((obs) => (
                  <tr key={obs.id} className="hover:bg-slate-800/30">
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(obs.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="font-mono text-xs font-semibold text-cyan-300">{obs.protocol}</td>
                    <td className="font-mono text-xs text-slate-300">
                      {obs.src_ip}:{obs.src_port}
                    </td>
                    <td className="font-mono text-xs text-slate-200">
                      {obs.dst_ip}:{obs.dst_port}
                    </td>
                    <td className="text-xs font-mono text-slate-400">{obs.service || '—'}</td>
                    <td className="font-mono text-xs text-slate-300">
                      {obs.bytes_orig} / {obs.bytes_resp}
                    </td>
                    <td>
                      {obs.is_anomalous ? (
                        <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-rose-950 text-rose-300 border border-rose-800/60">
                          ANOMALOUS
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-xs font-mono text-slate-500 bg-slate-900">
                          BENIGN
                        </span>
                      )}
                    </td>
                    <td className="text-xs text-slate-400 truncate max-w-xs font-mono">
                      {obs.anomaly_reason || 'Nominal traffic'}
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
