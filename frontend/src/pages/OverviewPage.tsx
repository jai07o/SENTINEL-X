import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiClient } from '../api/client';
import { Incident, Host, NormalizedEvent, SystemHealth } from '../types';
import { StatCard } from '../components/ui/StatCard';
import { StatusBadge } from '../components/ui/StatusBadge';
import {
  AlertTriangle,
  Server,
  Activity,
  Binary,
  ArrowRight,
  ShieldCheck,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [recentEvents, setRecentEvents] = useState<NormalizedEvent[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      const [hData, incData, hostData, evData] = await Promise.all([
        ApiClient.getHealth(),
        ApiClient.getIncidents({ page_size: 6 }),
        ApiClient.getHosts(),
        ApiClient.getEvents({ page_size: 6 }),
      ]);

      setHealth(hData);
      setIncidents(incData.items || []);
      setHosts(hostData || []);
      setRecentEvents(evData.items || []);
      setTotalEvents(evData.total || 0);
    } catch (err) {
      console.error('Failed to load overview data', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Compute severity distribution from loaded incidents
  const severityCounts = {
    CRITICAL: incidents.filter((i) => i.severity === 'CRITICAL').length,
    HIGH: incidents.filter((i) => i.severity === 'HIGH').length,
    MEDIUM: incidents.filter((i) => i.severity === 'MEDIUM').length,
    LOW: incidents.filter((i) => i.severity === 'LOW').length,
  };

  // Identify monitoring gaps (hosts offline or with failed collectors)
  const monitoringGaps = hosts.filter(
    (h) => h.status !== 'ONLINE' || h.collectors?.some((c) => c.status === 'FAILED')
  );

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <span>Security Operations Overview</span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time defensive posture, unified fleet telemetry, and correlated incident response.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={fetchDashboardData}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Active Incidents"
          value={health?.open_incidents ?? incidents.length}
          subtitle="Triaged & under active investigation"
          icon={<AlertTriangle className="w-4 h-4" />}
          variant="rose"
        />
        <StatCard
          title="Monitored Endpoints"
          value={health?.active_hosts ?? hosts.length}
          subtitle={`${hosts.filter((h) => h.status === 'ONLINE').length} healthy fleet agents`}
          icon={<Server className="w-4 h-4" />}
          variant="cyan"
        />
        <StatCard
          title="Normalized Telemetry"
          value={totalEvents}
          subtitle="Events ingested & fingerprinted"
          icon={<Activity className="w-4 h-4" />}
          variant="emerald"
        />
        <StatCard
          title="Detection Engine"
          value="EWCC-v1"
          subtitle="Evidence-weighted correlation active"
          icon={<ShieldCheck className="w-4 h-4" />}
          variant="amber"
        />
      </div>

      {/* Grid: Active Incidents & Fleet Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Incidents Table */}
        <div className="lg:col-span-2 bg-graphite-900 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Priority Threat Incidents</h2>
              <p className="text-xs text-slate-400">Sliding-window correlated alerts requiring analyst action</p>
            </div>
            <Link
              to="/incidents"
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
            >
              <span>View All</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {incidents.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
              No active security incidents detected. Fleet operating normally.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left table-dense">
                <thead>
                  <tr>
                    <th>Ref #</th>
                    <th>Incident</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="font-mono text-cyan-400 text-xs font-semibold">{inc.incident_number}</td>
                      <td className="font-medium text-slate-200">{inc.title}</td>
                      <td>
                        <StatusBadge severity={inc.severity} />
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {Math.round(inc.confidence * 100)}%
                      </td>
                      <td>
                        <StatusBadge status={inc.status} />
                      </td>
                      <td>
                        <Link
                          to={`/investigation?id=${inc.id}`}
                          className="text-xs text-cyan-400 hover:text-cyan-300 underline font-mono"
                        >
                          Investigate
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Severity Distribution & Monitoring Gaps */}
        <div className="space-y-6">
          <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white mb-1">Severity Distribution</h2>
            <p className="text-xs text-slate-400 mb-4">Live breakdown across active incidents</p>

            <div className="space-y-2.5">
              {[
                { label: 'Critical', count: severityCounts.CRITICAL, color: 'bg-rose-500' },
                { label: 'High', count: severityCounts.HIGH, color: 'bg-orange-500' },
                { label: 'Medium', count: severityCounts.MEDIUM, color: 'bg-amber-500' },
                { label: 'Low', count: severityCounts.LOW, color: 'bg-sky-500' },
              ].map((item) => (
                <div key={item.label} className="space-y-1">
                  <div className="flex justify-between text-xs font-medium">
                    <span className="text-slate-300">{item.label}</span>
                    <span className="font-mono text-slate-400">{item.count}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${item.color} rounded-full transition-all duration-300`}
                      style={{
                        width: `${incidents.length > 0 ? (item.count / incidents.length) * 100 : 0}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Monitoring Gaps Card */}
          <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
            <h2 className="text-sm font-semibold text-white mb-1 flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <span>Monitoring Gaps</span>
            </h2>
            <p className="text-xs text-slate-400 mb-3">Collector failures and unmonitored surfaces</p>

            {monitoringGaps.length === 0 ? (
              <div className="text-xs text-emerald-400/90 flex items-center space-x-1.5 bg-emerald-950/30 border border-emerald-800/40 p-2.5 rounded-md">
                <ShieldCheck className="w-4 h-4 shrink-0" />
                <span>All telemetry collectors and host heartbeats reporting healthy.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {monitoringGaps.map((h) => (
                  <div
                    key={h.id}
                    className="p-2.5 bg-amber-950/20 border border-amber-800/30 rounded-md text-xs text-amber-300 flex justify-between items-center"
                  >
                    <span>Host {h.hostname} has degraded telemetry</span>
                    <Link to="/endpoint-health" className="underline font-mono text-[10px]">
                      Check
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Telemetry Stream */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Live Ingested Telemetry Feed</h2>
            <p className="text-xs text-slate-400">Normalized, cryptographically hashed event stream</p>
          </div>
          <Link
            to="/live-events"
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
          >
            <span>Open Stream</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left table-dense">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Category</th>
                <th>Source</th>
                <th>Process / User</th>
                <th>Evidence SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.map((ev) => (
                <tr key={ev.id} className="hover:bg-slate-800/20">
                  <td className="font-mono text-cyan-400 text-xs">{ev.event_id}</td>
                  <td className="font-mono text-xs text-slate-400">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {ev.event_category}
                    </span>
                  </td>
                  <td className="text-xs text-slate-300">{ev.source}</td>
                  <td className="text-xs text-slate-300 font-mono">
                    {ev.process_name || ev.account_user || '—'}
                  </td>
                  <td className="font-mono text-xs text-slate-500">
                    {ev.evidence_hash.substring(0, 16)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
