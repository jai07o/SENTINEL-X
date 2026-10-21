import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiClient } from '../api/client';
import { Incident } from '../types';
import { StatusBadge } from '../components/ui/StatusBadge';
import { AlertTriangle, Filter, RefreshCw, FolderSearch, Clock, Trash2 } from 'lucide-react';

export const IncidentsPage: React.FC = () => {

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getIncidents({ page_size: 50 });
      setIncidents(data.items || []);
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const filteredIncidents = incidents.filter((inc) => {
    if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <span>Security Incident Queue</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Sliding-window correlated alerts mapped to MITRE ATT&CK techniques with human containment gates.
          </p>
        </div>

        <button
          onClick={fetchIncidents}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Queue</span>
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 bg-graphite-900 p-3 rounded-lg border border-slate-800 text-xs">
        <div className="flex items-center space-x-1 text-slate-400 mr-2">
          <Filter className="w-3.5 h-3.5" />
          <span>Lifecycle:</span>
        </div>
        {['ALL', 'New', 'Triaged', 'Investigating', 'Contained', 'Resolved', 'Closed'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-2.5 py-1 rounded font-medium text-xs transition-colors ${
              statusFilter === st
                ? 'bg-cyan-950 border border-cyan-500/50 text-cyan-300'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            {st}
          </button>
        ))}

        <div className="border-l border-slate-800 pl-3 ml-2 flex items-center space-x-1 text-slate-400">
          <span>Severity:</span>
        </div>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-colors ${
              severityFilter === sev
                ? 'bg-cyan-950 border border-cyan-500/50 text-cyan-300 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Incidents Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left table-dense">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Incident Title</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Correlated Events</th>
                <th>Detected At</th>
                <th>Investigation</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-10 text-xs text-slate-500">
                    No incidents matching selected filter.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/25 transition-colors">
                    <td className="font-mono text-xs text-cyan-400 font-semibold">{inc.incident_number}</td>
                    <td className="font-medium text-slate-200 max-w-xs truncate">{inc.title}</td>
                    <td>
                      <StatusBadge severity={inc.severity} />
                    </td>
                    <td>
                      <span className="font-mono text-xs text-slate-300">
                        {Math.round(inc.confidence * 100)}%
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="font-mono text-xs text-slate-300">{inc.event_count || 1} events</td>
                    <td className="font-mono text-xs text-slate-400 flex items-center space-x-1 pt-3">
                      <Clock className="w-3 h-3 text-slate-500 shrink-0" />
                      <span>{new Date(inc.created_at).toLocaleString()}</span>
                    </td>
                    <td>
                      <div className="flex items-center space-x-1.5">
                        <Link
                          to={`/investigation?id=${inc.id}`}
                          className="inline-flex items-center space-x-1 px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 rounded text-xs font-mono transition-colors"
                        >
                          <FolderSearch className="w-3.5 h-3.5" />
                          <span>Open Workspace</span>
                        </Link>
                        <button
                          onClick={async () => {
                            if (window.confirm(`Delete incident ${inc.incident_number}?`)) {
                              await ApiClient.deleteIncident(inc.id);
                              fetchIncidents();
                            }
                          }}
                          className="p-1 bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800/60 text-rose-300 rounded text-xs transition-colors"
                          title="Delete Incident"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
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
