import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { NormalizedEvent } from '../types';
import { useWebSocket } from '../context/WebSocketContext';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Radio, Play, Pause, RefreshCw, Eye, X, Filter, Trash2 } from 'lucide-react';

export const LiveEventStreamPage: React.FC = () => {

  const { isConnected, alerts } = useWebSocket();
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchEvents = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getEvents({ page_size: 100 });
      setEvents(data.items || []);
    } catch (err) {
      console.error('Failed to load events', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  // When live alerts come in over WebSocket and stream is not paused, prepend
  useEffect(() => {
    if (!isPaused && alerts.length > 0) {
      const latest = alerts[0];
      if (latest.type === 'NEW_EVENT') {
        fetchEvents();
      }
    }
  }, [alerts, isPaused]);

  const filteredEvents = events.filter((ev) => {
    if (categoryFilter === 'ALL') return true;
    return ev.event_category === categoryFilter;
  });

  return (
    <div className="space-y-6">
      {/* Header & Stream Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <span>Live Normalized Telemetry Stream</span>
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isConnected ? (isPaused ? 'bg-amber-400' : 'bg-emerald-400 animate-pulse') : 'bg-slate-600'
              }`}
            />
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time feed of multi-distribution syslog, journald, auditd, and FIM security events.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
              isPaused
                ? 'bg-amber-950/40 text-amber-300 border-amber-700/60 hover:bg-amber-900/50'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>

          {/* Purge Events */}
          <button
            onClick={async () => {
              if (window.confirm('Purge and clear all telemetry events?')) {
                await ApiClient.purgeEvents();
                fetchEvents();
              }
            }}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-rose-950/40 text-rose-300 border border-rose-800/60 hover:bg-rose-900/50 transition-colors"
            title="Clear all events"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge Events</span>
          </button>

          {/* Refresh */}
          <button
            onClick={fetchEvents}
            disabled={isLoading}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md border border-slate-700 transition-colors"
            title="Reload Events"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>


      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 flex items-center space-x-1 mr-2 shrink-0">
          <Filter className="w-3.5 h-3.5" />
          <span>Category:</span>
        </span>
        {[
          'ALL',
          'AUTH_FAILURE',
          'AUTH_SUCCESS',
          'PRIVILEGE_ESCALATION',
          'FILE_MODIFICATION',
          'NETWORK_OUTBOUND_UNUSUAL',
        ].map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-2.5 py-1 rounded font-mono text-xs transition-colors shrink-0 ${
              categoryFilter === cat
                ? 'bg-cyan-950 border border-cyan-500/50 text-cyan-300 font-semibold'
                : 'bg-graphite-900 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Events Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto max-h-[calc(100vh-18rem)]">
          <table className="w-full text-left table-dense">
            <thead className="sticky top-0 bg-graphite-950/90 backdrop-blur z-10">
              <tr>
                <th>Event ID</th>
                <th>Timestamp (UTC)</th>
                <th>Source</th>
                <th>Category</th>
                <th>Severity</th>
                <th>User / Process</th>
                <th>Target IP / Port</th>
                <th>Evidence SHA-256</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-8 text-xs text-slate-500">
                    No telemetry events matching current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="font-mono text-cyan-400 text-xs font-medium">{ev.event_id}</td>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="text-xs text-slate-300 font-mono">{ev.source}</td>
                    <td>
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800/80 text-slate-200 border border-slate-700/60">
                        {ev.event_category}
                      </span>
                    </td>
                    <td>
                      <StatusBadge severity={ev.severity} />
                    </td>
                    <td className="text-xs text-slate-300 font-mono">
                      {ev.account_user || ev.process_name || '—'}
                    </td>
                    <td className="text-xs text-slate-400 font-mono">
                      {ev.src_ip ? `${ev.src_ip}:${ev.src_port || '*'}` : '—'}
                    </td>
                    <td className="font-mono text-xs text-slate-500">
                      {ev.evidence_hash.substring(0, 14)}...
                    </td>
                    <td>
                      <div className="flex items-center space-x-1">
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-cyan-400 transition-colors"
                          title="Inspect Raw Payload"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={async () => {
                            if (window.confirm(`Delete event ${ev.event_id}?`)) {
                              await ApiClient.deleteEvent(ev.id || ev.event_id);
                              fetchEvents();
                            }
                          }}
                          className="p-1 hover:bg-rose-950/60 rounded text-slate-400 hover:text-rose-400 transition-colors"
                          title="Delete Event"
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

      {/* Raw Payload Inspection Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-graphite-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[85vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
                  <span>Event Payload Inspection</span>
                  <span className="font-mono text-cyan-400 text-xs">({selectedEvent.event_id})</span>
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Fingerprint: {selectedEvent.evidence_hash}
                </p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-4">
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-graphite-950 p-2.5 rounded border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase font-mono">Timestamp</div>
                  <div className="text-slate-200 font-mono mt-0.5">{selectedEvent.timestamp}</div>
                </div>
                <div className="bg-graphite-950 p-2.5 rounded border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase font-mono">Source Subsystem</div>
                  <div className="text-slate-200 font-mono mt-0.5">{selectedEvent.source}</div>
                </div>
                <div className="bg-graphite-950 p-2.5 rounded border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase font-mono">Category & Severity</div>
                  <div className="text-slate-200 font-mono mt-0.5">{selectedEvent.event_category} ({selectedEvent.severity})</div>
                </div>
                <div className="bg-graphite-950 p-2.5 rounded border border-slate-800">
                  <div className="text-slate-500 text-[10px] uppercase font-mono">Process / User</div>
                  <div className="text-slate-200 font-mono mt-0.5">{selectedEvent.process_name || selectedEvent.account_user || 'None'}</div>
                </div>
              </div>

              <div>
                <div className="text-xs font-semibold text-slate-300 mb-1.5">Raw Telemetry JSON</div>
                <pre className="p-3 bg-graphite-950 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(selectedEvent.raw_payload), null, 2);
                    } catch {
                      return selectedEvent.raw_payload;
                    }
                  })()}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
