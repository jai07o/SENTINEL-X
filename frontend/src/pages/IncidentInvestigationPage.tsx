import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiClient } from '../api/client';
import { Incident, AIInvestigationReport } from '../types';
import { StatusBadge } from '../components/ui/StatusBadge';
import {
  FolderSearch,
  ShieldAlert,
  Sparkles,
  Download,
  CheckCircle,
  Clock,
  User,
  Send,
  Zap,
  Terminal,
  FileCheck2,
} from 'lucide-react';

export const IncidentInvestigationPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const incidentIdParam = searchParams.get('id');

  const [incidentsList, setIncidentsList] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [aiReport, setAiReport] = useState<AIInvestigationReport | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [noteText, setNoteText] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [actionType, setActionType] = useState<string>('ISOLATE_HOST');
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  const fetchIncidentsAndDetail = async () => {
    setIsLoading(true);
    try {
      const listData = await ApiClient.getIncidents({ page_size: 50 });
      const items = listData.items || [];
      setIncidentsList(items);

      const targetId = incidentIdParam || (items.length > 0 ? items[0].id : null);
      if (targetId) {
        const detail = await ApiClient.getIncident(targetId);
        setSelectedIncident(detail);
      }
    } catch (err) {
      console.error('Failed to load incident investigation details', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentsAndDetail();
  }, [incidentIdParam]);

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await ApiClient.updateIncidentStatus(selectedIncident.id, { status: newStatus });
      setSelectedIncident((prev) => (prev ? { ...prev, status: updated.status } : null));
    } catch (err) {
      console.error('Failed to update status', err);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !noteText.trim()) return;
    try {
      await ApiClient.addIncidentNote(selectedIncident.id, noteText);
      setNoteText('');
      // Reload detail
      const refreshed = await ApiClient.getIncident(selectedIncident.id);
      setSelectedIncident(refreshed);
    } catch (err) {
      console.error('Failed to add note', err);
    }
  };

  const handleRequestAction = async () => {
    if (!selectedIncident) return;
    try {
      await ApiClient.requestContainmentAction(selectedIncident.id, actionType, {
        requested_reason: 'Automated policy triggered via investigation workspace',
      });
      const refreshed = await ApiClient.getIncident(selectedIncident.id);
      setSelectedIncident(refreshed);
    } catch (err) {
      console.error('Failed to request containment action', err);
    }
  };

  const handleApproveAction = async (actionId: string) => {
    if (!selectedIncident) return;
    try {
      await ApiClient.approveContainmentAction(selectedIncident.id, actionId);
      const refreshed = await ApiClient.getIncident(selectedIncident.id);
      setSelectedIncident(refreshed);
    } catch (err) {
      console.error('Failed to approve action', err);
    }
  };

  const handleRunAiExplanation = async () => {
    if (!selectedIncident) return;
    setIsAiLoading(true);
    try {
      const rep = await ApiClient.explainIncident(selectedIncident.id, 'security_analyst');
      setAiReport(rep);
    } catch (err) {
      console.error('Failed to run AI explanation', err);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleExportDossier = async () => {
    if (!selectedIncident) return;
    try {
      const exportRes = await ApiClient.exportIncidentDossier(selectedIncident.id);
      setExportMessage(`Dossier exported: ${exportRes.export_filepath || 'Report generated'}`);
      // Trigger browser text file download
      const element = document.createElement('a');
      const file = new Blob([exportRes.content_markdown], { type: 'text/markdown' });
      element.href = URL.createObjectURL(file);
      element.download = `${selectedIncident.incident_number}_Dossier.md`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    } catch (err) {
      console.error('Failed to export dossier', err);
    }
  };

  // Parse notes from string
  const parsedNotes = selectedIncident?.analyst_notes
    ? (() => {
        try {
          return JSON.parse(selectedIncident.analyst_notes);
        } catch {
          return [];
        }
      })()
    : [];

  return (
    <div className="space-y-6">
      {/* Workspace Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 mb-1">
            <FolderSearch className="w-4 h-4" />
            <span>INVESTIGATION WORKSPACE</span>
            <span>/</span>
            <span className="text-white font-bold">{selectedIncident?.incident_number || 'SELECT INCIDENT'}</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">{selectedIncident?.title || 'Incident Investigation'}</h1>
        </div>

        <div className="flex items-center space-x-3">
          {/* Status Selector */}
          {selectedIncident && (
            <select
              value={selectedIncident.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-xs font-medium text-slate-200 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="New">New</option>
              <option value="Triaged">Triaged</option>
              <option value="Investigating">Investigating</option>
              <option value="Contained">Contained</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
          )}

          {/* Export Dossier */}
          <button
            onClick={handleExportDossier}
            disabled={!selectedIncident}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 rounded-md text-xs font-medium transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Dossier</span>
          </button>
        </div>
      </div>

      {exportMessage && (
        <div className="p-3 bg-emerald-950/30 border border-emerald-800/40 rounded-lg text-xs text-emerald-300 flex items-center space-x-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{exportMessage}</span>
        </div>
      )}

      {selectedIncident && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main 2 Cols: Timeline, Correlated Events & Containment */}
          <div className="lg:col-span-2 space-y-6">
            {/* Incident Meta & EWCC Metric */}
            <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-500 uppercase font-mono text-[10px]">Severity</span>
                  <div className="mt-1">
                    <StatusBadge severity={selectedIncident.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono text-[10px]">EWCC Confidence</span>
                  <div className="mt-1 font-mono font-bold text-sm text-cyan-400">
                    {Math.round(selectedIncident.confidence * 100)}%
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono text-[10px]">Affected Asset</span>
                  <div className="mt-1 font-mono text-xs text-slate-300">{selectedIncident.host_id.substring(0, 14)}...</div>
                </div>
                <div>
                  <span className="text-slate-500 uppercase font-mono text-[10px]">Account User</span>
                  <div className="mt-1 font-mono text-xs text-slate-300">{selectedIncident.affected_account || 'N/A'}</div>
                </div>
              </div>
              <p className="mt-4 text-xs text-slate-300 border-t border-slate-800 pt-3">
                {selectedIncident.description}
              </p>
            </div>

            {/* Correlated Evidence Chain & Timeline */}
            <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
              <h2 className="text-sm font-semibold text-white mb-1 flex items-center space-x-2">
                <FileCheck2 className="w-4 h-4 text-cyan-400" />
                <span>Correlated Telemetry & Evidence Chain</span>
              </h2>
              <p className="text-xs text-slate-400 mb-4">
                Exact events linked by deterministic temporal rules and verified with SHA-256 fingerprints.
              </p>

              <div className="space-y-3">
                {selectedIncident.events && selectedIncident.events.length > 0 ? (
                  selectedIncident.events.map((ev, idx) => (
                    <div
                      key={ev.id}
                      className="p-3 bg-graphite-950 border border-slate-800/80 rounded-lg text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2 font-mono">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-semibold text-[11px]">
                            #{idx + 1}
                          </span>
                          <span className="text-slate-200">{ev.event_id}</span>
                          <span className="text-slate-500">({ev.source})</span>
                        </div>
                        <span className="font-mono text-slate-400 text-[11px]">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="flex items-center space-x-4 text-slate-300">
                        <span>Category: <strong className="text-white font-mono">{ev.event_category}</strong></span>
                        {ev.process_name && <span>Process: <code className="text-cyan-300">{ev.process_name}</code></span>}
                        {ev.account_user && <span>User: <code className="text-amber-300">{ev.account_user}</code></span>}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 truncate">
                        Evidence SHA-256: {ev.evidence_hash}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-xs text-slate-500 py-4 text-center">No telemetry items linked yet.</div>
                )}
              </div>
            </div>

            {/* Human-Approved Containment & Response Actions */}
            <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
              <h2 className="text-sm font-semibold text-white mb-1 flex items-center space-x-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Containment & Response Actions</span>
              </h2>
              <p className="text-xs text-slate-400 mb-4">
                Non-autonomous safeguard: response actions require explicit security team authorization.
              </p>

              {/* Action Request Box */}
              <div className="flex items-center space-x-3 bg-graphite-950 p-3 rounded-lg border border-slate-800 mb-4">
                <select
                  value={actionType}
                  onChange={(e) => setActionType(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono focus:outline-none"
                >
                  <option value="ISOLATE_HOST">ISOLATE_HOST (Network Quarantine)</option>
                  <option value="KILL_PROCESS">KILL_PROCESS (Terminate Malicious PID)</option>
                  <option value="DISABLE_ACCOUNT">DISABLE_ACCOUNT (Lock User Auth)</option>
                  <option value="NOTIFY_SOC">NOTIFY_SOC (Priority Escalation)</option>
                </select>
                <button
                  onClick={handleRequestAction}
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-medium transition-colors"
                >
                  Queue Action
                </button>
              </div>

              {/* Action History List */}
              <div className="space-y-2">
                {selectedIncident.response_actions?.map((act) => (
                  <div
                    key={act.id}
                    className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono font-semibold text-slate-200">{act.action_type}</span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                            act.status === 'EXECUTED'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                              : 'bg-amber-950 text-amber-300 border border-amber-800/50'
                          }`}
                        >
                          {act.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        {act.outcome_details || 'Pending human analyst sign-off.'}
                      </div>
                    </div>

                    {act.status === 'PENDING_APPROVAL' && (
                      <button
                        onClick={() => handleApproveAction(act.id)}
                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-medium font-mono"
                      >
                        Approve & Execute
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Col: AI Explanation & Analyst Notes */}
          <div className="space-y-6">
            {/* AI-Assisted Investigation Card */}
            <div className="bg-graphite-900 border border-cyan-500/30 rounded-lg p-5 shadow-sm shadow-cyan-950">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span>Defensive AI Assistant</span>
                </h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40">
                  Grounded
                </span>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Produces structured explanation with cited event IDs and safe diagnostic commands.
              </p>

              {!aiReport ? (
                <button
                  onClick={handleRunAiExplanation}
                  disabled={isAiLoading}
                  className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center justify-center space-x-1.5"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${isAiLoading ? 'animate-spin' : ''}`} />
                  <span>{isAiLoading ? 'Analyzing Telemetry Facts...' : 'Generate Investigation Brief'}</span>
                </button>
              ) : (
                <div className="space-y-4 text-xs">
                  <div className="bg-graphite-950 p-3 rounded border border-slate-800 text-slate-200">
                    <div className="text-[10px] font-mono text-cyan-400 font-semibold mb-1 uppercase">Executive Brief</div>
                    {aiReport.executive_summary}
                  </div>

                  <div>
                    <div className="text-[10px] font-mono text-slate-400 uppercase font-semibold mb-1">
                      Cited Genuine Event IDs
                    </div>
                    <div className="flex flex-wrap gap-1 font-mono text-[11px]">
                      {aiReport.cited_event_ids.map((id) => (
                        <span key={id} className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                          {id}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] font-mono text-slate-400 uppercase font-semibold mb-1.5">
                      Safe Investigative Commands
                    </div>
                    <div className="space-y-2">
                      {aiReport.safe_investigative_steps.map((st) => (
                        <div key={st.step_number} className="bg-graphite-950 p-2.5 rounded border border-slate-800">
                          <div className="font-semibold text-slate-200">{st.action_description}</div>
                          <pre className="mt-1 p-1.5 bg-black rounded text-[11px] font-mono text-cyan-300 overflow-x-auto">
                            {st.tool_or_command}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Analyst Notes */}
            <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
                <User className="w-4 h-4 text-slate-400" />
                <span>Analyst Case Notes</span>
              </h3>

              <div className="space-y-2.5 max-h-48 overflow-y-auto mb-4 pr-1">
                {parsedNotes.length === 0 ? (
                  <div className="text-xs text-slate-500 italic">No notes logged yet.</div>
                ) : (
                  parsedNotes.map((n: any, idx: number) => (
                    <div key={idx} className="bg-graphite-950 p-2.5 rounded border border-slate-800 text-xs">
                      <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono mb-1">
                        <span className="text-cyan-400 font-semibold">{n.author}</span>
                        <span>{new Date(n.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-slate-200">{n.text}</p>
                    </div>
                  ))
                )}
              </div>

              <form onSubmit={handleAddNote} className="flex space-x-2">
                <input
                  type="text"
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  placeholder="Add investigation observation..."
                  className="flex-1 bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium"
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
