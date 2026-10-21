import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { ForensicCase } from '../types';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Archive, Plus, Clock, FileCheck2, RefreshCw } from 'lucide-react';

export const ForensicCasesPage: React.FC = () => {
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('MEDIUM');
  const [isLoading, setIsLoading] = useState(true);

  const fetchCases = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getForensicCases();
      setCases(data || []);
    } catch (err) {
      console.error('Failed to load forensic cases', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await ApiClient.createForensicCase({ title, description, priority });
      setIsCreating(false);
      setTitle('');
      setDescription('');
      fetchCases();
    } catch (err: any) {
      alert(`Error creating case: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Archive className="w-5 h-5 text-cyan-400" />
            <span>Digital Forensics Cases & Chain of Custody</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Preserve immutable evidence hashes, record every analytical transformation, and track forensic timelines.
          </p>
        </div>

        <button
          onClick={() => setIsCreating(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Forensic Case</span>
        </button>
      </div>

      {/* Create Case Modal */}
      {isCreating && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleCreateCase} className="bg-graphite-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Create Forensic Case</h2>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Case Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
                placeholder="e.g., Host Infiltration Investigation - Srv01"
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Initial Case Synopsis</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
                rows={3}
                placeholder="Details regarding incident scope, affected hosts, and acquisition objectives."
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsCreating(false)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium"
              >
                Initialize Case
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Cases List */}
      <div className="space-y-4">
        {cases.length === 0 ? (
          <div className="p-8 bg-graphite-900 border border-dashed border-slate-800 rounded-lg text-center text-xs text-slate-500">
            No active forensic cases. Initialize a new case to intake memory, disk, or network evidence.
          </div>
        ) : (
          cases.map((c) => (
            <div key={c.id} className="bg-graphite-900 border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-cyan-400 font-bold text-xs">{c.case_number}</span>
                  <h3 className="text-sm font-semibold text-white">{c.title}</h3>
                </div>
                <div className="flex items-center space-x-2">
                  <StatusBadge severity={c.priority} />
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                    {c.status}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-300">{c.description}</p>

              {/* Case timeline preview */}
              {c.timeline_items && c.timeline_items.length > 0 && (
                <div className="bg-graphite-950 p-3 rounded border border-slate-800 space-y-2">
                  <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold">
                    Chronological Timeline ({c.timeline_items.length} items)
                  </span>
                  <div className="space-y-1.5">
                    {c.timeline_items.slice(0, 3).map((t) => (
                      <div key={t.id} className="flex items-center justify-between text-xs">
                        <span className="text-slate-200 font-medium">{t.title}</span>
                        <span className="text-[11px] font-mono text-slate-500">
                          {new Date(t.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs text-slate-400 font-mono">
                <span>Preserved Evidence Items: {c.evidence_items?.length || 0}</span>
                <a href="/evidence" className="text-cyan-400 hover:underline">
                  Open Evidence Vault →
                </a>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
