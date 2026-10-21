import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { AssessmentProject } from '../types';
import { Crosshair, Plus, ShieldCheck, AlertCircle, Play, CheckCircle2 } from 'lucide-react';

export const AssessmentsPage: React.FC = () => {
  const [projects, setProjects] = useState<AssessmentProject[]>([]);
  const [isCreatingProject, setIsCreatingProject] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  
  // Scope input state
  const [target, setTarget] = useState('scanme.nmap.org');
  const [org, setOrg] = useState('Authorized Lab Partner');
  const [authRef, setAuthRef] = useState('ROE-2026-LAB-01');
  const [approvedBy, setApprovedBy] = useState('Chief Information Security Officer');
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const fetchProjects = async () => {
    try {
      const data = await ApiClient.getAssessmentProjects();
      setProjects(data || []);
    } catch (err) {
      console.error('Failed to load assessment projects', err);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const expires = new Date();
      expires.setDate(expires.getDate() + 30);

      await ApiClient.createAssessmentProject({
        name,
        description,
        target_scopes: [
          {
            target,
            target_type: 'DOMAIN',
            owner_organization: org,
            authorization_reference: authRef,
            approved_by: approvedBy,
            expires_at: expires.toISOString(),
            allowed_methods: ['HTTP_HEADERS', 'TLS_CIPHERS'],
            excluded_targets: [],
            rate_limit_rps: 5,
          },
        ],
      });

      setIsCreatingProject(false);
      setName('');
      setDescription('');
      fetchProjects();
    } catch (err: any) {
      alert(`Error creating project: ${err.message}`);
    }
  };

  const handleRunSafeScan = async (projectId: string, targetDomain: string) => {
    setIsScanning(true);
    setScanMessage(null);
    try {
      const findings = await ApiClient.scanHeaders(projectId, targetDomain);
      setScanMessage(`Scan finished! Identified ${findings.length} findings under OWASP WSTG benchmarks.`);
      fetchProjects();
    } catch (err: any) {
      setScanMessage(`Scope Gate Enforcement: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Crosshair className="w-5 h-5 text-cyan-400" />
            <span>Authorized Security Assessments</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Strict scope authorization gates, non-destructive HTTP/TLS audits, and OWASP WSTG alignment.
          </p>
        </div>

        <button
          onClick={() => setIsCreatingProject(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Assessment Project</span>
        </button>
      </div>

      {scanMessage && (
        <div className="p-3 bg-slate-900 border border-cyan-500/40 rounded-lg text-xs text-cyan-300 flex items-center space-x-2">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{scanMessage}</span>
        </div>
      )}

      {/* Create Project Modal */}
      {isCreatingProject && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleCreateProject} className="bg-graphite-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Create Authorized Assessment Workspace</h2>
            
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Project Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                placeholder="e.g., Internal Production Web Audit Q4"
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Description & Scope Summary</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
                rows={2}
                placeholder="Authorized safe vulnerability assessment conforming to ROE agreement."
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="border-t border-slate-800 pt-3 space-y-3">
              <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold">Mandatory Scope Gate Contract</span>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 text-[11px] mb-1">Authorized Target</label>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                    className="w-full bg-graphite-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 text-[11px] mb-1">Authorization Ref #</label>
                  <input
                    type="text"
                    value={authRef}
                    onChange={(e) => setAuthRef(e.target.value)}
                    required
                    className="w-full bg-graphite-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 text-[11px] mb-1">Target Owner Org</label>
                  <input
                    type="text"
                    value={org}
                    onChange={(e) => setOrg(e.target.value)}
                    required
                    className="w-full bg-graphite-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 text-[11px] mb-1">Approved By</label>
                  <input
                    type="text"
                    value={approvedBy}
                    onChange={(e) => setApprovedBy(e.target.value)}
                    required
                    className="w-full bg-graphite-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-white font-mono"
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsCreatingProject(false)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium"
              >
                Create Workspace
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Projects List */}
      <div className="space-y-4">
        {projects.map((proj) => (
          <div key={proj.id} className="bg-graphite-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-cyan-400 text-xs font-bold">{proj.project_code}</span>
                  <h3 className="text-sm font-semibold text-white">{proj.name}</h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">{proj.description}</p>
              </div>

              <span className="text-xs font-mono text-slate-400">
                Created: {new Date(proj.created_at).toLocaleDateString()}
              </span>
            </div>

            {/* Scopes */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider font-mono">
                Active Authorization Scopes
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {proj.target_scopes?.map((s) => (
                  <div key={s.id} className="p-3 bg-graphite-950 border border-slate-800 rounded-lg text-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-cyan-300">{s.target}</span>
                      <span className="px-1.5 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-800/60 rounded text-[10px] font-mono">
                        AUTHORIZED
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Contract Ref: <strong className="text-slate-200 font-mono">{s.authorization_reference}</strong> ({s.owner_organization})
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Expires: {new Date(s.expires_at).toLocaleDateString()}
                    </div>

                    <div className="pt-2 border-t border-slate-800 flex justify-end">
                      <button
                        onClick={() => handleRunSafeScan(proj.id, s.target)}
                        disabled={isScanning}
                        className="flex items-center space-x-1.5 px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 rounded text-xs font-mono transition-colors disabled:opacity-50"
                      >
                        <Play className="w-3 h-3" />
                        <span>Run Safe HTTP Audit</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Findings preview */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-xs text-slate-400 font-mono">
              <span>Identified Findings: {proj.findings?.length || 0}</span>
              <a href="/vulnerabilities" className="text-cyan-400 hover:underline">
                View in Vulnerability Hub →
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
