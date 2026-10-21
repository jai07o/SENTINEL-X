import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { DetectionRule } from '../types';
import { StatusBadge } from '../components/ui/StatusBadge';
import { FileCode2, Sparkles, RefreshCw, Zap } from 'lucide-react';

export const DetectionRulesPage: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [ewccTestResult, setEwccTestResult] = useState<any>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  const fetchRules = async () => {
    try {
      const data = await ApiClient.getDetectionRules();
      setRules(data || []);
    } catch (err) {
      console.error('Failed to load detection rules', err);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleRunEWCCBenchmark = async () => {
    setIsEvaluating(true);
    try {
      // Benchmark event corpus
      const sampleEvents = [
        { source: 'auditd', account_uid: 0, account_user: 'root', process_name: 'sudo', evidence_hash: 'a1b2c3d4' },
        { source: 'fim', file_path: '/etc/shadow', evidence_hash: 'e5f6g7h8' },
      ];
      const res = await ApiClient.evaluateEWCC(sampleEvents, 0.85, 60, 'ubuntu');
      setEwccTestResult(res);
    } catch (err) {
      console.error('EWCC evaluation failed', err);
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <FileCode2 className="w-5 h-5 text-cyan-400" />
            <span>Detection Rules & EWCC Research Engine</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            YAML-based sliding correlation rules and Evidence-Weighted Cross-Distribution Correlation (EWCC) benchmarks.
          </p>
        </div>

        <button
          onClick={handleRunEWCCBenchmark}
          disabled={isEvaluating}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Sparkles className={`w-3.5 h-3.5 ${isEvaluating ? 'animate-spin' : ''}`} />
          <span>Test EWCC Evaluation Model</span>
        </button>
      </div>

      {/* EWCC Research Evaluation Card */}
      {ewccTestResult && (
        <div className="bg-graphite-900 border border-cyan-500/40 rounded-lg p-5 shadow-sm shadow-cyan-950 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center space-x-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>Evidence-Weighted Cross-Distribution Correlation (EWCC) Live Evaluation</span>
            </h3>
            <span className="font-mono text-xs text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800/50">
              Model: {ewccTestResult.evaluation_model}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-slate-500 uppercase font-mono text-[10px]">EWCC Calibrated Confidence</span>
              <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                {Math.round(ewccTestResult.ewcc_confidence * 100)}%
              </div>
            </div>
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-slate-500 uppercase font-mono text-[10px]">Rule-Only Baseline</span>
              <div className="text-lg font-bold font-mono text-slate-400 mt-0.5">
                {Math.round(ewccTestResult.rule_baseline_confidence * 100)}%
              </div>
            </div>
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-slate-500 uppercase font-mono text-[10px]">Source Reliability Score</span>
              <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                {Math.round(ewccTestResult.metrics.source_reliability * 100)}%
              </div>
            </div>
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-slate-500 uppercase font-mono text-[10px]">Evidence Completeness</span>
              <div className="text-lg font-bold font-mono text-cyan-400 mt-0.5">
                {Math.round(ewccTestResult.metrics.evidence_completeness * 100)}%
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-2">
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-emerald-400 font-mono text-[11px] font-semibold uppercase block mb-1">
                Observed Telemetry Facts
              </span>
              <ul className="list-disc list-inside space-y-1 text-slate-300">
                {ewccTestResult.observed_facts.map((fact: string, idx: number) => (
                  <li key={idx}>{fact}</li>
                ))}
              </ul>
            </div>
            <div className="bg-graphite-950 p-3 rounded border border-slate-800">
              <span className="text-cyan-400 font-mono text-[11px] font-semibold uppercase block mb-1">
                Inferred Hypotheses & Relationships
              </span>
              <ul className="list-disc list-inside space-y-1 text-slate-300">
                {ewccTestResult.inferred_relationships.map((rel: string, idx: number) => (
                  <li key={idx}>{rel}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Rules Catalog Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left table-dense">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Name & Description</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Sliding Window</th>
                <th>Threshold</th>
                <th>MITRE ATT&CK</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/30">
                  <td className="font-mono text-cyan-400 font-bold text-xs">{r.rule_id}</td>
                  <td>
                    <div className="font-semibold text-slate-200">{r.name}</div>
                    <div className="text-[11px] text-slate-400 truncate max-w-sm">{r.description}</div>
                  </td>
                  <td>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                      {r.event_category}
                    </span>
                  </td>
                  <td>
                    <StatusBadge severity={r.severity} />
                  </td>
                  <td className="font-mono text-xs text-slate-300">{r.window_seconds}s</td>
                  <td className="font-mono text-xs text-slate-300">{r.threshold} events</td>
                  <td className="font-mono text-xs text-cyan-300">
                    {r.mitre_technique_id} ({r.mitre_tactic})
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
