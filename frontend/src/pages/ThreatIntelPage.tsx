import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { Flame, ExternalLink, ShieldCheck, Database, RefreshCw } from 'lucide-react';

export const ThreatIntelPage: React.FC = () => {
  const [rules, setRules] = useState<any[]>([]);
  const [samples, setSamples] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchIntel = async () => {
    setIsLoading(true);
    try {
      const [rData, sData] = await Promise.all([
        ApiClient.getDetectionRules(),
        ApiClient.getMalwareSamples(),
      ]);
      setRules(rData || []);
      setSamples(sData || []);
    } catch (err) {
      console.error('Failed to load intel', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIntel();
  }, []);

  // Aggregate IOCs from malware samples
  const extractedIocs: { type: string; value: string; sample: string }[] = [];
  samples.forEach((s) => {
    if (s.static_analysis?.iocs_json) {
      try {
        const ioc = JSON.parse(s.static_analysis.iocs_json);
        ioc.ips?.forEach((ip: string) => extractedIocs.push({ type: 'IPv4', value: ip, sample: s.filename }));
        ioc.urls?.forEach((url: string) => extractedIocs.push({ type: 'URL', value: url, sample: s.filename }));
      } catch {}
    }
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Flame className="w-5 h-5 text-amber-400" />
            <span>Threat Intelligence & MITRE ATT&CK Mapping</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Verified adversarial tactics, techniques, procedures (TTPs), and empirical Indicators of Compromise (IOCs).
          </p>
        </div>

        <button
          onClick={fetchIntel}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md text-xs font-medium border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Intel</span>
        </button>
      </div>

      {/* MITRE ATT&CK Matrix Grid */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
        <h2 className="text-sm font-semibold text-white mb-1">Active MITRE ATT&CK Coverage</h2>
        <p className="text-xs text-slate-400 mb-4">Tactics and verified technique mappings codified in SENTINEL-X rules</p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {rules.map((r) => (
            <div key={r.id} className="p-4 bg-graphite-950 border border-slate-800 rounded-lg space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-cyan-400 font-bold">{r.mitre_technique_id || 'T1000'}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  {r.mitre_tactic || 'General'}
                </span>
              </div>
              <h3 className="font-semibold text-slate-200">{r.mitre_technique_name || r.name}</h3>
              <p className="text-[11px] text-slate-400">{r.description}</p>
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                <span>Rule: {r.rule_id}</span>
                <a
                  href={`https://attack.mitre.org/techniques/${(r.mitre_technique_id || 'T1110').replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-400 hover:underline flex items-center space-x-1"
                >
                  <span>ATT&CK</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Empirical Indicators of Compromise (IOCs) */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg p-5">
        <h2 className="text-sm font-semibold text-white mb-1">Empirical Indicators of Compromise (IOCs)</h2>
        <p className="text-xs text-slate-400 mb-4">Extracted indicators attributed to verified telemetry and malware triage</p>

        <div className="overflow-x-auto">
          <table className="w-full text-left table-dense">
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator Value</th>
                <th>Source Origin</th>
                <th>Reputation Verdict</th>
              </tr>
            </thead>
            <tbody>
              {extractedIocs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-center py-6 text-xs text-slate-500">
                    No active indicators extracted yet. Upload suspicious samples or ingest telemetry.
                  </td>
                </tr>
              ) : (
                extractedIocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="font-mono text-xs font-semibold text-cyan-400">{ioc.type}</td>
                    <td className="font-mono text-xs text-slate-200">{ioc.value}</td>
                    <td className="text-xs text-slate-400 font-mono truncate max-w-xs">{ioc.sample}</td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800/60 font-medium">
                        FLAGGED BY TRIAGE
                      </span>
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
