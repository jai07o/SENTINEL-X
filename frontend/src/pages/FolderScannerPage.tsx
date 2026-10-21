import React, { useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { FolderSearch, ShieldCheck, ShieldAlert, FileText, Binary, Search, RefreshCw, CheckCircle2, AlertOctagon } from 'lucide-react';

export const FolderScannerPage: React.FC = () => {
  const [scanResult, setScanResult] = useState<any>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [filterThreatsOnly, setFilterThreatsOnly] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const runScan = async () => {
    setIsScanning(true);
    try {
      const data = await ApiClient.scanWorkspaceFolder(undefined, 500);
      setScanResult(data);
    } catch (err) {
      console.error('Failed to scan workspace folder:', err);
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    runScan();
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const summary = scanResult?.summary || {};
  const files: any[] = scanResult?.files || [];

  const filteredFiles = files.filter((f) => {
    if (filterThreatsOnly && f.threat_level === 'CLEAN') return false;
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      f.file_name?.toLowerCase().includes(term) ||
      f.relative_path?.toLowerCase().includes(term) ||
      f.extension?.toLowerCase().includes(term) ||
      f.sha256?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <FolderSearch className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">Workspace Folder & File Threat Scanner</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Audits all files in this directory for cryptographic hashes, Shannon entropy, obfuscated code, and web shells.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={runScan}
            disabled={isScanning}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition disabled:opacity-50 shadow-lg shadow-cyan-950/40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Auditing Everything in Folder...' : 'Rescan Entire Folder'}</span>
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">FILES AUDITED</span>
            <FileText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2 font-mono">{summary.total_files || 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Total workspace files</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">WORKSPACE SIZE</span>
            <Binary className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-2 font-mono">
            {summary.total_size_mb || 0} MB
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Scanned data volume</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">CLEAN VERIFIED</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2 font-mono">{summary.clean_files || 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">Normal entropy & signatures</div>
        </div>

        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-mono">THREAT INDICATORS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2 font-mono">
            {summary.flagged_threats || 0}
          </div>
          <div className="text-[11px] text-rose-300/80 mt-1">High entropy or suspicious scripts</div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-graphite-900 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center space-x-2 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 ml-1" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search files by path, extension, or SHA-256..."
            className="w-full bg-graphite-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setFilterThreatsOnly(!filterThreatsOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              filterThreatsOnly
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-graphite-950 text-slate-400 border border-slate-800 hover:text-slate-200'
            }`}
          >
            Threats & High Entropy Only
          </button>
        </div>
      </div>

      {/* Files Scanned Table */}
      <div className="bg-graphite-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-graphite-950/80 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Relative Path & File</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4">Entropy (Shannon)</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4 text-right">Integrity Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    {isScanning ? 'Auditing files in workspace...' : 'No files matched the search filter.'}
                  </td>
                </tr>
              ) : (
                filteredFiles.map((f, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{f.file_name}</div>
                      <div className="text-[10px] text-slate-500 truncate max-w-sm" title={f.relative_path}>
                        {f.relative_path}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-slate-300">
                      {f.size_formatted}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-graphite-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                          <div
                            className={`h-full ${
                              f.entropy >= 7.0
                                ? 'bg-rose-500'
                                : f.entropy >= 5.5
                                ? 'bg-amber-400'
                                : 'bg-cyan-400'
                            }`}
                            style={{ width: `${(f.entropy / 8.0) * 100}%` }}
                          />
                        </div>
                        <span
                          className={`text-[11px] ${
                            f.entropy >= 7.0 ? 'text-rose-400 font-bold' : 'text-slate-300'
                          }`}
                        >
                          {f.entropy}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleCopyHash(f.sha256)}
                        title="Click to copy full SHA-256"
                        className="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono transition text-left"
                      >
                        {f.sha256 ? `${f.sha256.substring(0, 16)}...` : 'N/A'}
                        {copiedHash === f.sha256 && (
                          <span className="ml-1 text-emerald-400 font-sans">✓ Copied</span>
                        )}
                      </button>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <div className="flex flex-col items-end space-y-0.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            f.threat_level === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : f.threat_level === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : f.threat_level === 'SUSPICIOUS'
                              ? 'bg-amber-900/40 text-amber-300'
                              : 'bg-emerald-950/60 text-emerald-400'
                          }`}
                        >
                          {f.threat_level}
                        </span>
                        {f.threat_indicators && f.threat_indicators.length > 0 && (
                          <span className="text-[9px] text-rose-400 font-sans">
                            {f.threat_indicators[0]}
                          </span>
                        )}
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
