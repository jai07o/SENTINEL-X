import React, { useState, useEffect } from 'react';
import {
  Link as LinkIcon,
  QrCode,
  Image as ImageIcon,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Upload,
  ArrowRight,
  CheckCircle2,
  XCircle,
  FileSearch,
  Sparkles,
  Info,
  RefreshCw,
  Layers,
  Terminal,
  FileCheck,
  Power,
  Activity,
  Cpu,
  Smartphone,
  Laptop,
  Radio,
  Lock,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { ApiClient } from '../api/client';

type TabType = 'link' | 'qr' | 'picture' | 'file';

export const OmniScanPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('link');
  const [isScanning, setIsScanning] = useState(false);
  const [isDeepScanning, setIsDeepScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Link & Deep Software state
  const [urlInput, setUrlInput] = useState('http://malicious-update.top/setup.exe');
  const [linkResult, setLinkResult] = useState<any | null>(null);
  const [deepLinkResult, setDeepLinkResult] = useState<any | null>(null);

  // QR state
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);
  const [qrResult, setQrResult] = useState<any | null>(null);

  // Picture state
  const [pictureFile, setPictureFile] = useState<File | null>(null);
  const [picturePreview, setPicturePreview] = useState<string | null>(null);
  const [pictureResult, setPictureResult] = useState<any | null>(null);

  // File state
  const [docFile, setDocFile] = useState<File | null>(null);
  const [fileResult, setFileResult] = useState<any | null>(null);

  // Autonomous Sentinel state
  const [sentinelStatus, setSentinelStatus] = useState<any | null>(null);
  const [isSentinelToggling, setIsSentinelToggling] = useState(false);
  const [showSentinelLogs, setShowSentinelLogs] = useState(false);

  // Sample tests
  const [samples, setSamples] = useState<any | null>(null);

  const fetchSentinelStatus = () => {
    ApiClient.getAutonomousSentinelStatus()
      .then((data) => setSentinelStatus(data))
      .catch(() => {});
  };

  useEffect(() => {
    ApiClient.getOmniScanSamples()
      .then((data) => setSamples(data))
      .catch(() => {});

    fetchSentinelStatus();

    // Auto-refresh pulse every 5 seconds
    const interval = setInterval(fetchSentinelStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleSentinel = async () => {
    setIsSentinelToggling(true);
    setError(null);
    try {
      if (sentinelStatus?.is_active) {
        await ApiClient.stopAutonomousSentinel();
      } else {
        await ApiClient.startAutonomousSentinel();
      }
      fetchSentinelStatus();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle Autonomous Background Sentinel');
    } finally {
      setIsSentinelToggling(false);
    }
  };

  const handleLinkScan = async (targetUrl?: string) => {
    const url = targetUrl || urlInput;
    if (!url.trim()) return;
    setIsScanning(true);
    setError(null);
    setLinkResult(null);
    setDeepLinkResult(null);

    try {
      const data = await ApiClient.scanLink(url);
      setLinkResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to scan URL');
    } finally {
      setIsScanning(false);
    }
  };

  const handleDeepLinkScan = async (targetUrl?: string) => {
    const url = targetUrl || urlInput;
    if (!url.trim()) return;
    setIsDeepScanning(true);
    setError(null);
    setLinkResult(null);
    setDeepLinkResult(null);

    try {
      const data = await ApiClient.scanDeepLink(url);
      setDeepLinkResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to perform deep software and path scan');
    } finally {
      setIsDeepScanning(false);
    }
  };

  const handleQrUpload = async (file: File) => {
    setQrFile(file);
    setQrPreview(URL.createObjectURL(file));
    setIsScanning(true);
    setError(null);
    setQrResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await ApiClient.scanQrCode(formData);
      setQrResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze QR code');
    } finally {
      setIsScanning(false);
    }
  };

  const handlePictureUpload = async (file: File) => {
    setPictureFile(file);
    setPicturePreview(URL.createObjectURL(file));
    setIsScanning(true);
    setError(null);
    setPictureResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await ApiClient.scanPicture(formData);
      setPictureResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to scan image for steganography');
    } finally {
      setIsScanning(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setDocFile(file);
    setIsScanning(true);
    setError(null);
    setFileResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await ApiClient.scanFile(formData);
      setFileResult(data);
    } catch (err: any) {
      setError(err.message || 'Failed to deep-scan file');
    } finally {
      setIsScanning(false);
    }
  };

  const getVerdictBadge = (verdict: string, riskScore: number) => {
    if (verdict?.includes('MALICIOUS') || riskScore >= 70) {
      return (
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> MALICIOUS THREAT DETECTED ({riskScore}/100)
        </span>
      );
    }
    if (verdict?.includes('SUSPICIOUS') || riskScore >= 35) {
      return (
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> SUSPICIOUS ACTIVITY ({riskScore}/100)
        </span>
      );
    }
    if (verdict === 'UNREADABLE') {
      return (
        <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold bg-slate-700 text-slate-300">
          <Info className="w-3.5 h-3.5 text-slate-400" /> UNREADABLE / NO MATRIX
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> CLEAN / VERIFIED SAFE ({riskScore}/100)
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-graphite-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Omni Threat Scanner
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono font-normal">
                  4-VECTOR & BACKGROUND SHIELD
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Deep software, link, QR code, picture, and file analysis with autonomous real-time background protection.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-graphite-900 border border-graphite-800 p-1 rounded-xl">
          <button
            onClick={() => setActiveTab('link')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'link'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LinkIcon className="w-3.5 h-3.5" />
            Link & Software Deep Path
          </button>
          <button
            onClick={() => setActiveTab('qr')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'qr'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <QrCode className="w-3.5 h-3.5" />
            QR Quishing
          </button>
          <button
            onClick={() => setActiveTab('picture')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'picture'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ImageIcon className="w-3.5 h-3.5" />
            Picture Stego/Polyglot
          </button>
          <button
            onClick={() => setActiveTab('file')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === 'file'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            Deep File & Macros
          </button>
        </div>
      </div>

      {/* =========================================================================
          AUTONOMOUS REAL-TIME BACKGROUND SENTINEL MASTER CONTROLLER
          ========================================================================= */}
      <div className={`p-5 rounded-2xl border transition-all ${
        sentinelStatus?.is_active
          ? 'bg-gradient-to-r from-emerald-950/40 via-graphite-900 to-cyan-950/40 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
          : 'bg-graphite-900 border-graphite-800'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className={`p-3 rounded-xl mt-0.5 border ${
              sentinelStatus?.is_active
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30 animate-pulse'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              <Power className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                  Autonomous Background Sentinel
                  {sentinelStatus?.is_active ? (
                    <span className="flex items-center gap-1.5 text-[11px] px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                      RUNNING IN BACKGROUND (LAPTOP & MOBILE)
                    </span>
                  ) : (
                    <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      STOPPED / IDLE
                    </span>
                  )}
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                When activated, this engine runs persistently in the background across your laptop and mobile device, continuously checking connected sockets for C2 trojans, auto-opening camera/mic handles, rogue miners, and newly downloaded files until you click exit.
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleToggleSentinel}
              disabled={isSentinelToggling}
              className={`px-5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2 transition-all shadow-md ${
                sentinelStatus?.is_active
                  ? 'bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white shadow-rose-950/40'
                  : 'bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-emerald-950/40'
              } disabled:opacity-50`}
            >
              {isSentinelToggling ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" /> Processing...
                </>
              ) : sentinelStatus?.is_active ? (
                <>
                  <Power className="w-4 h-4" /> STOP & EXIT SENTINEL
                </>
              ) : (
                <>
                  <Radio className="w-4 h-4 animate-pulse" /> ACTIVATE AUTONOMOUS SENTINEL
                </>
              )}
            </button>

            <button
              onClick={() => setShowSentinelLogs(!showSentinelLogs)}
              className="px-3.5 py-2.5 rounded-xl bg-graphite-950 hover:bg-graphite-800 border border-graphite-700 text-xs text-slate-300 flex items-center gap-1.5 transition-colors"
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              Telemetry
              {showSentinelLogs ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Live Metrics Row if Active */}
        {sentinelStatus?.is_active && (
          <div className="mt-4 pt-4 border-t border-graphite-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-2.5 rounded-xl bg-graphite-950/70 border border-graphite-800 flex items-center gap-2.5">
              <Laptop className="w-4 h-4 text-cyan-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-mono">Sockets Monitored</div>
                <div className="text-xs font-bold text-white font-mono">{sentinelStatus.stats?.sockets_monitored || 0} active</div>
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-graphite-950/70 border border-graphite-800 flex items-center gap-2.5">
              <Activity className="w-4 h-4 text-rose-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-mono">Camera Sweeps</div>
                <div className="text-xs font-bold text-white font-mono">{sentinelStatus.stats?.webcam_checks || 0} sweeps</div>
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-graphite-950/70 border border-graphite-800 flex items-center gap-2.5">
              <Smartphone className="w-4 h-4 text-purple-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-mono">Mobile Sync</div>
                <div className="text-xs font-bold text-emerald-400 font-mono">ONLINE & PROTECTED</div>
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-graphite-950/70 border border-graphite-800 flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-mono">Threats Blocked</div>
                <div className="text-xs font-bold text-amber-400 font-mono">{sentinelStatus.stats?.threats_intercepted || 0} intercepted</div>
              </div>
            </div>
          </div>
        )}

        {/* Expandable Telemetry Drawer */}
        {showSentinelLogs && (
          <div className="mt-4 pt-4 border-t border-graphite-800 space-y-2 animate-in fade-in duration-200">
            <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mb-2">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              Real-Time Background Sentinel Event Log
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2 font-mono text-[11px]">
              {sentinelStatus?.recent_activity_log?.length > 0 ? (
                sentinelStatus.recent_activity_log.map((entry: any, i: number) => (
                  <div key={i} className="p-2 rounded-lg bg-graphite-950 border border-graphite-800/80 flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        entry.level === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                        entry.level === 'WARNING' ? 'bg-amber-500/20 text-amber-300' :
                        'bg-cyan-500/20 text-cyan-300'
                      }`}>
                        {entry.category}
                      </span>
                      <span className="text-slate-300">{entry.message}</span>
                    </div>
                    <span className="text-slate-500 text-[10px] shrink-0">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic p-3 text-center">
                  No background events recorded yet. Activate sentinel to begin live monitoring.
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* =========================================================================
          TAB 1: LINK & SOFTWARE DEEP PATH AUDITOR
          ========================================================================= */}
      {activeTab === 'link' && (
        <div className="space-y-6">
          <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
              <LinkIcon className="w-4 h-4 text-cyan-400" />
              Scan Target URL & Inspect Entire Path, Including Software, Files & Embedded Binaries
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Performs deep recursive traversal: traces redirect chains, unpacks linked software/installers (.exe, .zip, .msi), parses HTML for hidden scripts and iframes, and audits nested payloads until the path is verified clean.
            </p>

            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example.com/target-link"
                  className="w-full bg-graphite-950 border border-graphite-700 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              {/* Action Buttons: Quick & Deep Scan */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleLinkScan()}
                  disabled={isScanning || isDeepScanning}
                  className="px-4 py-2.5 bg-graphite-800 hover:bg-graphite-700 text-slate-200 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 transition-all border border-graphite-700 disabled:opacity-50"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Scanning...
                    </>
                  ) : (
                    <>
                      <LinkIcon className="w-3.5 h-3.5 text-cyan-400" /> Quick Link Audit
                    </>
                  )}
                </button>

                <button
                  onClick={() => handleDeepLinkScan()}
                  disabled={isScanning || isDeepScanning}
                  className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition-all shadow-md shadow-purple-950/30 disabled:opacity-50"
                >
                  {isDeepScanning ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Traversing Software & Path Depth...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5" /> Deep Path & Software Analysis
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Quick Test Vectors */}
            {samples?.links && (
              <div className="mt-4 pt-4 border-t border-graphite-800">
                <span className="text-[11px] font-medium text-slate-400 block mb-2">Curated Test Vectors:</span>
                <div className="flex flex-wrap gap-2">
                  {samples.links.map((item: any, i: number) => (
                    <button
                      key={i}
                      onClick={() => {
                        setUrlInput(item.url);
                        handleDeepLinkScan(item.url);
                      }}
                      className="px-2.5 py-1 rounded-lg bg-graphite-950 hover:bg-graphite-800 border border-graphite-700/60 text-[11px] text-slate-300 flex items-center gap-1.5 transition-colors"
                    >
                      <Sparkles className="w-3 h-3 text-cyan-400" />
                      {item.title}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Deep Path & Software Scan Results */}
          {deepLinkResult && (
            <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-graphite-800 pb-4">
                <div>
                  <div className="text-xs font-mono text-cyan-400 font-bold flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" /> DEEP PATH & SOFTWARE INSPECTION DOSSIER
                  </div>
                  <div className="text-sm font-bold text-white font-mono break-all mt-0.5">{deepLinkResult.target_url}</div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Resolved Destination: <span className="text-cyan-300 font-mono">{deepLinkResult.final_url}</span>
                  </div>
                </div>
                <div>{getVerdictBadge(deepLinkResult.threat_verdict, deepLinkResult.risk_score)}</div>
              </div>

              {/* Step-by-Step Traversal Audit Trail */}
              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-purple-400" />
                  Path Traversal Audit Trail ({deepLinkResult.audit_trail?.length || 0} Steps)
                </h3>
                <div className="space-y-1.5 bg-graphite-950 p-3 rounded-xl border border-graphite-800 font-mono text-xs max-h-48 overflow-y-auto">
                  {deepLinkResult.audit_trail?.map((step: string, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-slate-300">
                      <span className="text-cyan-500 font-bold">[{i + 1}]</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Downloaded Software & Payloads Analyzed along the path */}
              {deepLinkResult.software_payloads_analyzed?.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 mb-2.5 flex items-center gap-1.5">
                    <FileSearch className="w-3.5 h-3.5 text-amber-400" />
                    Software & Binary Payloads Analyzed at End of Path ({deepLinkResult.software_payloads_analyzed.length})
                  </h3>
                  <div className="space-y-3">
                    {deepLinkResult.software_payloads_analyzed.map((sw: any, idx: number) => (
                      <div key={idx} className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 space-y-2">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-graphite-800/60 pb-2">
                          <div className="font-mono text-xs font-bold text-white flex items-center gap-2">
                            <FileCheck className="w-4 h-4 text-cyan-400" />
                            {sw.filename}
                            <span className="text-slate-400 font-normal">({sw.file_size_formatted})</span>
                          </div>
                          <div>{getVerdictBadge(sw.threat_verdict, sw.risk_score)}</div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] font-mono text-slate-400">
                          <div>SHA-256: <span className="text-cyan-300">{sw.sha256?.substring(0, 16)}...</span></div>
                          <div>Entropy: <span className="text-purple-300">{sw.entropy} / 8.0</span></div>
                          <div>Archive Files: <span className="text-slate-200">{sw.archive_contents?.length || 0}</span></div>
                        </div>

                        {sw.threat_indicators?.length > 0 && (
                          <div className="mt-2 space-y-1">
                            {sw.threat_indicators.map((ind: string, j: number) => (
                              <div key={j} className="text-[11px] text-rose-300 flex items-center gap-1.5 bg-rose-500/10 p-1.5 rounded">
                                <XCircle className="w-3 h-3 text-rose-400 shrink-0" />
                                <span>{ind}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Security Indicators */}
              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Path Security Indicators ({deepLinkResult.threat_indicators?.length || 0})
                </h3>
                {deepLinkResult.threat_indicators?.length > 0 ? (
                  <div className="space-y-1.5">
                    {deepLinkResult.threat_indicators.map((ind: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-2 text-xs p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-200">
                        <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-xs p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>The entire path, destination web page, and all associated software packages were deep-audited and verified completely clean.</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Basic Link Scan Results (Fallback if quick scan clicked) */}
          {linkResult && !deepLinkResult && (
            <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-graphite-800 pb-4">
                <div>
                  <div className="text-xs font-mono text-slate-400">TARGET DESTINATION AUDIT</div>
                  <div className="text-sm font-bold text-white font-mono break-all mt-0.5">{linkResult.target_url}</div>
                </div>
                <div>{getVerdictBadge(linkResult.threat_verdict, linkResult.risk_score)}</div>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2.5 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Detected Security Indicators ({linkResult.threat_indicators?.length || 0})
                </h3>
                {linkResult.threat_indicators?.length > 0 ? (
                  <div className="space-y-1.5">
                    {linkResult.threat_indicators.map((ind: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-2 text-xs p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-200">
                        <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-xs p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>No heuristic risks, typosquatting, or malicious executable downloads detected.</span>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-xs font-semibold text-slate-300 mb-3 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" />
                    HTTP Redirect Chain ({linkResult.redirect_chain?.length || 1} Hops)
                  </div>
                  {linkResult.redirect_chain?.length > 0 ? (
                    <div className="space-y-2">
                      {linkResult.redirect_chain.map((hop: any, idx: number) => (
                        <div key={idx} className="flex items-center gap-2 text-xs font-mono text-slate-300">
                          <span className="px-1.5 py-0.5 rounded bg-graphite-800 text-cyan-400 font-bold text-[10px]">
                            {hop.status}
                          </span>
                          <span className="truncate flex-1" title={hop.url}>{hop.url}</span>
                          {idx < linkResult.redirect_chain.length - 1 && (
                            <ArrowRight className="w-3 h-3 text-slate-500 shrink-0" />
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs font-mono text-slate-400">Direct connection (0 intermediate redirects)</div>
                  )}
                  <div className="mt-3 pt-3 border-t border-graphite-800/60 text-xs">
                    <span className="text-slate-400">Final Resolved URL: </span>
                    <span className="text-cyan-300 font-mono break-all">{linkResult.final_url}</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 space-y-2.5">
                  <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-purple-400" />
                    Payload at End of Link
                  </div>
                  <div className="flex justify-between text-xs py-1 border-b border-graphite-800/50">
                    <span className="text-slate-400">Content-Type (MIME):</span>
                    <span className="font-mono text-white font-medium">{linkResult.content_type || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between text-xs py-1 border-b border-graphite-800/50">
                    <span className="text-slate-400">Payload Size:</span>
                    <span className="font-mono text-white font-medium">{linkResult.payload_size_bytes} bytes</span>
                  </div>
                  <div className="flex justify-between text-xs py-1 border-b border-graphite-800/50">
                    <span className="text-slate-400">HTTP Status Code:</span>
                    <span className="font-mono text-white font-medium">{linkResult.status_code || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between text-xs py-1">
                    <span className="text-slate-400">Server Banner:</span>
                    <span className="font-mono text-slate-300">{linkResult.server_header || 'Hidden'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          TAB 2: QR CODE SCANNER & QUISHING ANALYZER
          ========================================================================= */}
      {activeTab === 'qr' && (
        <div className="space-y-6">
          <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
              <QrCode className="w-4 h-4 text-purple-400" />
              Upload QR Code Picture for Quishing & Destination Virus Audit
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Decodes QR matrix points, parses malicious phishing redirects, and deep-inspects the virus or download payload at the destination of the QR code.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
              <label className="border-2 border-dashed border-graphite-700 hover:border-purple-500/60 bg-graphite-950/60 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-all hover:bg-graphite-950">
                <input
                  type="file"
                  accept="image/*"
                  onChange={(e) => e.target.files?.[0] && handleQrUpload(e.target.files[0])}
                  className="hidden"
                />
                <div className="p-3 rounded-full bg-purple-500/10 text-purple-400 mb-3">
                  <Upload className="w-5 h-5" />
                </div>
                <div className="text-xs font-semibold text-white text-center">Click or Drag & Drop QR Image</div>
                <div className="text-[11px] text-slate-400 text-center mt-1">PNG, JPG, BMP, WebP supported</div>
              </label>

              {qrPreview && (
                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 flex flex-col items-center justify-center">
                  <div className="text-xs text-slate-400 mb-2 font-mono">{qrFile?.name}</div>
                  <img src={qrPreview} alt="QR Preview" className="max-h-44 object-contain rounded-lg border border-graphite-700" />
                </div>
              )}
            </div>
          </div>

          {qrResult && (
            <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-graphite-800 pb-4">
                <div>
                  <div className="text-xs font-mono text-slate-400">QR CODE DECODED MATRIX</div>
                  <div className="text-sm font-bold text-white font-mono break-all mt-0.5">
                    {qrResult.decoded_payload || 'Unreadable Matrix'}
                  </div>
                </div>
                <div>{getVerdictBadge(qrResult.threat_verdict, qrResult.risk_score)}</div>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Quishing & Threat Findings ({qrResult.threat_indicators?.length || 0})
                </h3>
                <div className="space-y-1.5">
                  {qrResult.threat_indicators?.map((ind: string, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 text-xs p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-200">
                      <ShieldAlert className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>

              {qrResult.link_audit && (
                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 space-y-3">
                  <div className="text-xs font-semibold text-cyan-400 flex items-center gap-1.5">
                    <ExternalLink className="w-3.5 h-3.5" />
                    Deep Audit of Destination Link inside QR
                  </div>
                  <div className="text-xs text-slate-300">
                    <span className="text-slate-400">Endpoint Payload Type: </span>
                    <span className="font-mono text-white">{qrResult.link_audit.content_type}</span>
                  </div>
                  <div className="text-xs text-slate-300">
                    <span className="text-slate-400">Final Resolved URL: </span>
                    <span className="font-mono text-cyan-300 break-all">{qrResult.link_audit.final_url}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          TAB 3: PICTURE STEGANOGRAPHY & POLYGLOT SCANNER
          ========================================================================= */}
      {activeTab === 'picture' && (
        <div className="space-y-6">
          <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
              <ImageIcon className="w-4 h-4 text-rose-400" />
              Upload Picture to Detect Steganography, Polyglots & EXIF Malware
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Scans past JPEG `FF D9` and PNG `IEND` image EOF markers to detect hidden trailing executables, parses EXIF tags for PHP/XSS shellcode, and analyzes SVG vector graphics for embedded scripts.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
              <label className="border-2 border-dashed border-graphite-700 hover:border-rose-500/60 bg-graphite-950/60 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-all hover:bg-graphite-950">
                <input
                  type="file"
                  accept="image/*,.svg"
                  onChange={(e) => e.target.files?.[0] && handlePictureUpload(e.target.files[0])}
                  className="hidden"
                />
                <div className="p-3 rounded-full bg-rose-500/10 text-rose-400 mb-3">
                  <Upload className="w-5 h-5" />
                </div>
                <div className="text-xs font-semibold text-white text-center">Click or Drag & Drop Picture</div>
                <div className="text-[11px] text-slate-400 text-center mt-1">JPEG, PNG, SVG, WebP, GIF</div>
              </label>

              {picturePreview && (
                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 flex flex-col items-center justify-center">
                  <div className="text-xs text-slate-400 mb-2 font-mono">{pictureFile?.name}</div>
                  <img src={picturePreview} alt="Picture Preview" className="max-h-44 object-contain rounded-lg border border-graphite-700" />
                </div>
              )}
            </div>
          </div>

          {pictureResult && (
            <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-graphite-800 pb-4">
                <div>
                  <div className="text-xs font-mono text-slate-400">IMAGE STEGANOGRAPHY INSPECTOR</div>
                  <div className="text-sm font-bold text-white font-mono break-all mt-0.5">{pictureResult.filename}</div>
                </div>
                <div>{getVerdictBadge(pictureResult.threat_verdict, pictureResult.risk_score)}</div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-[11px] text-slate-400">Total Size</div>
                  <div className="text-sm font-bold text-white font-mono mt-0.5">
                    {(pictureResult.total_size_bytes / 1024).toFixed(1)} KB
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-[11px] text-slate-400">Shannon Entropy</div>
                  <div className="text-sm font-bold text-cyan-400 font-mono mt-0.5">
                    {pictureResult.entropy} / 8.0
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-[11px] text-slate-400">Polyglot Carrier?</div>
                  <div className={`text-sm font-bold font-mono mt-0.5 ${pictureResult.is_polyglot ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {pictureResult.is_polyglot ? 'DETECTED' : 'NO'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-[11px] text-slate-400">Hidden Payload</div>
                  <div className="text-xs font-bold text-amber-300 truncate mt-1">
                    {pictureResult.hidden_payload_type || 'None'}
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2.5 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Steganography & Structural Findings
                </h3>
                {pictureResult.threat_indicators?.length > 0 ? (
                  <div className="space-y-1.5">
                    {pictureResult.threat_indicators.map((ind: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-2 text-xs p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-200">
                        <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-xs p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Clean image stream. No trailing executable byte payloads or EXIF shellcode found.</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          TAB 4: DEEP MULTI-FORMAT FILE SCANNER
          ========================================================================= */}
      {activeTab === 'file' && (
        <div className="space-y-6">
          <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
              <FileCode className="w-4 h-4 text-emerald-400" />
              Upload Any File or Document for Deep Malware & Macro Audit
            </h2>
            <p className="text-xs text-slate-400 mb-4">
              Performs binary signature analysis, detects double-extension masquerades (e.g. `doc.pdf.exe`), unpacks Office VBA macros, audits PDF `/Launch` actions, and inspects archive droppers.
            </p>

            <label className="border-2 border-dashed border-graphite-700 hover:border-emerald-500/60 bg-graphite-950/60 rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer transition-all hover:bg-graphite-950">
              <input
                type="file"
                onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                className="hidden"
              />
              <div className="p-3 rounded-full bg-emerald-500/10 text-emerald-400 mb-3">
                <Upload className="w-6 h-6" />
              </div>
              <div className="text-xs font-semibold text-white text-center">Click or Drag & Drop File to Deep-Scan</div>
              <div className="text-[11px] text-slate-400 text-center mt-1">PDF, Word, Excel, ZIP, EXE, PS1, Shell scripts (Max 50MB)</div>
            </label>
          </div>

          {fileResult && (
            <div className="bg-graphite-900 border border-graphite-800 rounded-xl p-5 space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-graphite-800 pb-4">
                <div>
                  <div className="text-xs font-mono text-slate-400">FILE INTEGRITY & STATIC SCAN</div>
                  <div className="text-sm font-bold text-white font-mono break-all mt-0.5">{fileResult.filename}</div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">Size: {fileResult.file_size_formatted}</div>
                </div>
                <div>{getVerdictBadge(fileResult.threat_verdict, fileResult.risk_score)}</div>
              </div>

              <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800 space-y-2">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs">
                  <span className="text-slate-400">SHA-256:</span>
                  <span className="font-mono text-cyan-300 select-all break-all">{fileResult.sha256}</span>
                </div>
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs">
                  <span className="text-slate-400">MD5:</span>
                  <span className="font-mono text-slate-300 select-all">{fileResult.md5}</span>
                </div>
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 text-xs">
                  <span className="text-slate-400">Shannon Entropy:</span>
                  <span className="font-mono text-purple-300">{fileResult.entropy} / 8.0</span>
                </div>
              </div>

              {fileResult.archive_contents && (
                <div className="p-4 rounded-xl bg-graphite-950 border border-graphite-800">
                  <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                    <FileSearch className="w-3.5 h-3.5 text-amber-400" />
                    Archive Contained Files ({fileResult.archive_contents.length})
                  </div>
                  <div className="space-y-1">
                    {fileResult.archive_contents.map((item: string, i: number) => (
                      <div key={i} className="text-xs font-mono text-slate-300 flex items-center gap-2">
                        <FileCheck className="w-3 h-3 text-cyan-400" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-xs font-semibold text-slate-300 mb-2.5 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  Detected Malware Indicators ({fileResult.threat_indicators?.length || 0})
                </h3>
                {fileResult.threat_indicators?.length > 0 ? (
                  <div className="space-y-1.5">
                    {fileResult.threat_indicators.map((ind: string, idx: number) => (
                      <div key={idx} className="flex items-start gap-2 text-xs p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-200">
                        <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-xs p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Clean document/file. No double extensions, macros, or malicious exploit objects detected.</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
