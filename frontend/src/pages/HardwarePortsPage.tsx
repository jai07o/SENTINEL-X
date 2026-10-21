import React, { useState, useEffect } from 'react';
import {
  Usb,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Lock,
  Unlock,
  HardDrive,
  FileSearch,
  CheckCircle2,
  XCircle,
  Smartphone,
  Radio,
  Cpu,
} from 'lucide-react';
import { ApiClient } from '../api/client';

export const HardwarePortsPage: React.FC = () => {
  const [devices, setDevices] = useState<any[]>([]);
  const [quarantineStatus, setQuarantineStatus] = useState<any>(null);
  const [immunization, setImmunization] = useState<any>(null);
  const [badUsbInfo, setBadUsbInfo] = useState<any>(null);
  const [isImmunizing, setIsImmunizing] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [selectedDrive, setSelectedDrive] = useState<string>('');
  const [customPath, setCustomPath] = useState<string>('');
  const [autoQuarantine, setAutoQuarantine] = useState<boolean>(true);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [devRes, statusRes, immRes, badUsbRes] = await Promise.all([
        ApiClient.getHardwareDevices(),
        ApiClient.getHardwarePortStatus(),
        ApiClient.getUsbImmunizationStatus().catch(() => null),
        ApiClient.getBadUsbStatus().catch(() => null),
      ]);
      setDevices(devRes.devices || []);
      setQuarantineStatus(statusRes);
      if (immRes) setImmunization(immRes);
      if (badUsbRes) setBadUsbInfo(badUsbRes);
      if (statusRes && typeof statusRes.auto_quarantine_enabled === 'boolean') {
        setAutoQuarantine(statusRes.auto_quarantine_enabled);
      }
    } catch (err: any) {
      console.error('Error fetching hardware ports:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleApplyHostImmunization = async () => {
    setIsImmunizing(true);
    try {
      const res = await ApiClient.applyHostUsbImmunization();
      setActionMessage(`🛡️ ${res.message}`);
      await fetchData();
    } catch (err: any) {
      setActionMessage(`Host immunization error: ${err.message}`);
    } finally {
      setIsImmunizing(false);
    }
  };

  const handleVaccinate = async (driveLetter: string) => {
    try {
      const res = await ApiClient.vaccinateDrive(driveLetter);
      if (res.success) {
        setActionMessage(`🛡️ ${res.message}`);
      } else {
        setActionMessage(`Vaccination note: ${res.message}`);
      }
      await fetchData();
    } catch (err: any) {
      setActionMessage(`Vaccination error: ${err.message}`);
    }
  };

  const handleToggleAutoQuarantine = async () => {
    try {
      const res = await ApiClient.toggleAutoQuarantine(!autoQuarantine);
      setAutoQuarantine(res.auto_quarantine_enabled);
      setActionMessage(`Auto-Quarantine on Virus is now ${res.auto_quarantine_enabled ? 'ENABLED' : 'DISABLED'}`);
    } catch (err: any) {
      setActionMessage(`Failed to toggle auto-quarantine: ${err.message}`);
    }
  };

  const handleScanDevice = async (targetPath: string, deviceId?: string) => {
    setIsScanning(true);
    setScanResult(null);
    setActionMessage(null);
    try {
      const res = await ApiClient.scanHardwarePort(targetPath, deviceId, autoQuarantine);
      setScanResult(res);
      await fetchData();
      if (!res.is_clean) {
        setActionMessage(`🚨 VIRUS DETECTED on ${targetPath}! Port immediately quarantined and dismounted.`);
      } else {
        setActionMessage(`[+] Scan complete for ${targetPath}: Device is verified CLEAN.`);
      }
    } catch (err: any) {
      setActionMessage(`Scan error: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleQuarantine = async (targetOrDevice: string) => {
    try {
      const res = await ApiClient.quarantineHardwarePort(targetOrDevice, 'Manual Analyst Quarantine');
      setActionMessage(res.message);
      await fetchData();
    } catch (err: any) {
      setActionMessage(`Quarantine failed: ${err.message}`);
    }
  };

  const handleRelease = async (targetOrDevice: string) => {
    try {
      const res = await ApiClient.releaseHardwarePort(targetOrDevice);
      setActionMessage(res.message);
      await fetchData();
    } catch (err: any) {
      setActionMessage(`Release failed: ${err.message}`);
    }
  };

  const quarantinedCount = quarantineStatus?.active_quarantined_ports_count || 0;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-graphite-900 border border-slate-800 p-5 rounded-lg shadow-xl relative overflow-hidden">
        <div className="flex items-center space-x-4 z-10">
          <div className={`p-3 rounded-lg ${quarantinedCount > 0 ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'}`}>
            <Usb className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold font-mono tracking-wide text-white">
                CABLE & HARDWARE PORT SENTINEL
              </h1>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider ${quarantinedCount > 0 ? 'bg-rose-500/30 text-rose-300 border border-rose-500/50 animate-pulse' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}`}>
                {quarantinedCount > 0 ? `${quarantinedCount} PORT(S) BLOCKED` : 'PORTS SECURE & ACTIVE'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Monitors all devices connected via physical cables/ports (USB flash drives, external hard drives, smartphones, serial cables, BadUSB). Detects autorun worms, cryptors, and double extensions, and immediately dismounts and locks ports upon virus detection.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3 z-10">
          <button
            onClick={handleToggleAutoQuarantine}
            className={`px-3 py-2 rounded text-xs font-mono font-bold flex items-center space-x-2 border transition-all ${
              autoQuarantine
                ? 'bg-rose-950/40 text-rose-300 border-rose-600/50 hover:bg-rose-900/50'
                : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>AUTO-QUARANTINE: {autoQuarantine ? 'ON' : 'OFF'}</span>
          </button>

          <button
            onClick={fetchData}
            disabled={isLoading}
            className="p-2 bg-graphite-800 hover:bg-graphite-700 text-slate-300 rounded border border-slate-700"
            title="Refresh connected devices"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action Notification Alert */}
      {actionMessage && (
        <div className={`p-3.5 rounded-lg border text-xs font-mono flex items-center justify-between ${
          actionMessage.includes('🚨') || actionMessage.includes('VIRUS') || actionMessage.includes('failed')
            ? 'bg-rose-950/50 border-rose-500/50 text-rose-200'
            : 'bg-cyan-950/50 border-cyan-500/50 text-cyan-200'
        }`}>
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* PENDRIVE & USB ANTI-INJECTION SHIELD */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Host Immunization Card */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                Host OS AutoRun Immunization
              </h2>
            </div>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
              immunization?.is_immune
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse'
            }`}>
              {immunization?.is_immune ? 'IMMUNIZED / PROTECTED' : 'VULNERABLE TO AUTORUN'}
            </span>
          </div>

          <p className="text-xs font-mono text-slate-400">
            {immunization?.message || 'Guards the laptop from automatic execution of scripts or droppers when pendrives are plugged in.'}
          </p>

          <div className="flex items-center justify-between pt-1">
            <div className="text-[10px] font-mono text-slate-500">
              Policies: HKCU NoDriveTypeAutoRun ({immunization?.policies?.hkcu_nodrivetypeautorun || 'N/A'})
            </div>
            {!immunization?.is_immune && (
              <button
                onClick={handleApplyHostImmunization}
                disabled={isImmunizing}
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded font-mono text-xs font-bold flex items-center space-x-1.5 transition-all shadow-md shadow-cyan-900/30"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>{isImmunizing ? 'IMMUNIZING...' : 'IMMUNIZE LAPTOP HOST'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Real-time Plug & Play Guard & BadUSB */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-purple-400" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                Plug & Play Guard & BadUSB Shield
              </h2>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              REAL-TIME INTERCEPT ACTIVE
            </span>
          </div>

          <p className="text-xs font-mono text-slate-400">
            Automatically intercepts inserted pendrives on plug-in. Deep-audits for autorun worms, hidden droppers, and rogue BadUSB keystroke injectors, halting port before injection.
          </p>

          <div className="flex items-center justify-between pt-1 text-xs font-mono">
            <span className="text-slate-400">
              BadUSB Keystroke Injectors: <strong className={badUsbInfo?.count > 0 ? 'text-rose-400' : 'text-emerald-400'}>{badUsbInfo?.count || 0} Suspect Devices</strong>
            </span>
            <span className="text-[10px] text-cyan-400 font-mono">
              Auto-Quarantine: <strong>{autoQuarantine ? 'ENABLED' : 'DISABLED'}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Manual Targeted Scan Bar */}
      <div className="bg-graphite-900 border border-slate-800 p-4 rounded-lg flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-3 w-full md:w-auto flex-1">
          <FileSearch className="w-5 h-5 text-cyan-400" />
          <span className="text-xs font-mono text-slate-300 font-bold whitespace-nowrap">Target Path / Drive:</span>
          <input
            type="text"
            value={customPath}
            onChange={(e) => setCustomPath(e.target.value)}
            placeholder="e.g. E:\ or G:\ or C:\Users\kakan\Downloads"
            className="bg-graphite-950 border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-slate-200 flex-1 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <button
          onClick={() => customPath.trim() && handleScanDevice(customPath.trim())}
          disabled={isScanning || !customPath.trim()}
          className="w-full md:w-auto px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all shadow-lg shadow-cyan-900/30"
        >
          {isScanning ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              <span>SCANNING & AUDITING...</span>
            </>
          ) : (
            <>
              <FileSearch className="w-3.5 h-3.5" />
              <span>DEEP SCAN CABLE DEVICE</span>
            </>
          )}
        </button>
      </div>

      {/* Active Scan Results Banner */}
      {scanResult && (
        <div className={`p-4 rounded-lg border font-mono ${
          scanResult.is_clean
            ? 'bg-emerald-950/30 border-emerald-500/40'
            : 'bg-rose-950/40 border-rose-500/50'
        }`}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              {scanResult.is_clean ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-rose-400 animate-bounce" />
              )}
              <h3 className={`font-bold text-sm ${scanResult.is_clean ? 'text-emerald-300' : 'text-rose-300'}`}>
                SCAN RESULT: {scanResult.verdict} ({scanResult.files_scanned} files inspected)
              </h3>
            </div>
            {scanResult.auto_quarantine_triggered && (
              <span className="px-2 py-0.5 text-[10px] font-bold bg-rose-500 text-white rounded animate-pulse">
                IMMEDIATE PORT QUARANTINE EXECUTED
              </span>
            )}
          </div>

          {scanResult.threats && scanResult.threats.length > 0 ? (
            <div className="space-y-2 mt-2">
              <div className="text-xs text-rose-300 font-bold">Intercepted Malicious Payloads:</div>
              {scanResult.threats.map((t: any, idx: number) => (
                <div key={idx} className="bg-graphite-950/80 p-2.5 rounded border border-rose-900/50 text-xs text-slate-300">
                  <div className="flex items-center justify-between text-rose-400 font-bold">
                    <span>[{t.threat_type}] Severity: {t.severity}</span>
                    <span className="text-slate-400 text-[10px]">{t.file_path}</span>
                  </div>
                  <div className="text-slate-300 mt-1">{t.details}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-emerald-300">
              Target volume verified clean. No autorun triggers, double extensions, or packed payloads detected.
            </div>
          )}
        </div>
      )}

      {/* Connected Cable Devices Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Usb className="w-4 h-4 text-cyan-400" />
            <span>Connected Cable Hardware Devices ({devices.length})</span>
          </h2>
          <span className="text-xs font-mono text-slate-500">Live Hardware PnP Registry</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {devices.map((dev, idx) => {
            const isQuarantined = dev.quarantined || dev.status === 'QUARANTINED';
            const isStorage = Boolean(dev.mount_point);

            return (
              <div
                key={idx}
                className={`bg-graphite-900 border rounded-lg p-4 transition-all relative overflow-hidden flex flex-col justify-between ${
                  isQuarantined
                    ? 'border-rose-500/70 shadow-lg shadow-rose-950/30'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase tracking-wider bg-slate-800 text-slate-300">
                      {dev.device_type}
                    </span>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase tracking-wider ${
                      isQuarantined
                        ? 'bg-rose-500 text-white animate-pulse'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}>
                      {isQuarantined ? 'QUARANTINED' : 'ACTIVE'}
                    </span>
                  </div>

                  <div className="flex items-center space-x-2 mb-2">
                    {dev.device_type.includes('Phone') ? (
                      <Smartphone className="w-5 h-5 text-purple-400" />
                    ) : dev.device_type.includes('Serial') ? (
                      <Radio className="w-5 h-5 text-amber-400" />
                    ) : (
                      <HardDrive className="w-5 h-5 text-cyan-400" />
                    )}
                    <h3 className="font-bold text-sm text-white font-mono truncate">{dev.name}</h3>
                  </div>

                  <div className="space-y-1 text-xs font-mono text-slate-400 mb-4">
                    {dev.mount_point && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Mount Point:</span>
                        <span className="text-cyan-300 font-bold">{dev.mount_point}</span>
                      </div>
                    )}
                    {dev.filesystem && (
                      <div className="flex justify-between">
                        <span className="text-slate-500">Filesystem:</span>
                        <span className="text-slate-300">{dev.filesystem}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-slate-500">Interface:</span>
                      <span className="text-slate-300">{dev.connection_interface}</span>
                    </div>
                    {dev.is_system_drive && (
                      <div className="text-[10px] text-amber-400 font-bold mt-1">
                        [OS System Partition - Dismount Protected]
                      </div>
                    )}
                  </div>
                </div>

                {/* Card Actions */}
                <div className="flex items-center gap-2 pt-3 border-t border-slate-800">
                  {dev.mount_point && !dev.is_system_drive && (
                    <>
                      <button
                        onClick={() => handleScanDevice(dev.mount_point, dev.device_id)}
                        disabled={isScanning}
                        className="flex-1 py-1.5 px-2 bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 rounded text-xs font-mono font-bold flex items-center justify-center space-x-1"
                      >
                        <FileSearch className="w-3.5 h-3.5" />
                        <span>Scan</span>
                      </button>

                      {dev.is_removable && dev.drive_letter && (
                        <button
                          onClick={() => handleVaccinate(dev.drive_letter)}
                          className="py-1.5 px-2.5 bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/60 rounded text-xs font-mono font-bold flex items-center justify-center space-x-1"
                          title="Vaccinate pendrive: locks autorun.inf so viruses cannot infect it"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>Vaccinate</span>
                        </button>
                      )}
                    </>
                  )}

                  {isQuarantined ? (
                    <button
                      onClick={() => handleRelease(dev.drive_letter || dev.device_id)}
                      className="flex-1 py-1.5 px-2 bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/60 rounded text-xs font-mono font-bold flex items-center justify-center space-x-1"
                    >
                      <Unlock className="w-3.5 h-3.5" />
                      <span>Release</span>
                    </button>
                  ) : (
                    !dev.is_system_drive && (
                      <button
                        onClick={() => handleQuarantine(dev.drive_letter || dev.device_id)}
                        className="flex-1 py-1.5 px-2 bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/60 rounded text-xs font-mono font-bold flex items-center justify-center space-x-1"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>Quarantine Port</span>
                      </button>
                    )
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Quarantined Ports Ledger */}
      {quarantineStatus?.quarantined_ports && quarantineStatus.quarantined_ports.length > 0 && (
        <div className="bg-graphite-900 border border-rose-900/50 p-4 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold text-rose-300 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>ACTIVE QUARANTINED PORTS ({quarantineStatus.quarantined_ports.length})</span>
            </h3>
            <span className="text-[10px] font-mono text-rose-400">PORTS DISMOUNTED & HARDWARE DISABLED</span>
          </div>

          <div className="space-y-2">
            {quarantineStatus.quarantined_ports.map((qp: any, idx: number) => (
              <div key={idx} className="bg-graphite-950 p-3 rounded border border-rose-800/40 flex items-center justify-between font-mono text-xs">
                <div>
                  <div className="text-white font-bold">{qp.port_key} - {qp.reason}</div>
                  <div className="text-slate-400 text-[10px]">
                    Quarantined at: {new Date(qp.quarantined_at).toLocaleTimeString()} | Dismounted: {qp.dismount_executed ? 'YES' : 'NO'}
                  </div>
                </div>
                <button
                  onClick={() => handleRelease(qp.port_key)}
                  className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-bold flex items-center space-x-1"
                >
                  <Unlock className="w-3 h-3" />
                  <span>Unblock</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
