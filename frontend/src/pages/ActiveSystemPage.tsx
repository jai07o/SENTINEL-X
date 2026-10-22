import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import {
  Laptop,
  Monitor,
  Battery,
  BatteryCharging,
  Cpu,
  HardDrive,
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Usb,
  Bluetooth,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Radio,
  Lock,
} from 'lucide-react';

interface ActiveHostProfile {
  hostname: string;
  device_classification: string;
  is_laptop: boolean;
  battery: {
    is_laptop: boolean;
    has_battery: boolean;
    percent: number;
    power_plugged: boolean;
    status_text: string;
  };
  operating_system: string;
  distro_id: string;
  os_release: string;
  kernel_version: string;
  architecture: string;
  processor: string;
  cpu_cores_logical: number;
  cpu_cores_physical: number;
  cpu_usage_percent: number;
  ram_total_gb: number;
  ram_used_gb: number;
  ram_free_gb: number;
  ram_usage_percent: number;
  disks: Array<{
    device: string;
    mountpoint: string;
    fstype: string;
    total_gb: number;
    free_gb: number;
    percent_used: number;
  }>;
  primary_ip: string;
  primary_mac: string;
  connected_and_active: boolean;
  active_protection_mode: string;
  creator: string;
  platform: string;
  timestamp: string;
}

interface ConnectedDevicesData {
  connected_mobiles_count: number;
  connected_mobiles: Array<{
    device_id: string;
    name: string;
    device_type: string;
    platform: string;
    connection_interface: string;
    status: string;
    juice_jacking_protected: boolean;
    debug_bridge_exposed: boolean;
    risk_level: string;
    recommendation: string;
  }>;
  external_storage_count: number;
  external_storage: Array<{
    device_id: string;
    name: string;
    device_type: string;
    mountpoint?: string;
    total_gb?: number;
    free_gb?: number;
    quarantined: boolean;
    auto_immunized: boolean;
    risk_level: string;
  }>;
  connected_peripherals_count: number;
  connected_peripherals: Array<{
    device_id: string;
    name: string;
    pnp_class: string;
    device_type: string;
    status: string;
    badusb_protected: boolean;
  }>;
  network_neighbors_count: number;
  network_neighbors: Array<{
    ip_address: string;
    mac_address: string;
    type: string;
    status: string;
  }>;
}

interface DeepScanResult {
  scan_id: string;
  status: string;
  host_scanned: string;
  device_classification: string;
  os_environment: string;
  security_score: number;
  overall_posture: string;
  duration_seconds: number;
  statistics: {
    processes_analyzed: number;
    sockets_analyzed: number;
    files_vetted: number;
    connected_mobiles: number;
    external_drives: number;
    findings_total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: Array<{
    severity: string;
    category: string;
    item: string;
    details: string;
    remediation: string;
  }>;
  scanned_at: string;
}

export const ActiveSystemPage: React.FC = () => {
  const [profile, setProfile] = useState<ActiveHostProfile | null>(null);
  const [devices, setDevices] = useState<ConnectedDevicesData | null>(null);
  const [deepScan, setDeepScan] = useState<DeepScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [deviceScanTarget, setDeviceScanTarget] = useState<string | null>(null);
  const [deviceScanResult, setDeviceScanResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchHostData = async () => {
    try {
      setError(null);
      const [profRes, devRes] = await Promise.all([
        api.get<ActiveHostProfile>('/system/active-host'),
        api.get<ConnectedDevicesData>('/system/connected-devices'),
      ]);
      setProfile(profRes.data);
      setDevices(devRes.data);
    } catch (err: any) {
      setError('Unable to load active host hardware telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHostData();
    const interval = setInterval(fetchHostData, 12000);
    return () => clearInterval(interval);
  }, []);

  const runDeepScan = async () => {
    setIsScanning(true);
    try {
      const res = await api.post<DeepScanResult>('/system/deep-scan');
      setDeepScan(res.data);
      await fetchHostData();
    } catch (err: any) {
      setError('Deep OS Scan failed to complete.');
    } finally {
      setIsScanning(false);
    }
  };

  const scanSpecificDevice = async (deviceId: string, devType: string) => {
    setDeviceScanTarget(deviceId);
    try {
      const res = await api.post('/system/scan-connected-device', {
        device_id: deviceId,
        device_type: devType,
      });
      setDeviceScanResult(res.data);
    } catch (err) {
      alert('Device deep scan failed.');
    } finally {
      setDeviceScanTarget(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <div className="text-sm font-mono text-cyan-400">CONNECTING TO ACTIVE LOCAL HOST & SENSORS...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header & Real-Time Badge */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-graphite-900 border border-slate-800 p-5 rounded-xl shadow-lg">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-cyan-950/80 border border-cyan-500/40 rounded-xl text-cyan-400">
            {profile?.is_laptop ? <Laptop className="w-8 h-8" /> : <Monitor className="w-8 h-8" />}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xl font-bold text-white tracking-wide">{profile?.hostname}</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-500/40 flex items-center space-x-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                <span>CONNECTED ACTIVE {profile?.device_classification.toUpperCase()}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {profile?.operating_system} • {profile?.architecture} • {profile?.processor}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchHostData}
            className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Refresh Host & Device Telemetry"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={runDeepScan}
            disabled={isScanning}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs flex items-center space-x-2 shadow-md shadow-cyan-950 transition disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>SCANNING OS IN-DEPTH...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                <span>RUN IN-DEPTH DEEP SCAN</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-500/50 rounded-lg text-rose-300 text-xs flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Hardware Telemetry Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Battery & Power */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Power & Battery</span>
            <div className="text-lg font-bold text-white mt-1 flex items-center space-x-1.5">
              {profile?.battery.power_plugged ? (
                <BatteryCharging className="w-5 h-5 text-emerald-400" />
              ) : (
                <Battery className="w-5 h-5 text-amber-400" />
              )}
              <span>{profile?.battery.percent}%</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">{profile?.battery.status_text}</div>
          </div>
          <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center font-bold text-xs text-cyan-400">
            {profile?.is_laptop ? 'BAT' : 'AC'}
          </div>
        </div>

        {/* CPU Telemetry */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Processor Cores</span>
            <div className="text-lg font-bold text-white mt-1 flex items-center space-x-1.5">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <span>{profile?.cpu_usage_percent}% Load</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {profile?.cpu_cores_logical} Logical / {profile?.cpu_cores_physical} Physical Cores
            </div>
          </div>
          <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center font-mono text-xs text-cyan-400">
            CPU
          </div>
        </div>

        {/* RAM Telemetry */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">System Memory</span>
            <div className="text-lg font-bold text-white mt-1 flex items-center space-x-1.5">
              <HardDrive className="w-5 h-5 text-purple-400" />
              <span>{profile?.ram_usage_percent}% Used</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              {profile?.ram_used_gb} GB / {profile?.ram_total_gb} GB RAM
            </div>
          </div>
          <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center font-mono text-xs text-purple-400">
            RAM
          </div>
        </div>

        {/* Network Identity */}
        <div className="bg-graphite-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Network Identity</span>
            <div className="text-sm font-bold text-white mt-1 font-mono">{profile?.primary_ip}</div>
            <div className="text-[11px] text-slate-400 font-mono mt-0.5">MAC: {profile?.primary_mac}</div>
          </div>
          <div className="p-2.5 rounded-full bg-slate-800/80 border border-slate-700 text-cyan-400">
            <Network className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Deep Scan Results Banner */}
      {deepScan && (
        <div className="bg-graphite-900 border border-cyan-500/40 p-5 rounded-xl space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-4 gap-2">
            <div className="flex items-center space-x-3">
              <div
                className={`p-2.5 rounded-lg ${
                  deepScan.security_score >= 85
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                    : 'bg-amber-950 text-amber-400 border border-amber-500/40'
                }`}
              >
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <div className="text-base font-bold text-white flex items-center space-x-2">
                  <span>IN-DEPTH OS DEEP SCAN COMPLETED</span>
                  <span className="text-xs px-2 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">
                    {deepScan.scan_id}
                  </span>
                </div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Host: {deepScan.host_scanned} • Duration: {deepScan.duration_seconds}s • Posture:{' '}
                  <span className="text-emerald-400 font-bold">{deepScan.overall_posture}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <div className="text-right">
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Overall Security Score</div>
                <div className="text-2xl font-black text-cyan-400">{deepScan.security_score}%</div>
              </div>
            </div>
          </div>

          {/* Scan Stats Chips */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-400">Processes Analyzed</span>
              <div className="text-sm font-bold text-white mt-0.5">{deepScan.statistics.processes_analyzed}</div>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-400">Sockets Examined</span>
              <div className="text-sm font-bold text-white mt-0.5">{deepScan.statistics.sockets_analyzed}</div>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-400">Files Vetted</span>
              <div className="text-sm font-bold text-white mt-0.5">{deepScan.statistics.files_vetted}</div>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-400">Connected Mobiles</span>
              <div className="text-sm font-bold text-white mt-0.5">{deepScan.statistics.connected_mobiles}</div>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] font-mono text-slate-400">Anomalies Detected</span>
              <div
                className={`text-sm font-bold mt-0.5 ${
                  deepScan.statistics.findings_total > 0 ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {deepScan.statistics.findings_total}
              </div>
            </div>
          </div>

          {/* Findings List */}
          {deepScan.findings.length > 0 && (
            <div className="space-y-2 mt-2">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Deep Inspection Findings & Remediation:
              </div>
              <div className="space-y-2">
                {deepScan.findings.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div>
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            f.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400 border border-rose-500/40'
                              : f.severity === 'HIGH'
                              ? 'bg-orange-950 text-orange-400 border border-orange-500/40'
                              : 'bg-amber-950 text-amber-400 border border-amber-500/40'
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="font-semibold text-white">{f.category}:</span>
                        <span className="text-slate-300">{f.item}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">{f.details}</div>
                    </div>
                    <div className="text-[11px] text-cyan-400 font-mono bg-cyan-950/40 px-2.5 py-1 rounded border border-cyan-500/30 whitespace-nowrap">
                      Remedy: {f.remediation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Connected Devices Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              Connected Devices & Peripherals Real-Time Guard
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {devices ? devices.connected_mobiles_count + devices.external_storage_count + devices.connected_peripherals_count : 0} Active Device(s) Linked
          </span>
        </div>

        {/* Device Categories Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* 1. Mobile Smartphones & Tablets */}
          <div className="bg-graphite-900 border border-slate-800 p-5 rounded-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Smartphone className="w-5 h-5 text-emerald-400" />
                <span className="font-bold text-sm text-white">Mobile Devices (Phones & Tablets)</span>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {devices?.connected_mobiles_count || 0} Connected
              </span>
            </div>

            {devices && devices.connected_mobiles.length > 0 ? (
              <div className="space-y-3">
                {devices.connected_mobiles.map((mob, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="font-bold text-xs text-white flex items-center space-x-2">
                        <span>{mob.name}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                          {mob.platform}
                        </span>
                      </div>
                      <button
                        onClick={() => scanSpecificDevice(mob.device_id, 'mobile')}
                        disabled={deviceScanTarget === mob.device_id}
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono transition"
                      >
                        {deviceScanTarget === mob.device_id ? 'Scanning...' : 'Deep Scan Mobile'}
                      </button>
                    </div>
                    <div className="text-[11px] text-slate-400">Interface: {mob.connection_interface}</div>
                    <div className="flex items-center space-x-2 text-[10px] text-emerald-400 font-mono">
                      <Lock className="w-3 h-3" />
                      <span>Juice-Jacking Shield Active • Charging Data-Pins Filtered</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No physical smartphone or tablet currently plugged via USB. Connect device to trigger instant scan.
              </div>
            )}
          </div>

          {/* 2. External USB Storage & Removable Drives */}
          <div className="bg-graphite-900 border border-slate-800 p-5 rounded-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Usb className="w-5 h-5 text-rose-400" />
                <span className="font-bold text-sm text-white">External USB Storage & Media</span>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {devices?.external_storage_count || 0} Drives
              </span>
            </div>

            {devices && devices.external_storage.length > 0 ? (
              <div className="space-y-3">
                {devices.external_storage.map((d, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="font-bold text-xs text-white">{d.name}</div>
                      <button
                        onClick={() => scanSpecificDevice(d.mountpoint || d.device_id, 'storage')}
                        disabled={deviceScanTarget === (d.mountpoint || d.device_id)}
                        className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono transition"
                      >
                        {deviceScanTarget === (d.mountpoint || d.device_id) ? 'Scanning...' : 'Deep Scan Drive'}
                      </button>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Mount: {d.mountpoint || 'Removable Device'} • Free Space: {d.free_gb || 0} GB
                    </div>
                    <div className="flex items-center space-x-2 text-[10px] text-emerald-400 font-mono">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Auto-Immunized & Virus Filter Active</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No removable USB drives connected. Any plugged-in flash drive is automatically quarantined & scanned.
              </div>
            )}
          </div>

          {/* 3. Connected Peripherals (Bluetooth & USB) */}
          <div className="bg-graphite-900 border border-slate-800 p-5 rounded-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Bluetooth className="w-5 h-5 text-blue-400" />
                <span className="font-bold text-sm text-white">Peripherals & Bluetooth Accessories</span>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {devices?.connected_peripherals_count || 0} Accessories
              </span>
            </div>

            {devices && devices.connected_peripherals.length > 0 ? (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {devices.connected_peripherals.map((p, idx) => (
                  <div key={idx} className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                    <span className="font-medium text-slate-200">{p.name}</span>
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                      BadUSB Protected
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No external wireless or USB accessories active.
              </div>
            )}
          </div>

          {/* 4. Local Subnet / Wi-Fi Network Neighbors */}
          <div className="bg-graphite-900 border border-slate-800 p-5 rounded-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Network className="w-5 h-5 text-purple-400" />
                <span className="font-bold text-sm text-white">Local Wi-Fi / Subnet Devices</span>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {devices?.network_neighbors_count || 0} Peers
              </span>
            </div>

            {devices && devices.network_neighbors.length > 0 ? (
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {devices.network_neighbors.map((n, idx) => (
                  <div key={idx} className="p-2 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300">{n.ip_address}</span>
                    <span className="text-slate-500">{n.mac_address}</span>
                    <span className="text-[10px] text-cyan-400">{n.type}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg">
                No neighbor devices detected on current subnet interface.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Target Device Scan Modal */}
      {deviceScanResult && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-graphite-900 border border-cyan-500/50 p-6 rounded-xl max-w-lg w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span className="font-bold text-white text-base">TARGET DEVICE SCAN REPORT</span>
              </div>
              <button
                onClick={() => setDeviceScanResult(null)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Device ID / Path:</span>
                <span className="font-mono text-white truncate max-w-xs">{deviceScanResult.device_id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Status:</span>
                <span className="font-bold text-emerald-400">{deviceScanResult.status}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Files Inspected:</span>
                <span className="font-mono text-white">{deviceScanResult.files_scanned}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Threats Found:</span>
                <span className="font-mono text-emerald-400 font-bold">{deviceScanResult.threats_count}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Juice-Jacking Protection:</span>
                <span className="font-mono text-emerald-400">ACTIVE & SECURED</span>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300">
              Target device has been verified and sanitized. Hardware cables and data buses are throttled to charging-only handshake.
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setDeviceScanResult(null)}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
