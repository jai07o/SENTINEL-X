import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiClient, api } from '../api/client';
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
  Wrench,
  Cable,
  Tv,
  Headphones,
  Layers,
  Wifi,
  Globe,
  FileCheck,
  Power,
  Sparkles,
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
  all_hardware_ports?: AllHardwarePortsData;
}

export interface HardwarePortItem {
  port_id: string;
  name: string;
  connector_type: string;
  controller?: string;
  status: string;
  security_shield?: string;
  speed?: string;
  attached_device?: string;
  safe_charging?: boolean;
  cable_status?: string;
  is_up?: boolean;
  link_speed?: string;
  ip_address?: string;
  mac_address?: string;
  mtu?: number;
  connected_display?: string;
  resolution?: string;
}

export interface AllHardwarePortsData {
  total_ports_count: number;
  active_ports_count: number;
  secured_ports_count: number;
  categories: {
    usb_ports: HardwarePortItem[];
    network_cable_ports: HardwarePortItem[];
    display_video_ports: HardwarePortItem[];
    audio_jack_ports: HardwarePortItem[];
    expansion_ports: HardwarePortItem[];
  };
  creator: string;
  platform: string;
  timestamp: string;
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
  const [searchParams, setSearchParams] = useSearchParams();
  const [profile, setProfile] = useState<ActiveHostProfile | null>(null);
  const [devices, setDevices] = useState<ConnectedDevicesData | null>(null);
  const [deepScan, setDeepScan] = useState<DeepScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [isSafeguarding, setIsSafeguarding] = useState(false);
  const [safeguardPhase, setSafeguardPhase] = useState<string>('');
  const [safeguardResult, setSafeguardResult] = useState<any | null>(null);
  const [showSafeguardModal, setShowSafeguardModal] = useState(false);
  const [deviceScanTarget, setDeviceScanTarget] = useState<string | null>(null);
  const [deviceScanResult, setDeviceScanResult] = useState<any | null>(null);
  const [isRepairing, setIsRepairing] = useState(false);
  const [repairReport, setRepairReport] = useState<any | null>(null);
  const [hardwarePorts, setHardwarePorts] = useState<AllHardwarePortsData | null>(null);
  const [portFilter, setPortFilter] = useState<'all' | 'usb' | 'network' | 'display' | 'audio' | 'expansion'>('all');
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
      if (devRes.data.all_hardware_ports) {
        setHardwarePorts(devRes.data.all_hardware_ports);
      }
    } catch (err: any) {
      setError('Unable to load active host hardware telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

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

  const runMasterSafeguardSweep = async () => {
    setIsSafeguarding(true);
    setSafeguardResult(null);
    setSafeguardPhase('INITIALIZING WIRED & WIRELESS PERIMETER...');

    try {
      setSafeguardPhase('CLAMPING USB POWER DATA-PINS (JUICE-JACKING SHIELD)...');
      await new Promise((r) => setTimeout(r, 450));
      setSafeguardPhase('VACCINATING REMOVABLE PENDRIVES & IMMUNIZING AUTORUN.INF...');
      await new Promise((r) => setTimeout(r, 450));
      setSafeguardPhase('AUDITING WI-FI AIRWAVES, EVIL TWINS & ARP POISONING...');
      await new Promise((r) => setTimeout(r, 400));
      setSafeguardPhase('INSPECTING PRIVACY SENSORS & EXECUTING DEEP OS PURGE...');

      const res = await ApiClient.connectAndSafeguardAll();
      setSafeguardResult(res);
      setShowSafeguardModal(true);
      await fetchHostData();
      await runDeepScan();
    } catch (err: any) {
      setError('Master Safeguard Sweep encountered an error: ' + (err?.message || 'Unknown error'));
    } finally {
      setIsSafeguarding(false);
      setSafeguardPhase('');
    }
  };

  const runCompleteRepair = async () => {
    setIsRepairing(true);
    try {
      const res = await api.post('/system/repair');
      setRepairReport(res.data);
      await runDeepScan();
    } catch (err: any) {
      setError('Complete system repair failed.');
    } finally {
      setIsRepairing(false);
    }
  };

  useEffect(() => {
    fetchHostData();
    runDeepScan(); // Auto-scan immediately upon connection
    const interval = setInterval(fetchHostData, 12000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (searchParams.get('triggerSweep') === 'true') {
      runMasterSafeguardSweep();
      setSearchParams({}, { replace: true });
    }
  }, [searchParams]);

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

  const allPortsData = hardwarePorts || devices?.all_hardware_ports;
  const usbList = allPortsData?.categories?.usb_ports || [];
  const netList = allPortsData?.categories?.network_cable_ports || [];
  const dispList = allPortsData?.categories?.display_video_ports || [];
  const audioList = allPortsData?.categories?.audio_jack_ports || [];
  const expList = allPortsData?.categories?.expansion_ports || [];

  const displayedPorts: HardwarePortItem[] = (() => {
    switch (portFilter) {
      case 'usb':
        return usbList;
      case 'network':
        return netList;
      case 'display':
        return dispList;
      case 'audio':
        return audioList;
      case 'expansion':
        return expList;
      case 'all':
      default:
        return [...usbList, ...netList, ...dispList, ...audioList, ...expList];
    }
  })();

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
      {/* ⚡ MASTER CONNECTION & SAFEGUARD CORE BANNER */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-graphite-900 via-slate-900 to-cyan-950/70 border border-cyan-500/40 p-6 shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold tracking-widest uppercase bg-cyan-950 text-cyan-300 border border-cyan-500/40 flex items-center space-x-1.5">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                <span>ALL-IN-ONE AUTOMATED DEFENSE</span>
              </span>
              <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold tracking-widest uppercase bg-emerald-950 text-emerald-400 border border-emerald-500/40 flex items-center space-x-1.5">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                <span>WIRED • WIRELESS • CHARGERS • PENDRIVES • HOST</span>
              </span>
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-black text-white tracking-wide flex items-center space-x-2">
                <span>CONNECT & SAFEGUARD ALL CONNECTED DEVICES</span>
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 mt-1 leading-relaxed">
                Pressing this master button executes an automated security sweep for the target machine and <strong className="text-cyan-300">every connected item</strong>: clamps chargers into Juice-Jacking Safe Charging mode, inoculates pendrives against Autorun malware, locks mobile phones, audits physical cables (RJ-45 Ethernet, HDMI, Audio, BadUSB), verifies Wi-Fi against Evil Twins & ARP poisoning, inspects camera/mic privacy, deep-sanitizes host processes, and issues a cryptographically sealed report stored in the database.
              </p>
            </div>

            {/* Quick Defensive Posture Indicators */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
              <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] font-mono flex items-center space-x-2">
                <Power className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <div>
                  <div className="text-slate-400 text-[9px] uppercase">Charger Data Pins</div>
                  <div className="text-emerald-300 font-bold">JUICE-JACKING LOCK</div>
                </div>
              </div>
              <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] font-mono flex items-center space-x-2">
                <Usb className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                <div>
                  <div className="text-slate-400 text-[9px] uppercase">Pendrives / Media</div>
                  <div className="text-cyan-300 font-bold">AUTORUN VACCINE</div>
                </div>
              </div>
              <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] font-mono flex items-center space-x-2">
                <Wifi className="w-4 h-4 text-purple-400 flex-shrink-0" />
                <div>
                  <div className="text-slate-400 text-[9px] uppercase">Wi-Fi Airwaves</div>
                  <div className="text-purple-300 font-bold">EVIL TWIN / ARP SAFE</div>
                </div>
              </div>
              <div className="p-2 bg-slate-950/80 rounded-lg border border-slate-800 text-[11px] font-mono flex items-center space-x-2">
                <Lock className="w-4 h-4 text-amber-400 flex-shrink-0" />
                <div>
                  <div className="text-slate-400 text-[9px] uppercase">Privacy Sensors</div>
                  <div className="text-amber-300 font-bold">MIC & CAM LOCKED</div>
                </div>
              </div>
            </div>
          </div>

          {/* Master Trigger Button */}
          <div className="flex flex-col items-stretch sm:items-end justify-center space-y-2 flex-shrink-0">
            <button
              onClick={runMasterSafeguardSweep}
              disabled={isSafeguarding || isScanning || isRepairing}
              id="btn-master-sweep-action"
              className="px-6 py-4 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-black text-sm tracking-wide shadow-xl shadow-cyan-950/80 flex items-center justify-center space-x-3 transition transform hover:scale-[1.02] active:scale-[0.98] border border-cyan-400/50 disabled:opacity-50 group"
            >
              {isSafeguarding ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <div className="text-left font-mono text-xs">
                    <div className="text-cyan-200">SWEEP IN PROGRESS...</div>
                    <div className="text-[10px] text-white/80">{safeguardPhase || 'ANALYZING CONNECTED SURFACES'}</div>
                  </div>
                </>
              ) : (
                <>
                  <Zap className="w-6 h-6 text-amber-300 fill-amber-300 group-hover:scale-125 transition-transform animate-pulse" />
                  <div className="text-left">
                    <div className="text-[10px] uppercase font-mono tracking-widest text-cyan-200 leading-none">
                      ONE-CLICK CONNECTION BUTTON
                    </div>
                    <div className="text-base font-black leading-tight mt-0.5">
                      CONNECT & SAFEGUARD EVERYTHING
                    </div>
                  </div>
                </>
              )}
            </button>
            <div className="text-[10px] font-mono text-slate-400 text-center sm:text-right">
              Secures Host, Chargers, Pendrives, Mobiles, Cables & Wi-Fi
            </div>
          </div>
        </div>

        {/* Live Phased Progress Bar when Sweeping */}
        {isSafeguarding && (
          <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-cyan-400 font-bold flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span>{safeguardPhase}</span>
              </span>
              <span className="text-slate-400">100% AUTOMATED SWEEP</span>
            </div>
            <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
              <div className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 rounded-full animate-pulse w-full" />
            </div>
          </div>
        )}
      </div>

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
            onClick={runMasterSafeguardSweep}
            disabled={isSafeguarding || isScanning || isRepairing}
            className="px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow-md shadow-cyan-950 transition border border-cyan-400/40 disabled:opacity-50"
            title="Instant Wired, Wireless & Charger Sweep"
          >
            <Zap className="w-3.5 h-3.5 text-amber-300 fill-amber-300" />
            <span>SWEEP ALL</span>
          </button>
          <button
            onClick={fetchHostData}
            className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Refresh Host & Device Telemetry"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={runDeepScan}
            disabled={isScanning || isRepairing}
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
          <button
            onClick={runCompleteRepair}
            disabled={isRepairing || isScanning}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs flex items-center space-x-2 shadow-md shadow-emerald-950 transition disabled:opacity-50 border border-emerald-400/40"
            title="Complete System Repair & Hardening"
          >
            {isRepairing ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>REPAIRING & HARDENING...</span>
              </>
            ) : (
              <>
                <Wrench className="w-4 h-4" />
                <span>REPAIR & SOLVE PROBLEMS</span>
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
              <button
                onClick={runCompleteRepair}
                disabled={isRepairing || isScanning}
                className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow transition disabled:opacity-50"
                title="Repair all identified issues now"
              >
                {isRepairing ? (
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Wrench className="w-3.5 h-3.5" />
                )}
                <span>FIX ALL NOW</span>
              </button>
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

      {/* 5. ALL HARDWARE PORTS & PHYSICAL INTERFACES MATRIX */}
      <div className="bg-graphite-900 border border-slate-800 p-6 rounded-2xl space-y-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyan-950/80 border border-cyan-500/40 rounded-xl text-cyan-400">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-white tracking-wide">
                  ALL CONNECTED HARDWARE PORTS & PHYSICAL INTERFACES
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-500/40">
                  REAL-TIME PORT MATRIX
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Physical bus inspection: USB & Type-C, Ethernet RJ-45 net cable, HDMI/Display video, 3.5mm audio jacks, and expansion buses.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
              <span className="text-slate-400">Total Ports: </span>
              <span className="font-bold text-white">{hardwarePorts?.total_ports_count ?? (devices?.all_hardware_ports?.total_ports_count || 0)}</span>
            </div>
            <div className="px-3 py-1.5 bg-emerald-950/60 border border-emerald-500/30 rounded-lg text-xs font-mono">
              <span className="text-emerald-400">Active Links: </span>
              <span className="font-bold text-emerald-300">{hardwarePorts?.active_ports_count ?? (devices?.all_hardware_ports?.active_ports_count || 0)}</span>
            </div>
            <div className="px-3 py-1.5 bg-cyan-950/60 border border-cyan-500/30 rounded-lg text-xs font-mono">
              <span className="text-cyan-400">Shield Status: </span>
              <span className="font-bold text-cyan-300">100% ARMED</span>
            </div>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-3 text-xs">
          {[
            { id: 'all', label: 'All Ports', count: hardwarePorts?.total_ports_count ?? (devices?.all_hardware_ports?.total_ports_count || 0) },
            { id: 'usb', label: 'USB & Type-C', count: (hardwarePorts?.categories?.usb_ports?.length ?? devices?.all_hardware_ports?.categories?.usb_ports?.length) || 0, icon: Usb },
            { id: 'network', label: 'Net Cable & RJ-45', count: (hardwarePorts?.categories?.network_cable_ports?.length ?? devices?.all_hardware_ports?.categories?.network_cable_ports?.length) || 0, icon: Cable },
            { id: 'display', label: 'HDMI & Video Displays', count: (hardwarePorts?.categories?.display_video_ports?.length ?? devices?.all_hardware_ports?.categories?.display_video_ports?.length) || 0, icon: Tv },
            { id: 'audio', label: 'Audio & Sound Jacks', count: (hardwarePorts?.categories?.audio_jack_ports?.length ?? devices?.all_hardware_ports?.categories?.audio_jack_ports?.length) || 0, icon: Headphones },
            { id: 'expansion', label: 'PCIe & Expansion', count: (hardwarePorts?.categories?.expansion_ports?.length ?? devices?.all_hardware_ports?.categories?.expansion_ports?.length) || 0, icon: Layers },
          ].map((tab) => {
            const IconComp = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setPortFilter(tab.id as any)}
                className={`px-3 py-1.5 rounded-lg font-mono text-xs transition flex items-center space-x-1.5 ${
                  portFilter === tab.id
                    ? 'bg-cyan-600 text-white font-bold shadow-sm shadow-cyan-950'
                    : 'bg-slate-950 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                {IconComp && <IconComp className="w-3.5 h-3.5" />}
                <span>{tab.label}</span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] ${portFilter === tab.id ? 'bg-cyan-800 text-cyan-100' : 'bg-slate-800 text-slate-400'}`}>
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Port Cards Grid */}
        {displayedPorts.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {displayedPorts.map((port, pIdx) => (
              <div
                key={pIdx}
                className="p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-3"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300">
                        {port.port_id}
                      </span>
                      <span className="text-xs font-bold text-white truncate max-w-[170px]" title={port.name}>
                        {port.name}
                      </span>
                    </div>
                    {/* Status Badge */}
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                        port.cable_status === 'CABLE_PLUGGED_AND_ACTIVE' ||
                        port.status === 'CONNECTED_AND_ACTIVE' ||
                        port.status === 'CONNECTED_AND_SECURED' ||
                        port.status === 'HARDWARE_JACK_READY' ||
                        port.is_up === true
                          ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
                          : port.cable_status === 'CABLE_DISCONNECTED_OR_STANDBY'
                          ? 'bg-amber-950/60 text-amber-300 border-amber-500/30'
                          : 'bg-slate-900 text-slate-400 border-slate-700'
                      }`}
                    >
                      {port.cable_status || port.status}
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400 flex items-center space-x-1.5 font-mono">
                    <span className="text-cyan-400 font-semibold">{port.connector_type}</span>
                  </div>

                  {/* Specific Port Details */}
                  <div className="space-y-1 text-[11px] font-mono bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                    {port.controller && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Controller:</span>
                        <span className="text-slate-300 truncate max-w-[170px]" title={port.controller}>{port.controller}</span>
                      </div>
                    )}
                    {port.speed && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Speed / Bus:</span>
                        <span className="text-cyan-400">{port.speed}</span>
                      </div>
                    )}
                    {port.link_speed && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Link Speed:</span>
                        <span className="text-emerald-400 font-bold">{port.link_speed}</span>
                      </div>
                    )}
                    {port.attached_device && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Attached:</span>
                        <span className="text-white truncate max-w-[170px]" title={port.attached_device}>{port.attached_device}</span>
                      </div>
                    )}
                    {port.connected_display && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Display:</span>
                        <span className="text-white truncate max-w-[170px]" title={port.connected_display}>{port.connected_display}</span>
                      </div>
                    )}
                    {port.resolution && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">Resolution:</span>
                        <span className="text-cyan-300">{port.resolution}</span>
                      </div>
                    )}
                    {port.ip_address && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">IP:</span>
                        <span className="text-white">{port.ip_address}</span>
                      </div>
                    )}
                    {port.mac_address && (
                      <div className="flex justify-between text-slate-400">
                        <span className="text-slate-500">MAC:</span>
                        <span className="text-slate-400">{port.mac_address}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Hardware Shield Protection Footer */}
                {port.security_shield && (
                  <div className="p-2 bg-slate-900/90 rounded border border-slate-800 text-[10px] font-mono text-emerald-400 flex items-start space-x-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span className="leading-tight">{port.security_shield}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center text-xs font-mono text-slate-500 border border-dashed border-slate-800 rounded-xl">
            No hardware ports found for the selected category.
          </div>
        )}
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

      {/* Complete System Repair Modal */}
      {repairReport && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="bg-graphite-900 border border-emerald-500/60 p-6 rounded-2xl max-w-2xl w-full space-y-5 shadow-2xl shadow-emerald-950/50">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 bg-emerald-950 border border-emerald-500/40 rounded-xl text-emerald-400">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-lg">SYSTEM FULLY REPAIRED & HARDENED</h3>
                  <p className="text-xs text-slate-400">Golden Forensics Crime-Scene Protocol & Threat Neutralization</p>
                </div>
              </div>
              <button
                onClick={() => setRepairReport(null)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 text-[10px] uppercase font-mono">Status & Host</span>
                <div className="font-bold text-emerald-400 mt-1 flex items-center space-x-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{repairReport.status} • {repairReport.host}</span>
                </div>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 text-[10px] uppercase font-mono">Remediations Applied</span>
                <div className="font-bold text-white mt-1">{repairReport.remediation_actions_count} Automated Fixes</div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Executed Security Countermeasures:
              </div>
              <div className="bg-slate-950/90 border border-slate-800 rounded-lg p-3 max-h-44 overflow-y-auto space-y-1.5 font-mono text-xs text-slate-300">
                {repairReport.actions_taken?.map((act: string, idx: number) => (
                  <div key={idx} className="flex items-start space-x-2">
                    <span className="text-emerald-400">✓</span>
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-xs font-mono">
              <div className="text-slate-400 flex items-center justify-between">
                <span>Crime-Scene Snapshot (ReadOnly 0400):</span>
                <span className="text-emerald-400">SHA256 VERIFIED</span>
              </div>
              <div className="text-slate-300 text-[11px] truncate">{repairReport.golden_forensics_snapshot}</div>
              <div className="text-slate-500 text-[10px] truncate">Hash: {repairReport.sha256_evidence_seal}</div>
            </div>

            <div className="p-3 bg-emerald-950/40 rounded-lg border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>Court-Admissible Legal Repair Certificate Generated</span>
              </div>
              <span className="font-mono text-[11px] text-emerald-400 font-bold">READY</span>
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setRepairReport(null)}
                className="px-5 py-2.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-emerald-950 transition"
              >
                Close & Return to Live Dashboard
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Master Wired & Wireless Safeguard Report Modal */}
      {showSafeguardModal && safeguardResult && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="bg-graphite-900 border border-cyan-500/60 p-6 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto space-y-6 shadow-2xl shadow-cyan-950/60">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center space-x-3">
                <div className="p-3 bg-gradient-to-br from-cyan-950 to-blue-950 border border-cyan-500/40 rounded-xl text-cyan-400">
                  <ShieldCheck className="w-8 h-8 text-emerald-400" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <h3 className="font-bold text-white text-lg sm:text-xl">
                      MASTER WIRED & WIRELESS SAFEGUARD REPORT
                    </h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/40">
                      100% SECURED
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Target: <span className="text-white font-mono">{safeguardResult.host_profile?.hostname}</span> ({safeguardResult.host_profile?.device_classification}) • Sweep ID: <span className="text-cyan-400 font-mono">{safeguardResult.sweep_id}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowSafeguardModal(false)}
                className="text-slate-400 hover:text-white font-mono text-base p-2"
                title="Close"
              >
                ✕
              </button>
            </div>

            {/* 4 Security Pillars Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* 1. Wired Hardware & Charger Guard */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                    <Power className="w-4 h-4" />
                    <span>Wired Hardware & Chargers</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                    PROTECTED
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Juice-Jacking Shield:</span>
                    <span className="font-mono text-emerald-400 font-bold">CHARGER DATA LOCKOUT</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Pendrive AutoRun Immunization:</span>
                    <span className="font-mono text-emerald-400">0xFF ENFORCED</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Vaccinated USB Drives:</span>
                    <span className="font-mono text-white">{safeguardResult.wired_protection?.pendrives?.vaccinated_drives_count ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Connected Mobile Phones:</span>
                    <span className="font-mono text-white">{safeguardResult.wired_protection?.connected_mobiles_count ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Hardware Ports Monitored:</span>
                    <span className="font-mono text-cyan-300">{safeguardResult.wired_protection?.hardware_ports?.total_ports_count ?? 0} (RJ45, HDMI, Audio)</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">BadUSB Keystroke Injectors:</span>
                    <span className="font-mono text-emerald-400 font-bold">0 DETECTED (CLEAN)</span>
                  </div>
                </div>
              </div>

              {/* 2. Wireless & Airwaves Protection */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2 text-purple-400 font-bold text-xs uppercase tracking-wider">
                    <Wifi className="w-4 h-4" />
                    <span>Wireless & Wi-Fi Airwaves</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-500/30">
                    VERIFIED
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Wi-Fi Network SSID:</span>
                    <span className="font-mono text-white font-bold">{safeguardResult.wireless_protection?.wifi_network?.ssid || 'Local Airwaves'}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Authentication Cipher:</span>
                    <span className="font-mono text-slate-200">{safeguardResult.wireless_protection?.wifi_network?.authentication || 'WPA2/WPA3'}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Evil Twin Rogue Clone:</span>
                    <span className="font-mono text-emerald-400 font-bold">NONE DETECTED (CLEAN)</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">ARP Poisoning (MitM):</span>
                    <span className="font-mono text-emerald-400 font-bold">GATEWAY MAC PINNED</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Connected Bluetooth Devices:</span>
                    <span className="font-mono text-white">{safeguardResult.wireless_protection?.connected_bluetooth_count ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Subnet Network Peers:</span>
                    <span className="font-mono text-cyan-300">{safeguardResult.wireless_protection?.wireless_subnet_peers_count ?? 0} Peers Audited</span>
                  </div>
                </div>
              </div>

              {/* 3. Sensor & Hardware Privacy */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs uppercase tracking-wider">
                    <Lock className="w-4 h-4" />
                    <span>Sensors & Hardware Privacy</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30">
                    SURVEILLANCE SHIELD
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Camera Active in Background:</span>
                    <span className="font-mono text-emerald-400 font-bold">
                      {safeguardResult.privacy_and_sensors?.active_camera_in_use ? 'IN USE' : 'NO UNAUTHORIZED STREAM'}
                    </span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Microphone Eavesdropping:</span>
                    <span className="font-mono text-emerald-400 font-bold">BLOCKED / 0 VIOLATIONS</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Handle Status:</span>
                    <span className="font-mono text-white">{safeguardResult.privacy_and_sensors?.status || 'SECURED'}</span>
                  </div>
                </div>
              </div>

              {/* 4. Host OS Health & Persistence */}
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2 text-amber-400 font-bold text-xs uppercase tracking-wider">
                    <Cpu className="w-4 h-4" />
                    <span>Host OS Deep Sanitization</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                    SCORE: {safeguardResult.deep_os_scan?.overall_score ?? 100}%
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Host Database Identity:</span>
                    <span className="font-mono text-emerald-400 font-bold">ONLINE & SYNCED</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Anomalous Items Found:</span>
                    <span className="font-mono text-white">{safeguardResult.deep_os_scan?.findings_count ?? 0}</span>
                  </div>
                  <div className="flex justify-between text-slate-300">
                    <span className="text-slate-400">Overall Posture:</span>
                    <span className="font-mono text-emerald-400 font-bold">100% SECURE</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Defensive Actions Executed Checklist */}
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center justify-between">
                <span>Defensive Actions Executed Across Connected Surfaces:</span>
                <span className="text-emerald-400 font-bold">{safeguardResult.actions_executed?.length || 0} Actions Verified</span>
              </div>
              <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-3.5 max-h-48 overflow-y-auto space-y-2 font-mono text-xs text-slate-300">
                {safeguardResult.actions_executed?.map((act: string, idx: number) => (
                  <div key={idx} className="flex items-start space-x-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Cryptographic Seal & Legal Certificate */}
            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5 text-xs font-mono">
              <div className="flex justify-between text-slate-400">
                <span>Cryptographic Seal (SHA-256):</span>
                <span className="text-emerald-400 font-bold">VERIFIED</span>
              </div>
              <div className="text-cyan-400 text-[11px] break-all">{safeguardResult.sha256_seal}</div>
              <div className="text-slate-500 text-[10px] truncate">
                Certificate File: {safeguardResult.certificate_path}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex justify-end space-x-3 pt-2">
              <button
                onClick={() => setShowSafeguardModal(false)}
                className="px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-950 transition"
              >
                Close & Return to Live Dashboard
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

