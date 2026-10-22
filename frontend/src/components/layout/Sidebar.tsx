import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  Radio,
  AlertTriangle,
  FolderSearch,
  Server,
  HeartPulse,
  Network,
  Crosshair,
  Bug,
  Binary,
  Archive,
  Fingerprint,
  Flame,
  FileCode2,
  FileText,
  ShieldCheck,
  Blocks,
  Settings,
  Camera,
  Cpu,
  ShieldAlert,
  Usb,
  Laptop,
} from 'lucide-react';

interface NavSection {
  title: string;
  items: {
    to: string;
    label: string;
    icon: React.ReactNode;
    badge?: string;
  }[];
}

export const Sidebar: React.FC = () => {
  const sections: NavSection[] = [
    {
      title: 'Host & Privacy Sentinel',
      items: [
        { to: '/active-system', label: 'Active System & Devices', icon: <Laptop className="w-4 h-4 text-cyan-400" />, badge: 'LIVE' },
        { to: '/total-360', label: '360° Total Safeguard', icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />, badge: '360°' },
        { to: '/omniscan', label: 'Omni Threat Scanner', icon: <ShieldAlert className="w-4 h-4 text-purple-400" />, badge: 'NEW' },
        { to: '/hardware-ports', label: 'Cable & Port Sentinel', icon: <Usb className="w-4 h-4 text-rose-400" />, badge: 'PORT-LOCK' },
        { to: '/sockets', label: 'Connected Sockets & C2', icon: <Network className="w-4 h-4 text-cyan-400" /> },
        { to: '/privacy-camera', label: 'Camera & Mic Sentinel', icon: <Camera className="w-4 h-4 text-rose-400" /> },
        { to: '/processes', label: 'Background Running Apps', icon: <Cpu className="w-4 h-4 text-amber-400" /> },
        { to: '/folder-scanner', label: 'Workspace File Scanner', icon: <FolderSearch className="w-4 h-4 text-emerald-400" /> },
      ],
    },

    {
      title: 'SOC Operations',
      items: [
        { to: '/', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
        { to: '/live-events', label: 'Live Event Stream', icon: <Radio className="w-4 h-4" /> },
        { to: '/incidents', label: 'Incidents', icon: <AlertTriangle className="w-4 h-4" /> },
        { to: '/investigation', label: 'Investigation Workspace', icon: <FolderSearch className="w-4 h-4" /> },
      ],
    },
    {
      title: 'Endpoints & Telemetry',
      items: [
        { to: '/hosts', label: 'Host Inventory', icon: <Server className="w-4 h-4" /> },
        { to: '/endpoint-health', label: 'Endpoint Health', icon: <HeartPulse className="w-4 h-4" /> },
        { to: '/network', label: 'Network Monitoring', icon: <Network className="w-4 h-4" /> },
      ],
    },
    {
      title: 'Offensive & Validation',
      items: [
        { to: '/assessments', label: 'Authorized Assessments', icon: <Crosshair className="w-4 h-4" /> },
        { to: '/vulnerabilities', label: 'Vulnerability Findings', icon: <Bug className="w-4 h-4" /> },
      ],
    },
    {
      title: 'Forensics & Triage',
      items: [
        { to: '/malware', label: 'Malware Triage', icon: <Binary className="w-4 h-4" /> },
        { to: '/forensics', label: 'Forensic Cases', icon: <Archive className="w-4 h-4" /> },
        { to: '/evidence', label: 'Evidence Vault', icon: <Fingerprint className="w-4 h-4" /> },
        { to: '/threat-intel', label: 'Threat Intel & IOCs', icon: <Flame className="w-4 h-4" /> },
      ],
    },
    {
      title: 'Intelligence & Config',
      items: [
        { to: '/detection-rules', label: 'Detection Rules & EWCC', icon: <FileCode2 className="w-4 h-4" /> },
        { to: '/reports', label: 'Security Reports', icon: <FileText className="w-4 h-4" /> },
        { to: '/audit', label: 'Audit Logs', icon: <ShieldCheck className="w-4 h-4" /> },
        { to: '/integrations', label: 'Integrations & Adapters', icon: <Blocks className="w-4 h-4" /> },
        { to: '/settings', label: 'Settings & Permissions', icon: <Settings className="w-4 h-4" /> },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-graphite-900 border-r border-slate-800/80 flex flex-col h-[calc(100vh-3.5rem)] sticky top-14 overflow-y-auto z-20">
      <div className="py-4 px-3 space-y-6">
        {sections.map((section, idx) => (
          <div key={idx} className="space-y-1">
            <div className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
              {section.title}
            </div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`
                }
              >
                <div className="flex items-center space-x-2.5">
                  <span className="text-current">{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/40 text-cyan-400 font-mono">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>
    </aside>
  );
};
