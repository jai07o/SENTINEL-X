import React, { useState } from 'react';
import { 
  Puzzle, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Activity, 
  Terminal, 
  Shield, 
  Cpu, 
  Globe, 
  FolderLock, 
  ExternalLink,
  Settings,
  RefreshCw
} from 'lucide-react';

interface IntegrationCard {
  id: string;
  name: string;
  category: 'HOST_AGENT' | 'NETWORK' | 'RUNTIME' | 'THREAT_INTEL' | 'EXTENSIONS';
  description: string;
  status: 'ACTIVE' | 'READY' | 'STANDBY' | 'DISABLED';
  eventsProcessed: string;
  configPath: string;
  distributionSupport: string;
  docUrl: string;
}

const INTEGRATIONS_DATA: IntegrationCard[] = [
  {
    id: 'systemd_journal',
    name: 'systemd journald & Auth Log Collector',
    category: 'HOST_AGENT',
    description: 'Real-time telemetry ingestion from systemd journal and Linux authentication logs (/var/log/auth.log, /var/log/secure).',
    status: 'ACTIVE',
    eventsProcessed: '1,420 events / min',
    configPath: '/etc/sentinel-x/agent.yaml:collectors.auth',
    distributionSupport: 'Ubuntu, Debian, Kali, Parrot, Fedora',
    docUrl: 'https://www.freedesktop.org/software/systemd/man/systemd-journald.service.html'
  },
  {
    id: 'fim_collector',
    name: 'Linux File Integrity Monitoring (FIM)',
    category: 'HOST_AGENT',
    description: 'Inotify-driven continuous SHA-256 baseline verification for /etc/passwd, /etc/shadow, /etc/sudoers, and binary paths.',
    status: 'ACTIVE',
    eventsProcessed: 'Continuous hash watch',
    configPath: '/etc/sentinel-x/agent.yaml:collectors.fim',
    distributionSupport: 'All Linux kernels with inotify (2.6.13+)',
    docUrl: 'https://man7.org/linux/man-pages/man7/inotify.7.html'
  },
  {
    id: 'auditd_framework',
    name: 'Linux Audit Daemon (auditd) Hook',
    category: 'HOST_AGENT',
    description: 'Deep kernel syscall auditing for privilege elevation (execve, setuid, ptrace) and immutable audit rules.',
    status: 'READY',
    eventsProcessed: 'Syscall queue standby',
    configPath: '/etc/audit/rules.d/sentinel-x.rules',
    distributionSupport: 'Debian/Ubuntu, RHEL/CentOS/Fedora',
    docUrl: 'https://linux.die.net/man/8/auditd'
  },
  {
    id: 'zeek_network',
    name: 'Zeek Network Security Monitor',
    category: 'NETWORK',
    description: 'Passive metadata extraction for connection logs (conn.log), DNS queries (dns.log), and TLS certificates without payload decryption.',
    status: 'ACTIVE',
    eventsProcessed: 'Live TSV stream parsing',
    configPath: '/opt/zeek/logs/current/',
    distributionSupport: 'Cross-platform passive sensor',
    docUrl: 'https://zeek.org/documentation/'
  },
  {
    id: 'falco_runtime',
    name: 'Falco Cloud-Native / eBPF Runtime Security',
    category: 'RUNTIME',
    description: 'Kernel-level behavioral anomaly detection using Linux eBPF probes for namespace breakout and sensitive file access.',
    status: 'READY',
    eventsProcessed: 'JSON output socket ready',
    configPath: '/etc/falco/falco_rules.yaml',
    distributionSupport: 'Linux kernels 4.14+ with eBPF',
    docUrl: 'https://falco.org/docs/'
  },
  {
    id: 'mitre_attack',
    name: 'MITRE ATT&CK Matrix v14.1 Enterprise',
    category: 'THREAT_INTEL',
    description: 'Automated technique mapping (T1110, T1548.003, T1053.003, T1562.001) with tactic taxonomy and mitigation references.',
    status: 'ACTIVE',
    eventsProcessed: 'Indexed local catalog',
    configPath: 'backend/data/mitre_attack.json',
    distributionSupport: 'Universal / In-Memory',
    docUrl: 'https://attack.mitre.org/'
  },
  {
    id: 'malware_sandbox',
    name: 'Disposable Lab Malware Sandbox Adapter',
    category: 'RUNTIME',
    description: 'Isolated ephemeral execution environment for non-host sample detonation with strict outbound egress filtering.',
    status: 'STANDBY',
    eventsProcessed: 'Static triage active (Detonation isolated)',
    configPath: 'sentinel-sandbox:unshare --net',
    distributionSupport: 'QEMU / KVM / Docker isolated subnet',
    docUrl: 'https://www.kernel.org/doc/Documentation/virtual/kvm/'
  },
  {
    id: 'chrome_extension',
    name: 'SENTINEL-X Chrome Security Extension',
    category: 'EXTENSIONS',
    description: 'Manifest V3 analyst companion for real-time TLS validation, HTTP security header auditing, and authenticated evidence push.',
    status: 'ACTIVE',
    eventsProcessed: 'User-initiated page checks',
    configPath: 'extension/manifest.json (MV3)',
    distributionSupport: 'Chromium browsers 110+',
    docUrl: 'https://developer.chrome.com/docs/extensions/mv3/'
  }
];

export const IntegrationsPage: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => {
      setRefreshing(false);
    }, 600);
  };

  const filteredIntegrations = selectedCategory === 'ALL'
    ? INTEGRATIONS_DATA
    : INTEGRATIONS_DATA.filter(i => i.category === selectedCategory);

  const getStatusBadge = (status: IntegrationCard['status']) => {
    switch (status) {
      case 'ACTIVE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950/50 text-emerald-400 border border-emerald-800/60">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Active & Ingesting
          </span>
        );
      case 'READY':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-950/50 text-cyan-400 border border-cyan-800/60">
            <Activity className="w-3.5 h-3.5" />
            Configured & Ready
          </span>
        );
      case 'STANDBY':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-950/50 text-amber-400 border border-amber-800/60">
            <AlertTriangle className="w-3.5 h-3.5" />
            Standby / Lab-Only
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <XCircle className="w-3.5 h-3.5" />
            Disabled
          </span>
        );
    }
  };

  const getCategoryIcon = (category: IntegrationCard['category']) => {
    switch (category) {
      case 'HOST_AGENT':
        return <Terminal className="w-4 h-4 text-cyan-400" />;
      case 'NETWORK':
        return <Globe className="w-4 h-4 text-indigo-400" />;
      case 'RUNTIME':
        return <Cpu className="w-4 h-4 text-emerald-400" />;
      case 'THREAT_INTEL':
        return <Shield className="w-4 h-4 text-amber-400" />;
      case 'EXTENSIONS':
        return <Puzzle className="w-4 h-4 text-sky-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-950/60 border border-cyan-800/60 rounded-lg text-cyan-400">
              <Puzzle className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">Telemetry & Framework Integrations</h1>
              <p className="text-sm text-slate-400">
                Connected log adapters, kernel probes, threat intelligence catalogs, and network sensors
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={handleRefresh}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium rounded-lg bg-slate-900 border border-slate-800 text-slate-200 hover:bg-slate-800 hover:border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          Check Integration Health
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Adapters</span>
            <Puzzle className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-100">{INTEGRATIONS_DATA.length}</div>
          <p className="mt-1 text-xs text-slate-500">Modular sensor architecture</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Telemetry</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-emerald-400">
            {INTEGRATIONS_DATA.filter(i => i.status === 'ACTIVE').length}
          </div>
          <p className="mt-1 text-xs text-slate-500">Ingesting live security events</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Kernel / eBPF Hooks</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-cyan-400">2 Hooks</div>
          <p className="mt-1 text-xs text-slate-500">auditd & Falco runtime ready</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Cross-Distro Matrix</span>
            <Terminal className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-100">5 Distros</div>
          <p className="mt-1 text-xs text-slate-500">Ubuntu, Debian, Kali, Parrot, Fedora</p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {[
          { key: 'ALL', label: 'All Integrations' },
          { key: 'HOST_AGENT', label: 'Host & Endpoint' },
          { key: 'NETWORK', label: 'Network Sensors' },
          { key: 'RUNTIME', label: 'Runtime & Sandboxes' },
          { key: 'THREAT_INTEL', label: 'Threat Intelligence' },
          { key: 'EXTENSIONS', label: 'Browser & Desktop' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setSelectedCategory(tab.key)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition ${
              selectedCategory === tab.key
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Grid of Integrations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredIntegrations.map(integration => (
          <div 
            key={integration.id} 
            className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5 hover:border-slate-700/80 transition flex flex-col justify-between space-y-4"
          >
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                    {getCategoryIcon(integration.category)}
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">{integration.name}</h3>
                    <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">
                      {integration.category}
                    </span>
                  </div>
                </div>
                {getStatusBadge(integration.status)}
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                {integration.description}
              </p>

              <div className="space-y-2 pt-2 border-t border-slate-800/60 text-xs">
                <div className="flex justify-between items-center text-slate-400">
                  <span className="text-slate-500">Throughput / Activity:</span>
                  <span className="font-mono text-slate-300 font-medium">{integration.eventsProcessed}</span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span className="text-slate-500">Config Path:</span>
                  <span className="font-mono text-cyan-400 text-[11px] truncate max-w-xs">{integration.configPath}</span>
                </div>
                <div className="flex justify-between items-center text-slate-400">
                  <span className="text-slate-500">Supported OS:</span>
                  <span className="text-slate-300">{integration.distributionSupport}</span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800/60 flex items-center justify-between">
              <a
                href={integration.docUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition"
              >
                <span>Documentation</span>
                <ExternalLink className="w-3 h-3" />
              </a>

              <button
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/70 hover:bg-slate-800 text-xs text-slate-300 border border-slate-700/60 transition"
              >
                <Settings className="w-3 h-3 text-slate-400" />
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
