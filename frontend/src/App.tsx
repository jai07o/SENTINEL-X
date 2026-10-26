import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { WebSocketProvider } from './context/WebSocketContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { NativeAppTitleBar } from './components/layout/NativeAppTitleBar';

// Lazy-loaded pages for lightning-fast initial load & code splitting
const LoginPage = lazy(() => import('./pages/LoginPage').then((m) => ({ default: m.LoginPage })));
const OverviewPage = lazy(() => import('./pages/OverviewPage').then((m) => ({ default: m.OverviewPage })));
const LiveEventStreamPage = lazy(() => import('./pages/LiveEventStreamPage').then((m) => ({ default: m.LiveEventStreamPage })));
const IncidentsPage = lazy(() => import('./pages/IncidentsPage').then((m) => ({ default: m.IncidentsPage })));
const IncidentInvestigationPage = lazy(() => import('./pages/IncidentInvestigationPage').then((m) => ({ default: m.IncidentInvestigationPage })));
const HostInventoryPage = lazy(() => import('./pages/HostInventoryPage').then((m) => ({ default: m.HostInventoryPage })));
const EndpointHealthPage = lazy(() => import('./pages/EndpointHealthPage').then((m) => ({ default: m.EndpointHealthPage })));
const NetworkMonitoringPage = lazy(() => import('./pages/NetworkMonitoringPage').then((m) => ({ default: m.NetworkMonitoringPage })));
const AssessmentsPage = lazy(() => import('./pages/AssessmentsPage').then((m) => ({ default: m.AssessmentsPage })));
const VulnerabilityFindingsPage = lazy(() => import('./pages/VulnerabilityFindingsPage').then((m) => ({ default: m.VulnerabilityFindingsPage })));
const MalwareAnalysisPage = lazy(() => import('./pages/MalwareAnalysisPage').then((m) => ({ default: m.MalwareAnalysisPage })));
const ForensicCasesPage = lazy(() => import('./pages/ForensicCasesPage').then((m) => ({ default: m.ForensicCasesPage })));
const EvidenceViewerPage = lazy(() => import('./pages/EvidenceViewerPage').then((m) => ({ default: m.EvidenceViewerPage })));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage').then((m) => ({ default: m.ThreatIntelPage })));
const DetectionRulesPage = lazy(() => import('./pages/DetectionRulesPage').then((m) => ({ default: m.DetectionRulesPage })));
const ReportsPage = lazy(() => import('./pages/ReportsPage').then((m) => ({ default: m.ReportsPage })));
const AuditLogsPage = lazy(() => import('./pages/AuditLogsPage').then((m) => ({ default: m.AuditLogsPage })));
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage').then((m) => ({ default: m.IntegrationsPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const LiveSocketsPage = lazy(() => import('./pages/LiveSocketsPage').then((m) => ({ default: m.LiveSocketsPage })));
const PrivacyCameraPage = lazy(() => import('./pages/PrivacyCameraPage').then((m) => ({ default: m.PrivacyCameraPage })));
const BackgroundProcessesPage = lazy(() => import('./pages/BackgroundProcessesPage').then((m) => ({ default: m.BackgroundProcessesPage })));
const FolderScannerPage = lazy(() => import('./pages/FolderScannerPage').then((m) => ({ default: m.FolderScannerPage })));
const OmniScanPage = lazy(() => import('./pages/OmniScanPage').then((m) => ({ default: m.OmniScanPage })));
const HardwarePortsPage = lazy(() => import('./pages/HardwarePortsPage').then((m) => ({ default: m.HardwarePortsPage })));
const Total360SafeguardPage = lazy(() => import('./pages/Total360SafeguardPage').then((m) => ({ default: m.Total360SafeguardPage })));
const ActiveSystemPage = lazy(() => import('./pages/ActiveSystemPage').then((m) => ({ default: m.ActiveSystemPage })));
const AITrainingHubPage = lazy(() => import('./pages/AITrainingHubPage').then((m) => ({ default: m.AITrainingHubPage })));

const PageLoadingFallback: React.FC = () => (
  <div className="flex-1 flex flex-col items-center justify-center min-h-[350px] space-y-3">
    <div className="w-8 h-8 border-2 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin" />
    <span className="text-[11px] font-mono text-cyan-400/70 tracking-widest uppercase">Initializing View...</span>
  </div>
);

const ProtectedLayout: React.FC<{ children?: React.ReactNode }> = () => {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-graphite-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <div className="text-xs font-mono text-cyan-400 tracking-wider">INITIALIZING SENTINEL-X SOC INTERFACE...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen bg-graphite-950 text-slate-100 flex flex-col selection:bg-cyan-500/20 selection:text-cyan-200">
      <NativeAppTitleBar />
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          <Suspense fallback={<PageLoadingFallback />}>
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/ai-training" element={<AITrainingHubPage />} />
              <Route path="/active-system" element={<ActiveSystemPage />} />
              <Route path="/total-360" element={<Total360SafeguardPage />} />
              <Route path="/omniscan" element={<OmniScanPage />} />
              <Route path="/hardware-ports" element={<HardwarePortsPage />} />
              <Route path="/sockets" element={<LiveSocketsPage />} />
              <Route path="/privacy-camera" element={<PrivacyCameraPage />} />
              <Route path="/processes" element={<BackgroundProcessesPage />} />
              <Route path="/folder-scanner" element={<FolderScannerPage />} />

              <Route path="/live-events" element={<LiveEventStreamPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/investigation" element={<IncidentInvestigationPage />} />
              <Route path="/investigation/:id" element={<IncidentInvestigationPage />} />
              <Route path="/hosts" element={<HostInventoryPage />} />
              <Route path="/endpoint-health" element={<EndpointHealthPage />} />
              <Route path="/network" element={<NetworkMonitoringPage />} />
              <Route path="/assessments" element={<AssessmentsPage />} />
              <Route path="/vulnerabilities" element={<VulnerabilityFindingsPage />} />
              <Route path="/malware" element={<MalwareAnalysisPage />} />
              <Route path="/forensics" element={<ForensicCasesPage />} />
              <Route path="/evidence" element={<EvidenceViewerPage />} />
              <Route path="/threat-intel" element={<ThreatIntelPage />} />
              <Route path="/detection-rules" element={<DetectionRulesPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/audit" element={<AuditLogsPage />} />
              <Route path="/integrations" element={<IntegrationsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <WebSocketProvider>
          <Suspense fallback={<PageLoadingFallback />}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/*" element={<ProtectedLayout />} />
            </Routes>
          </Suspense>
        </WebSocketProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
