import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { WebSocketProvider } from './context/WebSocketContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';

// Pages
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { LiveEventStreamPage } from './pages/LiveEventStreamPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { IncidentInvestigationPage } from './pages/IncidentInvestigationPage';
import { HostInventoryPage } from './pages/HostInventoryPage';
import { EndpointHealthPage } from './pages/EndpointHealthPage';
import { NetworkMonitoringPage } from './pages/NetworkMonitoringPage';
import { AssessmentsPage } from './pages/AssessmentsPage';
import { VulnerabilityFindingsPage } from './pages/VulnerabilityFindingsPage';
import { MalwareAnalysisPage } from './pages/MalwareAnalysisPage';
import { ForensicCasesPage } from './pages/ForensicCasesPage';
import { EvidenceViewerPage } from './pages/EvidenceViewerPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { DetectionRulesPage } from './pages/DetectionRulesPage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LiveSocketsPage } from './pages/LiveSocketsPage';
import { PrivacyCameraPage } from './pages/PrivacyCameraPage';
import { BackgroundProcessesPage } from './pages/BackgroundProcessesPage';
import { FolderScannerPage } from './pages/FolderScannerPage';
import { OmniScanPage } from './pages/OmniScanPage';
import { HardwarePortsPage } from './pages/HardwarePortsPage';
import { Total360SafeguardPage } from './pages/Total360SafeguardPage';
import { ActiveSystemPage } from './pages/ActiveSystemPage';

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
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
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
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/*" element={<ProtectedLayout />} />
          </Routes>
        </WebSocketProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
