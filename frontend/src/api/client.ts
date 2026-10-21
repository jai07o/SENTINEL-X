const API_BASE = '/api/v1';

export class ApiClient {
  private static getToken(): string | null {
    return localStorage.getItem('sx_access_token');
  }

  public static setToken(token: string): void {
    localStorage.setItem('sx_access_token', token);
  }

  public static clearToken(): void {
    localStorage.removeItem('sx_access_token');
  }

  private static async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers = new Headers(options.headers || {});

    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMessage = `API Error: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errorMessage = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch {
        // Fallback to text status
      }
      throw new Error(errorMessage);
    }

    return response.json();
  }

  // Health
  public static async getHealth() {
    return this.request<any>('/health');
  }

  // Auth
  public static async login(formData: FormData) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Login failed');
    }
    return res.json();
  }

  public static async getMe() {
    return this.request<any>('/auth/me');
  }

  public static async getApiKeys() {
    return this.request<any[]>('/auth/api-keys');
  }

  public static async createApiKey(name: string, days: number = 30) {
    return this.request<any>('/auth/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name, expires_days: days }),
    });
  }

  // Hosts
  public static async getHosts() {
    return this.request<any[]>('/hosts/');
  }

  public static async getHost(id: string) {
    return this.request<any>(`/hosts/${id}`);
  }

  // Events
  public static async getEvents(params: { page?: number; page_size?: number; category?: string; severity?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.page_size) query.set('page_size', params.page_size.toString());
    if (params.category) query.set('category', params.category);
    if (params.severity) query.set('severity', params.severity);
    return this.request<any>(`/events/?${query.toString()}`);
  }

  public static async getEvent(eventId: string) {
    return this.request<any>(`/events/${eventId}`);
  }

  // Incidents
  public static async getIncidents(params: { page?: number; page_size?: number; status?: string; severity?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.page_size) query.set('page_size', params.page_size.toString());
    if (params.status) query.set('status', params.status);
    if (params.severity) query.set('severity', params.severity);
    return this.request<any>(`/incidents/?${query.toString()}`);
  }

  public static async getIncident(id: string) {
    return this.request<any>(`/incidents/${id}`);
  }

  public static async updateIncidentStatus(id: string, update: { status?: string; resolution_notes?: string; assigned_to?: string }) {
    return this.request<any>(`/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(update),
    });
  }

  public static async addIncidentNote(id: string, text: string) {
    return this.request<any>(`/incidents/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ author: 'analyst', text }),
    });
  }

  public static async requestContainmentAction(id: string, actionType: string, parameters: any = {}) {
    return this.request<any>(`/incidents/${id}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action_type: actionType, parameters }),
    });
  }

  public static async approveContainmentAction(incidentId: string, actionId: string) {
    return this.request<any>(`/incidents/${incidentId}/actions/${actionId}/approve`, {
      method: 'POST',
    });
  }

  public static async exportIncidentDossier(id: string) {
    return this.request<any>(`/incidents/${id}/export`);
  }

  // Detection Rules & EWCC
  public static async getDetectionRules() {
    return this.request<any[]>('/detection/rules');
  }

  public static async evaluateEWCC(events: any[], baseConfidence: number = 0.85, windowSeconds: number = 60, osDistro: string = 'ubuntu') {
    return this.request<any>(`/detection/evaluate-ewcc?base_confidence=${baseConfidence}&window_seconds=${windowSeconds}&os_distro=${osDistro}`, {
      method: 'POST',
      body: JSON.stringify(events),
    });
  }

  // Assessments
  public static async getAssessmentProjects() {
    return this.request<any[]>('/assessments/projects');
  }

  public static async createAssessmentProject(project: { name: string; description: string; target_scopes?: any[] }) {
    return this.request<any>('/assessments/projects', {
      method: 'POST',
      body: JSON.stringify(project),
    });
  }

  public static async addTargetScope(projectId: string, scope: any) {
    return this.request<any>(`/assessments/projects/${projectId}/scopes`, {
      method: 'POST',
      body: JSON.stringify(scope),
    });
  }

  public static async scanHeaders(projectId: string, target: string) {
    return this.request<any[]>(`/assessments/projects/${projectId}/scan-headers?target=${encodeURIComponent(target)}`, {
      method: 'POST',
    });
  }

  public static async scanTLS(projectId: string, hostname: string, port: number = 443) {
    return this.request<any>(`/assessments/projects/${projectId}/scan-tls?hostname=${encodeURIComponent(hostname)}&port=${port}`, {
      method: 'POST',
    });
  }

  // Malware
  public static async getMalwareSamples() {
    return this.request<any[]>('/malware/samples');
  }

  public static async getMalwareSample(id: string) {
    return this.request<any>(`/malware/samples/${id}`);
  }

  public static async getMalwareSummary() {
    return this.request<any>('/malware/summary');
  }

  public static async uploadMalwareSample(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    return this.request<any>('/malware/upload', {
      method: 'POST',
      body: formData,
    });
  }

  // Forensics
  public static async getForensicCases() {
    return this.request<any[]>('/forensics/cases');
  }

  public static async getForensicCase(id: string) {
    return this.request<any>(`/forensics/cases/${id}`);
  }

  public static async createForensicCase(caseData: { title: string; description: string; priority: string }) {
    return this.request<any>('/forensics/cases', {
      method: 'POST',
      body: JSON.stringify(caseData),
    });
  }

  public static async intakeEvidence(caseId: string, name: string, sourceDesc: string, file: File) {
    const formData = new FormData();
    formData.append('name', name);
    formData.append('source_description', sourceDesc);
    formData.append('file', file);
    return this.request<any>(`/forensics/cases/${caseId}/evidence`, {
      method: 'POST',
      body: formData,
    });
  }

  public static async verifyEvidenceHash(evidenceId: string) {
    return this.request<any>(`/forensics/evidence/${evidenceId}/verify-hash`);
  }

  // Network
  public static async getNetworkObservations(anomalousOnly: boolean = false) {
    return this.request<any[]>(`/network/observations?anomalous_only=${anomalousOnly}`);
  }

  public static async getNetworkAnomalies() {
    return this.request<any>('/network/anomalies');
  }

  // AI
  public static async explainIncident(incidentId: string, audience: string = 'security_analyst') {
    return this.request<any>('/ai/explain-incident', {
      method: 'POST',
      body: JSON.stringify({ incident_id: incidentId, target_audience: audience }),
    });
  }

  // Reports
  public static async getReports() {
    return this.request<any[]>('/reports/');
  }

  public static async generateReport(title: string, reportType: string) {
    return this.request<any>('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ title, report_type: reportType }),
    });
  }

  public static async getReportContent(reportId: string) {
    return this.request<any>(`/reports/${reportId}`);
  }

  // Audit
  public static async getAuditLogs() {
    return this.request<any[]>('/audit/');
  }

  // Connected Sockets & C2 Virus Monitor
  public static async getSockets(externalOnly: boolean = false, highRiskOnly: boolean = false, limit: number = 150) {
    return this.request<{ summary: any; sockets: any[] }>(`/sockets/?external_only=${externalOnly}&high_risk_only=${highRiskOnly}&limit=${limit}`);
  }

  public static async killSocketProcess(pid: number) {
    return this.request<any>('/sockets/kill-process', {
      method: 'POST',
      body: JSON.stringify({ pid }),
    });
  }

  // Privacy & Camera Sentinel
  public static async getCameraStatus() {
    return this.request<{ summary: any; laptop_webcam_events: any[]; mobile_telemetry_events: any[]; all_events: any[] }>('/privacy/camera-status');
  }

  public static async ingestMobilePrivacyTelemetry(data: any) {
    return this.request<any>('/privacy/mobile-telemetry', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  public static async terminatePrivacyApp(pid: number) {
    return this.request<any>('/privacy/terminate-app', {
      method: 'POST',
      body: JSON.stringify({ pid }),
    });
  }

  // Background Processes & Applications
  public static async getProcesses(backgroundOnly: boolean = false, limit: number = 200) {
    return this.request<{ summary: any; processes: any[] }>(`/processes/?background_only=${backgroundOnly}&limit=${limit}`);
  }

  public static async killProcess(pid: number) {
    return this.request<any>('/processes/kill', {
      method: 'POST',
      body: JSON.stringify({ pid }),
    });
  }

  // Workspace & Local Folder Scanner
  public static async scanWorkspaceFolder(directoryPath?: string, maxFiles: number = 500) {
    return this.request<{ summary: any; files: any[] }>('/scanner/scan-workspace', {
      method: 'POST',
      body: JSON.stringify({ directory_path: directoryPath, max_files: maxFiles }),
    });
  }

  public static async quickScanWorkspace(limit: number = 200) {
    return this.request<{ summary: any; files: any[] }>(`/scanner/quick-scan?limit=${limit}`);
  }

  // Omni Threat Scanner (Links, QR Codes, Pictures, Files)
  public static async scanLink(url: string) {
    return this.request<any>('/omniscan/link', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  public static async scanDeepLink(url: string) {
    return this.request<any>('/omniscan/deep-scan', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  public static async startAutonomousSentinel() {
    return this.request<any>('/omniscan/autonomous-sentinel/start', {
      method: 'POST',
    });
  }

  public static async stopAutonomousSentinel() {
    return this.request<any>('/omniscan/autonomous-sentinel/stop', {
      method: 'POST',
    });
  }

  public static async getAutonomousSentinelStatus() {
    return this.request<any>('/omniscan/autonomous-sentinel/status');
  }

  public static async scanQrCode(formData: FormData) {
    return this.request<any>('/omniscan/qr', {
      method: 'POST',
      body: formData,
    });
  }

  public static async scanPicture(formData: FormData) {
    return this.request<any>('/omniscan/picture', {
      method: 'POST',
      body: formData,
    });
  }

  public static async scanFile(formData: FormData) {
    return this.request<any>('/omniscan/file', {
      method: 'POST',
      body: formData,
    });
  }

  public static async getOmniScanSamples() {
    return this.request<any>('/omniscan/samples');
  }

  // =========================================================================
  // UNIVERSAL DATA DELETION & STORAGE PURGE
  // =========================================================================
  public static async deleteIncident(id: string) {
    return this.request<any>(`/incidents/${id}`, { method: 'DELETE' });
  }

  public static async deleteEvent(id: string) {
    return this.request<any>(`/events/${id}`, { method: 'DELETE' });
  }

  public static async purgeEvents() {
    return this.request<any>('/events', { method: 'DELETE' });
  }

  public static async deleteHost(id: string) {
    return this.request<any>(`/hosts/${id}`, { method: 'DELETE' });
  }

  public static async deleteMalwareSample(id: string) {
    return this.request<any>(`/malware/samples/${id}`, { method: 'DELETE' });
  }

  public static async deleteForensicCase(id: string) {
    return this.request<any>(`/forensics/cases/${id}`, { method: 'DELETE' });
  }

  public static async deleteEvidenceItem(id: string) {
    return this.request<any>(`/forensics/evidence/${id}`, { method: 'DELETE' });
  }

  public static async deleteReport(id: string) {
    return this.request<any>(`/reports/${id}`, { method: 'DELETE' });
  }

  public static async getDataStats() {
    return this.request<any>('/data-management/stats');
  }

  public static async purgeDataCategory(category: string, confirm: boolean = true) {
    return this.request<any>('/data-management/purge', {
      method: 'POST',
      body: JSON.stringify({ category, confirm }),
    });
  }

  public static async deleteEntity(entityType: string, entityId: string) {
    return this.request<any>(`/data-management/entity/${entityType}/${entityId}`, {
      method: 'DELETE',
    });
  }

  // =========================================================================
  // CABLE-CONNECTED HARDWARE DEVICES & PORT QUARANTINE
  // =========================================================================
  public static async getHardwareDevices() {
    return this.request<any>('/hardware-ports/devices');
  }

  public static async getHardwarePortStatus() {
    return this.request<any>('/hardware-ports/status');
  }

  public static async scanHardwarePort(targetPath: string, deviceId?: string, autoQuarantine: boolean = true) {
    return this.request<any>('/hardware-ports/scan', {
      method: 'POST',
      body: JSON.stringify({ target_path: targetPath, device_id: deviceId, auto_quarantine: autoQuarantine }),
    });
  }

  public static async quarantineHardwarePort(targetOrDevice: string, reason: string = "Manual Security Analyst Quarantine") {
    return this.request<any>('/hardware-ports/quarantine', {
      method: 'POST',
      body: JSON.stringify({ target_or_device: targetOrDevice, reason }),
    });
  }

  public static async releaseHardwarePort(targetOrDevice: string) {
    return this.request<any>('/hardware-ports/release', {
      method: 'POST',
      body: JSON.stringify({ target_or_device: targetOrDevice }),
    });
  }

  public static async toggleAutoQuarantine(enabled: boolean) {
    return this.request<any>('/hardware-ports/toggle-auto-quarantine', {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  }

  public static async getUsbImmunizationStatus() {
    return this.request<any>('/hardware-ports/immunization');
  }

  public static async applyHostUsbImmunization() {
    return this.request<any>('/hardware-ports/immunize-host', {
      method: 'POST',
    });
  }

  public static async vaccinateDrive(driveLetter: string) {
    return this.request<any>('/hardware-ports/vaccinate-drive', {
      method: 'POST',
      body: JSON.stringify({ drive_letter: driveLetter }),
    });
  }

  public static async getBadUsbStatus() {
    return this.request<any>('/hardware-ports/badusb');
  }

  public static async interceptDriveInsertion(driveLetter: string, deviceId?: string) {
    return this.request<any>('/hardware-ports/intercept', {
      method: 'POST',
      body: JSON.stringify({ drive_letter: driveLetter, device_id: deviceId }),
    });
  }

  // Platform Self-Defense & Security Armor Posture
  public static async getSecurityPosture() {
    return this.request<any>('/health/security-posture');
  }

  public static async getSelfIntegrity() {
    return this.request<any>('/health/integrity');
  }

  public static async reanchorSelfIntegrity() {
    return this.request<any>('/health/integrity/reanchor', {
      method: 'POST',
    });
  }
}



