export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type IncidentStatus = 'New' | 'Triaged' | 'Investigating' | 'Contained' | 'Resolved' | 'Closed';

export interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string;
  is_active: boolean;
  role: {
    id: string;
    name: string;
    permissions: string;
  };
}

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  mac_address?: string;
  os_distro: string;
  os_version: string;
  kernel_version?: string;
  architecture: string;
  agent_version: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  is_isolated: boolean;
  first_seen: string;
  last_heartbeat: string;
  collectors?: CollectorHealth[];
}

export interface CollectorHealth {
  id: string;
  collector_name: string;
  status: 'HEALTHY' | 'WARNING' | 'FAILED' | 'DISABLED';
  events_collected: number;
  errors_count: number;
  last_error_message?: string;
  last_heartbeat: string;
}

export interface NormalizedEvent {
  id: string;
  event_id: string;
  timestamp: string;
  ingested_at: string;
  host_id: string;
  source: string;
  event_category: string;
  severity: Severity;
  confidence: number;
  account_user?: string;
  account_uid?: number;
  target_user?: string;
  process_name?: string;
  process_pid?: number;
  process_parent_pid?: number;
  process_cmdline?: string;
  file_path?: string;
  file_sha256?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  evidence_hash: string;
  raw_payload: string;
}

export interface Incident {
  id: string;
  incident_number: string;
  title: string;
  description: string;
  status: IncidentStatus;
  severity: Severity;
  confidence: number;
  rule_id?: string;
  host_id: string;
  affected_account?: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  analyst_notes: string;
  resolution_notes?: string;
  event_count: number;
  response_actions: ResponseAction[];
  events?: NormalizedEvent[];
}

export interface ResponseAction {
  id: string;
  incident_id: string;
  action_type: string;
  parameters: string;
  requested_by: string;
  approved_by?: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'EXECUTED' | 'FAILED';
  outcome_details?: string;
  execution_error?: string;
  created_at: string;
  executed_at?: string;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  base_confidence: number;
  mitre_tactic?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  event_category: string;
  window_seconds: number;
  threshold: number;
  is_active: boolean;
  version: string;
}

export interface AssessmentProject {
  id: string;
  project_code: string;
  name: string;
  description: string;
  created_at: string;
  created_by_id: string;
  target_scopes: TargetScope[];
  findings: VulnerabilityFinding[];
}

export interface TargetScope {
  id: string;
  project_id: string;
  target: string;
  target_type: string;
  owner_organization: string;
  authorization_reference: string;
  approved_by: string;
  valid_from: string;
  expires_at: string;
  allowed_methods: string;
  excluded_targets: string;
  rate_limit_rps: number;
  is_active: boolean;
}

export interface VulnerabilityFinding {
  id: string;
  finding_id: string;
  project_id: string;
  title: string;
  target: string;
  severity: Severity;
  cvss_score: number;
  confidence: number;
  owasp_category?: string;
  cwe_id?: string;
  description: string;
  evidence_data?: string;
  remediation: string;
  discovered_at: string;
}

export interface MalwareSample {
  id: string;
  sample_id: string;
  filename: string;
  file_size_bytes: number;
  mime_type: string;
  file_format: string;
  sha256_hash: string;
  sha1_hash?: string;
  md5_hash?: string;
  shannon_entropy: number;
  uploaded_at: string;
  uploader_id: string;
  sandbox_status: string;
  is_disarmed: boolean;
  static_analysis?: StaticAnalysis;
}

export interface StaticAnalysis {
  id: string;
  threat_verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNCERTAIN';
  risk_score: number;
  confidence: number;
  extracted_strings_json: string;
  iocs_json: string;
  pe_elf_metadata_json: string;
  yara_rule_matches_json: string;
  analysis_notes?: string;
  analyzed_at: string;
}

export interface TriageSummaryResponse {
  total_samples: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  uncertain_count: number;
  recent_samples: MalwareSample[];
}

export interface ForensicCase {
  id: string;
  case_number: string;
  title: string;
  description: string;
  status: 'ACTIVE' | 'ARCHIVED' | 'CLOSED';
  priority: Severity;
  lead_analyst_id: string;
  created_at: string;
  closed_at?: string;
  summary_findings?: string;
  evidence_items: EvidenceItem[];
  timeline_items: TimelineItem[];
  notes: ForensicNote[];
}

export interface EvidenceItem {
  id: string;
  evidence_number: string;
  name: string;
  source_description: string;
  original_filename: string;
  sha256_hash: string;
  md5_hash?: string;
  file_size_bytes: number;
  mime_type: string;
  is_read_only: boolean;
  is_derived_artifact: boolean;
  acquired_at: string;
  acquired_by_id: string;
  custody_records?: ChainOfCustody[];
}

export interface ChainOfCustody {
  id: string;
  evidence_id: string;
  analyst_id: string;
  action: string;
  timestamp: string;
  verified_hash: string;
  hash_matched: boolean;
  notes?: string;
}

export interface TimelineItem {
  id: string;
  case_id: string;
  timestamp: string;
  title: string;
  description: string;
  source_type: string;
  evidence_id?: string;
  created_at: string;
}

export interface ForensicNote {
  id: string;
  case_id: string;
  analyst_id: string;
  title: string;
  content: string;
  created_at: string;
}

export interface NetworkObservation {
  id: string;
  timestamp: string;
  host_id: string;
  source_type: string;
  protocol: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  service?: string;
  duration_seconds: number;
  bytes_orig: number;
  bytes_resp: number;
  dns_query?: string;
  is_outbound: boolean;
  is_anomalous: boolean;
  anomaly_score: number;
  anomaly_reason?: string;
}

export interface AIInvestigationReport {
  incident_id: string;
  executive_summary: string;
  detection_rationale: string;
  cited_event_ids: string[];
  missing_evidence_identified: string[];
  safe_investigative_steps: {
    step_number: number;
    action_description: string;
    rationale: string;
    tool_or_command: string;
    safety_precaution: string;
  }[];
  defensive_references: {
    title: string;
    source: string;
    url_or_reference: string;
    applicability: string;
  }[];
  prompt_injection_defense_applied: boolean;
  secrets_redacted_count: number;
  ai_provider: string;
}

export interface SecurityReport {
  id: string;
  report_number: string;
  title: string;
  report_type: string;
  generated_by_id: string;
  created_at: string;
  content_markdown: string;
  content_json: string;
}

export interface SystemHealth {
  status: string;
  version: string;
  environment: string;
  database_connected: boolean;
  active_hosts: number;
  open_incidents: number;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor_id?: string;
  actor_username: string;
  ip_address?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
  details_json: string;
}

export interface IntegrationInfo {
  id: string;
  name: string;
  type: string;
  status: 'ACTIVE' | 'WARNING' | 'INACTIVE' | 'NOT_CONFIGURED';
  description: string;
  version?: string;
  endpoint_or_path?: string;
  events_ingested: number;
  last_activity: string;
  config_options: Record<string, any>;
}

