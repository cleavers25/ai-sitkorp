export type Role = "ADMIN" | "INFRA" | "SECURITY" | "OPERATOR" | "VIEWER" | "AUDITOR";
export const ROLES: Role[] = ["ADMIN", "INFRA", "SECURITY", "OPERATOR", "VIEWER", "AUDITOR"];

export type AssetStatus = "UNKNOWN" | "GREEN" | "YELLOW" | "RED";
export type Criticality = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const CRITICALITIES: Criticality[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export type ConnectivityStatus = "UNKNOWN" | "PENDING" | "OK" | "FAILED" | "HOST_KEY_MISMATCH";
export type CredentialKind = "SSH_PRIVATE_KEY" | "SSH_PASSWORD" | "API_KEY";

export type Permission =
  | "dashboard:view"
  | "asset:view"
  | "asset:manage"
  | "credential:view"
  | "credential:manage"
  | "tool:run_safe"
  | "assessment:run"
  | "finding:triage"
  | "audit:view"
  | "user:manage"
  | "ai:config"
  | "memory:manage"
  | "action:request"
  | "action:approve"
  | "backup:run"
  | "backup:download"
  | "notify:manage"
  | "integration:manage";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Me extends User {
  permissions: Permission[];
}

interface AssetBase {
  id: string;
  asset_type: "SERVER" | "WEBSITE";
  name: string;
  description: string | null;
  status: AssetStatus;
  criticality: Criticality;
  environment: string | null;
  owner: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
  last_assessed_at: string | null;
  last_assessment_id: string | null;
}

export interface Server extends AssetBase {
  hostname: string;
  ssh_port: number;
  ssh_username: string | null;
  credential_id: string | null;
  os_name: string | null;
  os_version: string | null;
  kernel: string | null;
  host_key_fingerprint: string | null;
  connectivity_status: ConnectivityStatus;
  last_connectivity_check_at: string | null;
  last_connectivity_error: string | null;
  website_count: number;
}

export interface Website extends AssetBase {
  url: string;
  domain: string;
  server_id: string | null;
  server: { id: string; name: string; hostname: string } | null;
  application: string | null;
  web_server: string | null;
  runtime: string | null;
  document_root: string | null;
}

export interface Credential {
  id: string;
  name: string;
  kind: CredentialKind;
  username: string | null;
  secret_backend: string;
  access_scope: string | null;
  description: string | null;
  public_fingerprint: string | null;
  last_rotated_at: string | null;
  created_at: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user_id: string | null;
  username: string | null;
  source_ip: string | null;
  asset_id: string | null;
  action: string;
  tool: string | null;
  command_hash: string | null;
  result: "SUCCESS" | "FAILURE" | "DENIED";
  risk_level: "SAFE" | "LOW" | "HIGH" | "CRITICAL" | null;
  approval_id: string | null;
  details: Record<string, unknown>;
}

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export type CheckStatus = "PASS" | "WARNING" | "FAIL" | "ERROR" | "SKIPPED";
export type AssessmentState = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
export type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE";
export type FindingCategory =
  | "CONNECTIVITY"
  | "SYSTEM"
  | "STORAGE"
  | "SERVICE"
  | "NETWORK"
  | "WEB"
  | "SSL"
  | "MALWARE"
  | "CONFIGURATION"
  | "VULNERABILITY";

export interface AssetRef {
  id: string;
  name: string;
  asset_type: "SERVER" | "WEBSITE";
}

export interface AssessmentSummary {
  checks?: Partial<Record<CheckStatus, number>>;
  severity?: Partial<Record<Severity, number>>;
  diff?: { new: number; persistent: number; resolved: number; reopened: number; suppressed: number };
  malware_suspected?: number;
}

export interface Assessment {
  id: string;
  asset_id: string;
  asset?: AssetRef | null;
  state: AssessmentState;
  overall_status: AssetStatus | null;
  trigger: string;
  requested_by_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  summary: AssessmentSummary;
  created_at: string;
}

export interface Check {
  id: string;
  position: number;
  check: string;
  category: FindingCategory;
  target: string | null;
  status: CheckStatus;
  severity: Severity;
  title: string;
  value: string | null;
  evidence: unknown;
  recommendation: string | null;
  duration_ms: number | null;
  finding_id: string | null;
}

export interface AssessmentDetail extends Assessment {
  asset: AssetRef;
  checks: Check[];
}

export interface Finding {
  id: string;
  asset_id: string;
  asset: AssetRef | null;
  check: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: number;
  title: string;
  description: string | null;
  target: string | null;
  evidence: unknown;
  recommendation: string | null;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  reopened_count: number;
  resolved_at: string | null;
  triaged_at: string | null;
  triage_note: string | null;
}

export interface DashboardSummary {
  total_assets: number;
  total_servers: number;
  total_websites: number;
  status_counts: Record<AssetStatus, number>;
  connectivity_counts: Record<ConnectivityStatus, number>;
  open_findings: Record<Severity, number>;
  unresolved_findings: number;
  malware_suspected: number;
  ssl_expiring: number;
  service_down: number;
  disk_critical: number;
  never_assessed: number;
  assessments_running: number;
  last_assessment_at: string | null;
  red_assets: (AssetRef & { status: AssetStatus; open_findings: number })[];
  recent_activity: AuditLog[] | null;
}

export type AIProviderKind = "OPENAI_COMPATIBLE" | "ANTHROPIC";

export interface AIProvider {
  id: string;
  name: string;
  kind: AIProviderKind;
  base_url: string | null;
  model: string;
  max_tokens: number;
  temperature: number | null;
  is_default: boolean;
  enabled: boolean;
  has_api_key: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_error: string | null;
  created_at: string;
}

export type ProposalAction = "run_assessment" | "save_memory" | "quarantine_file" | "restrict_file" | "restart_service";

export interface AIProposal {
  id: string;
  action: ProposalAction;
  asset_id?: string;
  asset_name?: string;
  asset_type?: "SERVER" | "WEBSITE";
  reason: string;
  content?: string;
  kind?: "ASSET" | "OPERATIONAL" | "SECURITY";
  path?: string;
  service?: string;
}

export interface AIMessage {
  id: string;
  position: number;
  role: "user" | "assistant";
  content: string;
  user_id: string | null;
  created_at: string;
  provider_name: string | null;
  model: string | null;
  tool_calls: { name: string; arguments: Record<string, unknown>; error: boolean; chars: number }[];
  proposals: AIProposal[];
  usage: { input_tokens?: number; output_tokens?: number };
  error: string | null;
}

export interface AIConversation {
  id: string;
  asset_id: string | null;
  asset: AssetRef | null;
  title: string;
  created_by_id: string | null;
  created_at: string;
  updated_at: string;
  message_count: number;
}

export interface AIConversationDetail extends AIConversation {
  messages: AIMessage[];
}

export type ScheduleFrequency = "HOURLY" | "DAILY" | "WEEKLY";
export type ScheduleTarget = "ALL_WEBSITES" | "ALL_SERVERS" | "ALL_ASSETS" | "SELECTED";

export type JobKind = "ASSESSMENT" | "BACKUP";

export interface ScheduleRun {
  id: string;
  schedule_id: string | null;
  schedule_name: string;
  job: JobKind;
  trigger: string;
  state: "RUNNING" | "COMPLETED" | "FAILED";
  started_at: string;
  finished_at: string | null;
  queued: number;
  skipped: number;
  summary: {
    status?: Partial<Record<AssetStatus, number>>;
    new_findings?: number;
    resolved_findings?: number;
    worse?: { asset: string; from: string; to: string }[];
    failed?: (string | null)[];
    assessments?: number;
    backups?: number;
    succeeded?: number;
    verified?: number;
    total_bytes?: number;
  };
  ai_report: string | null;
  ai_state: "PENDING" | "DONE" | "FAILED" | "SKIPPED" | null;
  ai_error: string | null;
  ai_usage: { input_tokens?: number; output_tokens?: number; model?: string };
}

export interface Schedule {
  id: string;
  name: string;
  enabled: boolean;
  job: JobKind;
  target: ScheduleTarget;
  asset_ids: string[];
  frequency: ScheduleFrequency;
  time_of_day: string;
  weekdays: number[];
  minute: number;
  timezone: string;
  ai_report: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  created_at: string;
  last_run: ScheduleRun | null;
}

export type ChannelKind = "EMAIL" | "WEBHOOK" | "TELEGRAM";

export interface NotificationChannel {
  id: string;
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  config: Record<string, unknown>;
  has_secret: boolean;
  events: string[];
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_error: string | null;
}

export interface NotificationEvent {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  body: string;
  asset_id: string | null;
  link: string | null;
  created_at: string;
}
