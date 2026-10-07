import { cn } from "@/lib/utils";
import type {
  AssessmentState,
  AssetStatus,
  CheckStatus,
  ConnectivityStatus,
  Criticality,
  FindingStatus,
  Severity,
} from "@/lib/types";

const pill = "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset";

const STATUS: Record<AssetStatus, { label: string; cls: string; dot: string }> = {
  GREEN: { label: "GREEN", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-950 dark:text-emerald-300", dot: "bg-emerald-500" },
  YELLOW: { label: "YELLOW", cls: "bg-amber-50 text-amber-800 ring-amber-600/25 dark:bg-amber-950 dark:text-amber-300", dot: "bg-amber-500" },
  RED: { label: "RED", cls: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300", dot: "bg-red-500" },
  UNKNOWN: { label: "Belum dinilai", cls: "bg-muted text-muted-foreground ring-border", dot: "bg-muted-foreground/50" },
};

export function StatusBadge({ status }: { status: AssetStatus }) {
  const s = STATUS[status];
  return (
    <span className={cn(pill, s.cls)}>
      <span className={cn("size-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}

const CONN: Record<ConnectivityStatus, { label: string; cls: string }> = {
  OK: { label: "Terhubung", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-950 dark:text-emerald-300" },
  FAILED: { label: "Gagal", cls: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300" },
  HOST_KEY_MISMATCH: { label: "Host key berubah", cls: "bg-red-100 text-red-800 ring-red-700/30 dark:bg-red-950 dark:text-red-200" },
  PENDING: { label: "Memeriksa…", cls: "bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-950 dark:text-sky-300" },
  UNKNOWN: { label: "Belum dites", cls: "bg-muted text-muted-foreground ring-border" },
};

export function ConnectivityBadge({ status }: { status: ConnectivityStatus }) {
  const s = CONN[status];
  return <span className={cn(pill, s.cls)}>{s.label}</span>;
}

const CRIT: Record<Criticality, string> = {
  LOW: "text-muted-foreground",
  MEDIUM: "text-foreground",
  HIGH: "text-amber-700 dark:text-amber-400 font-medium",
  CRITICAL: "text-red-700 dark:text-red-400 font-semibold",
};

export function CriticalityText({ value }: { value: Criticality }) {
  return <span className={cn("text-xs", CRIT[value])}>{value}</span>;
}

const SEVERITY_CLS: Record<Severity, string> = {
  CRITICAL: "bg-red-900 text-white ring-red-900 dark:bg-red-700",
  HIGH: "bg-red-600 text-white ring-red-600",
  MEDIUM: "bg-amber-400 text-amber-950 ring-amber-500",
  LOW: "bg-amber-100 text-amber-900 ring-amber-300 dark:bg-amber-950 dark:text-amber-200",
  INFO: "bg-muted text-muted-foreground ring-border",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={cn(pill, "font-semibold", SEVERITY_CLS[severity])}>{severity}</span>;
}

const CHECK_CLS: Record<CheckStatus, { label: string; cls: string }> = {
  PASS: { label: "PASS", cls: "text-emerald-700 dark:text-emerald-400" },
  WARNING: { label: "WARNING", cls: "text-amber-700 dark:text-amber-400" },
  FAIL: { label: "FAIL", cls: "text-red-700 dark:text-red-400" },
  ERROR: { label: "ERROR", cls: "text-fuchsia-700 dark:text-fuchsia-400" },
  SKIPPED: { label: "SKIPPED", cls: "text-muted-foreground" },
};

export function CheckStatusText({ status }: { status: CheckStatus }) {
  const s = CHECK_CLS[status];
  return <span className={cn("text-xs font-semibold", s.cls)}>{s.label}</span>;
}

const FINDING_LABEL: Record<FindingStatus, { label: string; cls: string }> = {
  OPEN: { label: "Open", cls: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300" },
  ACKNOWLEDGED: { label: "Acknowledged", cls: "bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-950 dark:text-sky-300" },
  RESOLVED: { label: "Resolved", cls: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-950 dark:text-emerald-300" },
  FALSE_POSITIVE: { label: "False positive", cls: "bg-muted text-muted-foreground ring-border" },
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  const s = FINDING_LABEL[status];
  return <span className={cn(pill, s.cls)}>{s.label}</span>;
}

const STATE_LABEL: Record<AssessmentState, { label: string; cls: string }> = {
  QUEUED: { label: "Antre", cls: "bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-950 dark:text-sky-300" },
  RUNNING: { label: "Berjalan…", cls: "bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-950 dark:text-sky-300" },
  COMPLETED: { label: "Selesai", cls: "bg-muted text-foreground ring-border" },
  FAILED: { label: "Gagal", cls: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300" },
};

export function AssessmentStateBadge({ state }: { state: AssessmentState }) {
  const s = STATE_LABEL[state];
  return <span className={cn(pill, s.cls)}>{s.label}</span>;
}
