"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { AIReport, RunSummary } from "@/components/ai-report";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { ACTION_LABELS, formatDateTime } from "@/lib/format";
import type { AssetStatus, DashboardSummary, Page, ScheduleRun } from "@/lib/types";
import { cn } from "@/lib/utils";

function Stat({ label, value, href, alert }: { label: string; value: number; href?: string; alert?: boolean }) {
  const body = (
    <div className={cn("h-full rounded-xl border bg-card p-4 transition-colors", href && "hover:bg-muted/50",
      alert && value > 0 && "border-red-300 bg-red-50/60 dark:border-red-900 dark:bg-red-950/40")}>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn("mt-1 text-2xl font-semibold tabular-nums", alert && value > 0 && "text-red-700 dark:text-red-400")}>
        {value}
      </p>
    </div>
  );
  return href ? <Link href={href}>{body}</Link> : body;
}

const STATUS_BAR: { key: AssetStatus; label: string; cls: string }[] = [
  { key: "GREEN", label: "Green", cls: "bg-emerald-500" },
  { key: "YELLOW", label: "Yellow", cls: "bg-amber-400" },
  { key: "RED", label: "Red", cls: "bg-red-500" },
  { key: "UNKNOWN", label: "Belum dinilai", cls: "bg-muted-foreground/30" },
];

export default function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardSummary>("/dashboard/summary"),
    refetchInterval: 30_000,
  });

  const latestReport = useQuery({
    queryKey: ["schedule-runs", "latest-report"],
    queryFn: () => api<Page<ScheduleRun>>("/schedule-runs?with_report=true&limit=1"),
    refetchInterval: 60_000,
  });
  const report = latestReport.data?.items[0];

  if (isLoading || !data) return <p className="text-sm text-muted-foreground">Memuat dashboard…</p>;

  const total = data.total_assets || 1;
  const critHigh = data.open_findings.CRITICAL + data.open_findings.HIGH;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={`Assessment terakhir: ${formatDateTime(data.last_assessment_at)}${
          data.assessments_running ? ` · ${data.assessments_running} sedang berjalan` : ""}`}
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Website" value={data.total_websites} href="/websites" />
        <Stat label="Server" value={data.total_servers} href="/servers" />
        <Stat label="Green" value={data.status_counts.GREEN} />
        <Stat label="Yellow" value={data.status_counts.YELLOW} />
        <Stat label="Red" value={data.status_counts.RED} alert />
        <Stat label="Belum di-assess" value={data.never_assessed} href="/assessments" />
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Temuan critical/high" value={critHigh} href="/findings?severity=CRITICAL,HIGH" alert />
        <Stat label="Diduga malware" value={data.malware_suspected} href="/findings?category=MALWARE" alert />
        <Stat label="Service/website down" value={data.service_down} href="/findings?category=WEB" alert />
        <Stat label="SSL bermasalah/kedaluwarsa" value={data.ssl_expiring} href="/findings?category=SSL" />
        <Stat label="Disk kritis" value={data.disk_critical} href="/findings?category=STORAGE" />
        <Stat label="Temuan belum selesai" value={data.unresolved_findings} href="/findings" />
      </div>

      {report && (
        <Card className="mt-6">
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span>Laporan AI terbaru — {report.schedule_name}</span>
              <Link href="/schedules" className="text-xs font-normal text-primary hover:underline">Semua laporan →</Link>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <RunSummary run={report} />
            <AIReport run={report} />
          </CardContent>
        </Card>
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm">Status asset</CardTitle></CardHeader>
          <CardContent>
            <div className="flex h-2.5 overflow-hidden rounded-full bg-muted">
              {STATUS_BAR.map((s) => (
                <div key={s.key} className={s.cls} style={{ width: `${(data.status_counts[s.key] / total) * 100}%` }} />
              ))}
            </div>
            <ul className="mt-4 grid grid-cols-2 gap-2 text-sm">
              {STATUS_BAR.map((s) => (
                <li key={s.key} className="flex items-center gap-2">
                  <span className={cn("size-2.5 rounded-sm", s.cls)} />
                  <span className="text-muted-foreground">{s.label}</span>
                  <span className="ml-auto font-medium tabular-nums">{data.status_counts[s.key]}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Asset berstatus RED</CardTitle></CardHeader>
          <CardContent>
            {!data.red_assets.length ? (
              <p className="text-sm text-muted-foreground">Tidak ada asset berstatus RED.</p>
            ) : (
              <ul className="divide-y text-sm">
                {data.red_assets.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-3 py-2">
                    <Link href={`/${a.asset_type === "SERVER" ? "servers" : "websites"}/${a.id}`} className="truncate font-medium hover:underline">
                      {a.name}
                    </Link>
                    <span className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">{a.open_findings} temuan</span>
                      <StatusBadge status={a.status} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {data.recent_activity && (
        <Card className="mt-6">
          <CardHeader><CardTitle className="text-sm">Aktivitas terbaru</CardTitle></CardHeader>
          <CardContent>
            {data.recent_activity.length === 0 ? (
              <p className="text-sm text-muted-foreground">Belum ada aktivitas.</p>
            ) : (
              <ul className="divide-y text-sm">
                {data.recent_activity.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                    <span className="w-36 shrink-0 text-xs text-muted-foreground">{formatDateTime(a.timestamp)}</span>
                    <span className={cn("font-medium", a.result !== "SUCCESS" && "text-red-600 dark:text-red-400")}>
                      {ACTION_LABELS[a.action] ?? a.action}
                    </span>
                    <span className="truncate text-muted-foreground">{a.username ?? "system"}</span>
                  </li>
                ))}
              </ul>
            )}
            <Link href="/audit" className="mt-3 inline-block text-xs text-primary hover:underline">Lihat semua audit log →</Link>
          </CardContent>
        </Card>
      )}
    </>
  );
}
