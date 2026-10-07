"use client";

import { Bot, Loader2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { formatDateTime } from "@/lib/format";
import type { ScheduleRun } from "@/lib/types";

const STATUS_CLS: Record<string, string> = {
  GREEN: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  YELLOW: "bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  RED: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300",
};

export function RunSummary({ run }: { run: ScheduleRun }) {
  const s = run.summary;
  if (run.job === "BACKUP") {
    return (
      <div className="text-xs text-muted-foreground">
        {run.state === "RUNNING"
          ? `Backup berjalan (${run.queued} website)…`
          : `Backup: ${s.succeeded ?? 0}/${s.backups ?? 0} berhasil · ${s.verified ?? 0} terverifikasi${s.failed?.length ? ` · gagal: ${s.failed.join(", ")}` : ""}`}
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {(["RED", "YELLOW", "GREEN"] as const).map((k) =>
        s.status?.[k] ? (
          <span key={k} className={`rounded-full px-2 py-0.5 font-medium ${STATUS_CLS[k]}`}>
            {k} {s.status[k]}
          </span>
        ) : null,
      )}
      {run.state === "COMPLETED" && (
        <span className="text-muted-foreground">
          · {s.new_findings ?? 0} temuan baru · {s.resolved_findings ?? 0} selesai
          {s.worse?.length ? ` · ${s.worse.length} memburuk` : ""}
          {s.failed?.length ? ` · ${s.failed.length} gagal dicek` : ""}
        </span>
      )}
      {run.state === "RUNNING" && (
        <span className="inline-flex items-center gap-1 text-sky-700 dark:text-sky-400">
          <Loader2 className="size-3 animate-spin" /> berjalan ({run.queued} asset)
        </span>
      )}
    </div>
  );
}

export function AIReport({ run }: { run: ScheduleRun }) {
  if (run.ai_state === "SKIPPED") return <p className="text-xs text-muted-foreground">Ringkasan AI tidak diaktifkan untuk jadwal ini.</p>;
  if (run.ai_state === "PENDING" || run.state === "RUNNING")
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Laporan AI dibuat setelah semua pengecekan selesai…
      </p>
    );
  if (run.ai_state === "FAILED") return <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">Laporan AI gagal: {run.ai_error}</p>;
  if (!run.ai_report) return null;
  return (
    <div className="rounded-lg border bg-muted/20 p-4">
      <p className="mb-2 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Bot className="size-3.5" /> Laporan AI · {formatDateTime(run.finished_at)}
        {run.ai_usage.model ? ` · ${run.ai_usage.model}` : ""}
        {run.ai_usage.input_tokens ? ` · ${run.ai_usage.input_tokens + (run.ai_usage.output_tokens ?? 0)} token` : ""}
      </p>
      <div className="prose-chat text-sm">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{run.ai_report}</ReactMarkdown>
      </div>
    </div>
  );
}
