"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, Play } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { FindingDialog } from "@/components/finding-dialog";
import { AssessmentStateBadge, SeverityBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { SEVERITIES, type Assessment, type Finding, type Page } from "@/lib/types";

export function reportUrl(id: string, format: "html" | "markdown" | "json" = "html") {
  return `/api/v1/assessments/${id}/report?format=${format}`;
}

export function SeverityCounts({ counts }: { counts?: Partial<Record<string, number>> }) {
  const shown = SEVERITIES.filter((s) => s !== "INFO" && (counts?.[s] ?? 0) > 0);
  if (!shown.length) return <span className="text-xs text-muted-foreground">Tidak ada temuan</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {shown.map((s) => (
        <span key={s} className="inline-flex items-center gap-1 text-xs">
          <SeverityBadge severity={s} /> <b className="tabular-nums">{counts?.[s]}</b>
        </span>
      ))}
    </span>
  );
}

/** Assessment controls, latest result, active findings and history for one asset. */
export function AssessmentPanel({ assetId, onFinished }: { assetId: string; onFinished?: () => void }) {
  const qc = useQueryClient();
  const { can } = useMe();
  const [open, setOpen] = useState<Finding | null>(null);

  const history = useQuery({
    queryKey: ["assessments", { asset_id: assetId }],
    queryFn: () => api<Page<Assessment>>(`/assessments?asset_id=${assetId}&limit=10`),
    refetchInterval: (q) => {
      const running = q.state.data?.items.some((a) => a.state === "QUEUED" || a.state === "RUNNING");
      return running ? 3000 : false;
    },
  });
  const findings = useQuery({
    queryKey: ["findings", { asset_id: assetId }],
    queryFn: () => api<Page<Finding>>(`/findings?asset_id=${assetId}&status=OPEN&status=ACKNOWLEDGED&limit=200`),
  });

  const latest = history.data?.items[0];
  const running = latest && (latest.state === "QUEUED" || latest.state === "RUNNING");
  // When the latest run transitions from running to finished, refresh dependent data once.
  const prevState = useRef<string | undefined>(undefined);
  useEffect(() => {
    const prev = prevState.current;
    prevState.current = latest?.state;
    if (!latest || (prev !== "QUEUED" && prev !== "RUNNING")) return;
    if (latest.state !== "COMPLETED" && latest.state !== "FAILED") return;
    qc.invalidateQueries({ queryKey: ["findings"] });
    qc.invalidateQueries({ queryKey: ["dashboard"] });
    onFinished?.();
    if (latest.state === "COMPLETED") toast.success(`Assessment selesai: ${latest.overall_status}`);
    else toast.error("Assessment gagal");
  }, [latest, qc, onFinished]);

  const run = useMutation({
    mutationFn: () => api<Assessment>(`/assets/${assetId}/assess`, { method: "POST" }),
    onSuccess: () => {
      toast.info("Assessment dijalankan di background");
      qc.invalidateQueries({ queryKey: ["assessments", { asset_id: assetId }] });
    },
    onError: (e) => toast.error(e.message),
  });

  const sorted = [...(findings.data?.items ?? [])].sort(
    (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
  );

  return (
    <div className="mt-6 grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Assessment terakhir</CardTitle>
          <CardAction className="flex gap-2">
            {latest?.state === "COMPLETED" && (
              <a href={reportUrl(latest.id)} target="_blank" rel="noopener">
                <Button variant="outline" size="sm"><FileText /> Report</Button>
              </a>
            )}
            {can("assessment:run") && (
              <Button size="sm" onClick={() => run.mutate()} disabled={!!running || run.isPending}>
                <Play /> {running ? "Berjalan…" : "Jalankan assessment"}
              </Button>
            )}
          </CardAction>
        </CardHeader>
        <CardContent>
          {!latest ? (
            <p className="text-sm text-muted-foreground">Belum pernah di-assess.</p>
          ) : (
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <AssessmentStateBadge state={latest.state} />
              {latest.overall_status && <StatusBadge status={latest.overall_status} />}
              <SeverityCounts counts={latest.summary.severity} />
              {latest.summary.diff && (
                <span className="text-xs text-muted-foreground">
                  {latest.summary.diff.new} baru · {latest.summary.diff.resolved} selesai · {latest.summary.diff.reopened} muncul lagi
                </span>
              )}
              <span className="text-xs text-muted-foreground">{formatDateTime(latest.finished_at ?? latest.created_at)}</span>
              <Link href={`/assessments/${latest.id}`} className="text-xs text-primary hover:underline">Detail →</Link>
              {latest.error && <p className="w-full font-mono text-xs text-red-600">{latest.error}</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Temuan aktif ({sorted.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {!sorted.length ? (
            <p className="text-sm text-muted-foreground">Tidak ada temuan aktif.</p>
          ) : (
            <ul className="divide-y text-sm">
              {sorted.map((f) => (
                <li key={f.id}>
                  <button className="flex w-full items-start gap-3 py-2 text-left hover:bg-muted/40" onClick={() => setOpen(f)}>
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium">{f.title}</span>
                      {f.target && <span className="block truncate font-mono text-xs text-muted-foreground">{f.target}</span>}
                    </span>
                    {f.status === "ACKNOWLEDGED" && <span className="text-xs text-sky-700 dark:text-sky-400">ack</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {!!history.data?.items.length && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Timeline assessment</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="relative ml-2 border-l pl-5 text-sm">
              {history.data.items.map((a) => (
                <li key={a.id} className="mb-3 last:mb-0">
                  <span className="absolute -left-[5px] mt-1.5 size-2.5 rounded-full border bg-background" />
                  <Link href={`/assessments/${a.id}`} className="flex flex-wrap items-center gap-2 hover:underline">
                    <span className="w-36 text-xs text-muted-foreground">{formatDateTime(a.finished_at ?? a.created_at)}</span>
                    {a.overall_status ? <StatusBadge status={a.overall_status} /> : <AssessmentStateBadge state={a.state} />}
                    <SeverityCounts counts={a.summary.severity} />
                  </Link>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {open && <FindingDialog finding={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
