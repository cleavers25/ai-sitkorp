"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ChevronDown, ChevronRight, Download, FileText } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Fragment, useState } from "react";

import { reportUrl, SeverityCounts } from "@/components/assessment-panel";
import { EvidenceBlock } from "@/components/finding-dialog";
import { AssessmentStateBadge, CheckStatusText, SeverityBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AssessmentDetail, Check } from "@/lib/types";

const ORDER = { FAIL: 0, WARNING: 1, ERROR: 2, SKIPPED: 3, PASS: 4 } as const;

export default function AssessmentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [onlyIssues, setOnlyIssues] = useState(false);

  const { data: a, isLoading } = useQuery({
    queryKey: ["assessment", id],
    queryFn: () => api<AssessmentDetail>(`/assessments/${id}`),
    refetchInterval: (q) => (q.state.data && ["QUEUED", "RUNNING"].includes(q.state.data.state) ? 3000 : false),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Memuat…</p>;
  if (!a) return <p className="text-sm text-muted-foreground">Assessment tidak ditemukan.</p>;

  const assetHref = `/${a.asset.asset_type === "SERVER" ? "servers" : "websites"}/${a.asset.id}`;
  const checks = [...a.checks]
    .filter((c) => !onlyIssues || c.status !== "PASS")
    .sort((x: Check, y: Check) => ORDER[x.status] - ORDER[y.status] || x.position - y.position);
  const diff = a.summary.diff;

  return (
    <>
      <Link href={assetHref} className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> {a.asset.name}
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Assessment {a.asset.name}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {formatDateTime(a.started_at ?? a.created_at)} → {formatDateTime(a.finished_at)} · trigger {a.trigger}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <AssessmentStateBadge state={a.state} />
            {a.overall_status && <StatusBadge status={a.overall_status} />}
          </div>
        </div>
        {a.state === "COMPLETED" && (
          <div className="flex flex-wrap gap-2">
            <a href={reportUrl(a.id)} target="_blank" rel="noopener"><Button><FileText /> Report HTML</Button></a>
            <a href={reportUrl(a.id, "markdown")}><Button variant="outline"><Download /> Markdown</Button></a>
            <a href={reportUrl(a.id, "json")}><Button variant="outline"><Download /> JSON</Button></a>
          </div>
        )}
      </div>

      {a.error && <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 font-mono text-xs text-destructive">{a.error}</p>}

      <Card className="mb-6">
        <CardContent className="flex flex-wrap items-center gap-x-8 gap-y-3 text-sm">
          <SeverityCounts counts={a.summary.severity} />
          {diff && (
            <span className="text-muted-foreground">
              Dibanding sebelumnya: <b className="text-foreground">{diff.new}</b> baru · <b className="text-foreground">{diff.resolved}</b> selesai ·{" "}
              <b className="text-foreground">{diff.persistent}</b> masih ada · <b className="text-foreground">{diff.reopened}</b> muncul lagi
              {diff.suppressed ? ` · ${diff.suppressed} false positive` : ""}
            </span>
          )}
          {!!a.summary.malware_suspected && (
            <span className="font-medium text-red-700 dark:text-red-400">{a.summary.malware_suspected} file diduga malware</span>
          )}
        </CardContent>
      </Card>

      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Hasil check ({a.checks.length})</h2>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} />
          Sembunyikan yang PASS
        </label>
      </div>
      <div className="overflow-x-auto rounded-xl border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-6" />
              <TableHead>Status</TableHead>
              <TableHead>Check</TableHead>
              <TableHead>Hasil</TableHead>
              <TableHead>Nilai</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {checks.map((c) => (
              <Fragment key={c.id}>
                <TableRow className="cursor-pointer" onClick={() => setExpanded(expanded === c.id ? null : c.id)}>
                  <TableCell>{expanded === c.id ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    <span className="flex items-center gap-2">
                      <CheckStatusText status={c.status} />
                      {(c.status === "FAIL" || c.status === "WARNING") && <SeverityBadge severity={c.severity} />}
                    </span>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <span className="font-mono text-xs">{c.check}</span>
                    <span className="block text-xs text-muted-foreground">{c.category}</span>
                  </TableCell>
                  <TableCell className="max-w-md">
                    <p className="truncate">{c.title}</p>
                    {c.target && <p className="truncate font-mono text-xs text-muted-foreground">{c.target}</p>}
                  </TableCell>
                  <TableCell className="max-w-48 truncate text-muted-foreground">{c.value ?? ""}</TableCell>
                </TableRow>
                {expanded === c.id && (
                  <TableRow className="bg-muted/30 hover:bg-muted/30">
                    <TableCell />
                    <TableCell colSpan={4} className="whitespace-normal">
                      {c.recommendation && (
                        <p className="mb-2 whitespace-pre-line text-sm"><b>Rekomendasi:</b> {c.recommendation}</p>
                      )}
                      <EvidenceBlock value={c.evidence} />
                      {c.duration_ms != null && <p className="mt-1 text-xs text-muted-foreground">{c.duration_ms} ms</p>}
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            ))}
          </TableBody>
        </Table>
      </div>
    </>
  );
}
