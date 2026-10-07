"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useState } from "react";

import { NativeSelect } from "@/components/form";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { ACTION_LABELS, formatDateTime } from "@/lib/format";
import type { AuditLog, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 50;

const RESULT_CLS: Record<AuditLog["result"], string> = {
  SUCCESS: "text-emerald-700 dark:text-emerald-400",
  FAILURE: "text-red-700 dark:text-red-400",
  DENIED: "text-amber-700 dark:text-amber-400",
};

export default function AuditPage() {
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
  if (action) params.set("action", action);
  if (result) params.set("result", result);

  const { data, isLoading } = useQuery({
    queryKey: ["audit", action, result, offset],
    queryFn: () => api<Page<AuditLog>>(`/audit-logs?${params}`),
  });

  return (
    <>
      <PageHeader title="Audit Log" description="Catatan seluruh aktivitas. Bersifat append-only dan tidak dapat diubah." />

      <div className="mb-4 flex flex-wrap gap-2">
        <NativeSelect className="w-auto" aria-label="Filter aksi" value={action} onChange={(e) => { setAction(e.target.value); setOffset(0); }}>
          <option value="">Semua aksi</option>
          <option value="auth.">Autentikasi</option>
          <option value="user.">User</option>
          <option value="credential.">Credential</option>
          <option value="asset.">Asset</option>
          <option value="server.">Server tools</option>
          <option value="assessment.">Assessment</option>
          <option value="finding.">Triage temuan</option>
          <option value="report.">Report</option>
          <option value="schedule.">Jadwal</option>
          <option value="ai.">AI</option>
        </NativeSelect>
        <NativeSelect className="w-auto" aria-label="Filter hasil" value={result} onChange={(e) => { setResult(e.target.value); setOffset(0); }}>
          <option value="">Semua hasil</option>
          <option value="SUCCESS">SUCCESS</option>
          <option value="FAILURE">FAILURE</option>
          <option value="DENIED">DENIED</option>
        </NativeSelect>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <TableHead>Waktu</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Aksi</TableHead>
                  <TableHead>Hasil</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((a) => (
                  <Fragment key={a.id}>
                    <TableRow className="cursor-pointer" onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                      <TableCell>{expanded === a.id ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(a.timestamp)}</TableCell>
                      <TableCell className="max-w-48 truncate">{a.username ?? "system"}</TableCell>
                      <TableCell>
                        {ACTION_LABELS[a.action] ?? a.action}
                        {a.tool && <span className="ml-1 font-mono text-xs text-muted-foreground">[{a.tool}]</span>}
                      </TableCell>
                      <TableCell className={cn("text-xs font-medium", RESULT_CLS[a.result])}>{a.result}</TableCell>
                      <TableCell className="text-xs">{a.risk_level ?? "—"}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{a.source_ip ?? "—"}</TableCell>
                    </TableRow>
                    {expanded === a.id && (
                      <TableRow className="bg-muted/40 hover:bg-muted/40">
                        <TableCell />
                        <TableCell colSpan={6}>
                          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">
                            {JSON.stringify(
                              { action: a.action, asset_id: a.asset_id, command_hash: a.command_hash, details: a.details },
                              null,
                              2,
                            )}
                          </pre>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {data?.total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, data.total)} dari ${data.total}` : "Tidak ada data"}
            </span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Sebelumnya</Button>
              <Button variant="outline" size="sm" disabled={!data || offset + PAGE_SIZE >= data.total} onClick={() => setOffset(offset + PAGE_SIZE)}>Berikutnya</Button>
            </div>
          </div>
        </>
      )}
    </>
  );
}
