"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { FindingDialog } from "@/components/finding-dialog";
import { NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { FindingStatusBadge, SeverityBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { SEVERITIES, type Finding, type Page } from "@/lib/types";

const PAGE_SIZE = 50;
const STATUS_PRESETS: Record<string, string[]> = {
  active: ["OPEN", "ACKNOWLEDGED"],
  OPEN: ["OPEN"],
  ACKNOWLEDGED: ["ACKNOWLEDGED"],
  RESOLVED: ["RESOLVED"],
  FALSE_POSITIVE: ["FALSE_POSITIVE"],
  all: [],
};
const CATEGORIES = ["MALWARE", "SSL", "WEB", "CONFIGURATION", "STORAGE", "SYSTEM", "SERVICE", "NETWORK", "CONNECTIVITY"];

function FindingsContent() {
  const router = useRouter();
  const params = useSearchParams();
  const status = params.get("status") ?? "active";
  const category = params.get("category") ?? "";
  const severity = params.get("severity") ?? "";
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState<Finding | null>(null);

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setOffset(0);
    router.replace(`/findings?${next}`);
  };

  const search = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
  (STATUS_PRESETS[status] ?? []).forEach((s) => search.append("status", s));
  if (category) search.set("category", category);
  if (severity) severity.split(",").forEach((s) => search.append("severity", s));
  if (q) search.set("q", q);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", "list", search.toString()],
    queryFn: () => api<Page<Finding>>(`/findings?${search}`),
  });

  return (
    <>
      <PageHeader title="Findings" description="Temuan dari seluruh assessment, sudah di-dedup per asset." />

      <div className="mb-4 flex flex-wrap gap-2">
        <Input className="max-w-xs" placeholder="Cari judul temuan…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <NativeSelect className="w-auto" aria-label="Status" value={status} onChange={(e) => setParam("status", e.target.value)}>
          <option value="active">Aktif (open + acknowledged)</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False positive</option>
          <option value="all">Semua</option>
        </NativeSelect>
        <NativeSelect className="w-auto" aria-label="Severity" value={severity} onChange={(e) => setParam("severity", e.target.value)}>
          <option value="">Semua severity</option>
          <option value="CRITICAL,HIGH">Critical + High</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </NativeSelect>
        <NativeSelect className="w-auto" aria-label="Kategori" value={category} onChange={(e) => setParam("category", e.target.value)}>
          <option value="">Semua kategori</option>
          {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </NativeSelect>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.items.length ? (
        <EmptyState title="Tidak ada temuan">Tidak ada temuan yang cocok dengan filter ini.</EmptyState>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Temuan</TableHead>
                  <TableHead>Asset</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Terakhir terlihat</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((f) => (
                  <TableRow key={f.id} className="cursor-pointer" onClick={() => setOpen(f)}>
                    <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                    <TableCell className="max-w-md">
                      <p className="truncate font-medium">{f.title}</p>
                      <p className="truncate text-xs text-muted-foreground">
                        {f.category}{f.target ? ` · ${f.target}` : ""}
                      </p>
                    </TableCell>
                    <TableCell>{f.asset?.name ?? "—"}</TableCell>
                    <TableCell><FindingStatusBadge status={f.status} /></TableCell>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{formatDateTime(f.last_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
            <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} dari {data.total}</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Sebelumnya</Button>
              <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= data.total} onClick={() => setOffset(offset + PAGE_SIZE)}>Berikutnya</Button>
            </div>
          </div>
        </>
      )}
      {open && <FindingDialog finding={open} onClose={() => setOpen(null)} />}
    </>
  );
}

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsContent />
    </Suspense>
  );
}
