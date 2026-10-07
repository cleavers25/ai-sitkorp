"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PlayCircle } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { SeverityCounts } from "@/components/assessment-panel";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, PageHeader } from "@/components/page-header";
import { AssessmentStateBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Assessment, Page } from "@/lib/types";

function duration(a: Assessment): string {
  if (!a.started_at || !a.finished_at) return "—";
  const s = Math.round((new Date(a.finished_at).getTime() - new Date(a.started_at).getTime()) / 1000);
  return s < 60 ? `${s} dtk` : `${Math.floor(s / 60)} mnt ${s % 60} dtk`;
}

export default function AssessmentsPage() {
  const qc = useQueryClient();
  const { can } = useMe();
  const [confirm, setConfirm] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["assessments", "all"],
    queryFn: () => api<Page<Assessment>>("/assessments?limit=100"),
    refetchInterval: (q) =>
      q.state.data?.items.some((a) => a.state === "QUEUED" || a.state === "RUNNING") ? 3000 : false,
  });

  const runAll = useMutation({
    mutationFn: () => api<{ queued: number; skipped_active: number }>("/assessments/run-all", { method: "POST", json: {} }),
    onSuccess: (r) => {
      toast.success(`${r.queued} assessment masuk antrean${r.skipped_active ? `, ${r.skipped_active} sedang berjalan` : ""}`);
      setConfirm(false);
      qc.invalidateQueries({ queryKey: ["assessments"] });
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <>
      <PageHeader
        title="Assessment"
        description="Riwayat assessment seluruh asset. Hasil lama tetap disimpan untuk perbandingan."
        actions={can("assessment:run") && (
          <Button onClick={() => setConfirm(true)}><PlayCircle /> Assess semua asset</Button>
        )}
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.items.length ? (
        <EmptyState title="Belum ada assessment">Jalankan assessment dari halaman server/website atau tombol di atas.</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Waktu</TableHead>
                <TableHead>Asset</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Hasil</TableHead>
                <TableHead>Temuan</TableHead>
                <TableHead>Durasi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="whitespace-nowrap text-muted-foreground">
                    <Link href={`/assessments/${a.id}`} className="hover:underline">{formatDateTime(a.created_at)}</Link>
                  </TableCell>
                  <TableCell className="font-medium">
                    {a.asset ? (
                      <Link href={`/${a.asset.asset_type === "SERVER" ? "servers" : "websites"}/${a.asset.id}`} className="hover:underline">
                        {a.asset.name}
                      </Link>
                    ) : "—"}
                  </TableCell>
                  <TableCell><AssessmentStateBadge state={a.state} /></TableCell>
                  <TableCell>{a.overall_status ? <StatusBadge status={a.overall_status} /> : "—"}</TableCell>
                  <TableCell><SeverityCounts counts={a.summary.severity} /></TableCell>
                  <TableCell className="text-muted-foreground">{duration(a)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Assess semua asset?"
        description="Assessment untuk semua server dan website akan dimasukkan ke antrean worker. Semua check bersifat read-only; tidak ada perubahan di server target."
        confirmLabel="Jalankan"
        onConfirm={() => runAll.mutate()}
        pending={runAll.isPending}
      />
    </>
  );
}
