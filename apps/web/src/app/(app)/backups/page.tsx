"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Download, HardDriveDownload } from "lucide-react";
import Link from "next/link";
import { Fragment, useState } from "react";
import { toast } from "sonner";

import { EmptyState, PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Page } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Backup {
  id: string;
  asset_id: string;
  trigger: string;
  state: "RUNNING" | "SUCCEEDED" | "FAILED";
  started_at: string;
  finished_at: string | null;
  size_bytes: number | null;
  sha256: string | null;
  file_count: number | null;
  remote_file_count: number | null;
  verified: boolean;
  verify_note: string | null;
  error: string | null;
  pruned: boolean;
}
interface Overview {
  asset_id: string;
  name: string;
  document_root: string | null;
  ready: boolean;
  latest: Backup | null;
  backups_kept: number;
}

function formatBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function health(o: Overview): { label: string; cls: string } {
  const b = o.latest;
  if (!o.ready) return { label: "Belum siap", cls: "bg-muted text-muted-foreground" };
  if (!b) return { label: "Belum ada backup", cls: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300" };
  if (b.state === "RUNNING") return { label: "Berjalan…", cls: "bg-sky-50 text-sky-700 dark:bg-sky-950 dark:text-sky-300" };
  if (b.state === "FAILED") return { label: "Gagal", cls: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300" };
  if (!b.verified) return { label: "Tidak terverifikasi", cls: "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300" };
  const ageH = (Date.now() - new Date(b.started_at).getTime()) / 36e5;
  if (ageH > 48) return { label: `Usang (${Math.floor(ageH / 24)} hari)`, cls: "bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-300" };
  return { label: "Valid", cls: "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300" };
}

function History({ assetId }: { assetId: string }) {
  const { can } = useMe();
  const { data } = useQuery({
    queryKey: ["backups", assetId],
    queryFn: () => api<Page<Backup>>(`/backups?asset_id=${assetId}&limit=20`),
  });
  return (
    <ul className="divide-y text-sm">
      {data?.items.map((b) => (
        <li key={b.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2">
          <span className="w-36 text-xs text-muted-foreground">{formatDateTime(b.started_at)}</span>
          <span className={cn("text-xs font-medium", b.state === "FAILED" ? "text-red-600" : b.verified ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700")}>
            {b.state === "SUCCEEDED" ? (b.verified ? "✓ terverifikasi" : "⚠ belum terverifikasi") : b.state}
          </span>
          <span className="text-xs">{formatBytes(b.size_bytes)} · {b.file_count ?? "—"} file</span>
          <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{b.error ?? b.verify_note}</span>
          {b.sha256 && <code className="hidden font-mono text-[11px] text-muted-foreground lg:inline">sha256 {b.sha256.slice(0, 12)}…</code>}
          {b.pruned ? (
            <span className="text-[11px] text-muted-foreground">dihapus (retensi)</span>
          ) : b.state === "SUCCEEDED" && can("backup:download") ? (
            <a href={`/api/v1/backups/${b.id}/download`}><Button size="xs" variant="outline"><Download /> Unduh</Button></a>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export default function BackupsPage() {
  const qc = useQueryClient();
  const { can } = useMe();
  const [open, setOpen] = useState<string | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ["backups", "overview"],
    queryFn: () => api<Overview[]>("/backups/overview"),
    refetchInterval: (q) => (q.state.data?.some((o) => o.latest?.state === "RUNNING") ? 3000 : 30000),
  });
  const backupNow = useMutation({
    mutationFn: (assetId: string) => api("/backups", { method: "POST", json: { asset_id: assetId } }),
    onSuccess: () => {
      toast.success("Backup dijalankan");
      qc.invalidateQueries({ queryKey: ["backups"] });
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <>
      <PageHeader
        title="Backup"
        description="Arsip document root website disimpan di server aplikasi ini lalu diverifikasi (arsip dibaca utuh & jumlah file dicocokkan). Jadwalkan lewat menu Jadwal → jenis Backup."
      />
      <p className="mb-4 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200">
        Arsip bisa berisi secret (wp-config.php, .env). Unduh hanya untuk ADMIN dan tercatat di audit log. Backup database belum termasuk.
      </p>
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.length ? (
        <EmptyState title="Belum ada website">Tambahkan website terlebih dahulu.</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6" />
                <TableHead>Website</TableHead>
                <TableHead>Status backup</TableHead>
                <TableHead>Terakhir</TableHead>
                <TableHead>Ukuran</TableHead>
                <TableHead>Disimpan</TableHead>
                <TableHead className="text-right">Aksi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((o) => {
                const h = health(o);
                return (
                  <Fragment key={o.asset_id}>
                    <TableRow>
                      <TableCell>
                        <button aria-label="Riwayat" onClick={() => setOpen(open === o.asset_id ? null : o.asset_id)}>
                          {open === o.asset_id ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                        </button>
                      </TableCell>
                      <TableCell>
                        <Link href={`/websites/${o.asset_id}`} className="font-medium hover:underline">{o.name}</Link>
                        <p className="font-mono text-xs text-muted-foreground">{o.document_root ?? "document root belum diisi"}</p>
                      </TableCell>
                      <TableCell><span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", h.cls)}>{h.label}</span></TableCell>
                      <TableCell className="text-muted-foreground">{formatDateTime(o.latest?.started_at)}</TableCell>
                      <TableCell>{formatBytes(o.latest?.size_bytes)}</TableCell>
                      <TableCell>{o.backups_kept}</TableCell>
                      <TableCell className="text-right">
                        {can("backup:run") && (
                          <Button size="sm" variant="outline" disabled={!o.ready || o.latest?.state === "RUNNING" || backupNow.isPending}
                            onClick={() => backupNow.mutate(o.asset_id)} title={o.ready ? undefined : "Hubungkan ke server & isi document root"}>
                            <HardDriveDownload /> Backup sekarang
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                    {open === o.asset_id && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell />
                        <TableCell colSpan={6}><History assetId={o.asset_id} /></TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </>
  );
}
