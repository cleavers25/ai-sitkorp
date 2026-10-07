"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronDown, ChevronRight, RotateCcw, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { ACTION_LABEL } from "@/components/request-action-dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AssetRef, Page } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Action {
  id: string;
  kind: string;
  label: string;
  state: "PENDING_APPROVAL" | "APPROVED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "REJECTED" | "CANCELLED";
  risk_level: string;
  asset: AssetRef | null;
  params: Record<string, string>;
  reason: string;
  command_preview: string;
  requested_by: string | null;
  requested_by_id: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  finished_at: string | null;
  result: { steps?: { step: string; exit: number; stdout: string; stderr: string }[]; [k: string]: unknown };
  error: string | null;
  rollback_of_id: string | null;
  rolled_back_by_id: string | null;
  created_at: string;
}

const STATE: Record<Action["state"], { label: string; cls: string }> = {
  PENDING_APPROVAL: { label: "Menunggu approval", cls: "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200" },
  APPROVED: { label: "Disetujui", cls: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200" },
  RUNNING: { label: "Berjalan…", cls: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200" },
  SUCCEEDED: { label: "Berhasil", cls: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200" },
  FAILED: { label: "Gagal", cls: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200" },
  REJECTED: { label: "Ditolak", cls: "bg-muted text-muted-foreground" },
  CANCELLED: { label: "Dibatalkan", cls: "bg-muted text-muted-foreground" },
};

function ActionCard({ a }: { a: Action }) {
  const qc = useQueryClient();
  const { can, me } = useMe();
  const [open, setOpen] = useState(a.state === "PENDING_APPROVAL");
  const [note, setNote] = useState("");
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["actions"] });
    qc.invalidateQueries({ queryKey: ["actions-pending"] });
  };
  const decide = useMutation({
    mutationFn: (verb: "approve" | "reject" | "cancel" | "rollback") =>
      api(`/actions/${a.id}/${verb}`, { method: "POST", json: verb === "cancel" || verb === "rollback" ? undefined : { note: note || null } }),
    onSuccess: (_, verb) => {
      refresh();
      toast.success({ approve: "Disetujui — sedang dijalankan", reject: "Ditolak", cancel: "Dibatalkan", rollback: "Permintaan rollback dibuat (perlu approval)" }[verb]);
    },
    onError: (e) => toast.error(e.message),
  });
  const pending = a.state === "PENDING_APPROVAL";
  const href = a.asset ? `/${a.asset.asset_type === "SERVER" ? "servers" : "websites"}/${a.asset.id}` : null;
  const canRollback = a.state === "SUCCEEDED" && !a.rolled_back_by_id && ["QUARANTINE_FILE", "RESTRICT_FILE"].includes(a.kind);

  return (
    <Card>
      <CardContent className="space-y-3">
        <button className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 text-left" onClick={() => setOpen(!open)}>
          {open ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
          <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", STATE[a.state].cls)}>{STATE[a.state].label}</span>
          <span className="font-medium">{ACTION_LABEL[a.kind] ?? a.label}</span>
          <span className="text-sm text-muted-foreground">
            {a.asset?.name} · <span className="font-mono text-xs">{a.params.path ?? a.params.service}</span>
          </span>
          <span className="ml-auto text-xs text-muted-foreground">{formatDateTime(a.created_at)}</span>
        </button>
        {open && (
          <div className="space-y-3 pl-7 text-sm">
            <p><span className="text-muted-foreground">Alasan:</span> {a.reason}</p>
            <p className="text-xs text-muted-foreground">
              Diajukan oleh {a.requested_by ?? "—"} · risiko {a.risk_level}
              {href && <> · <Link href={href} className="underline">buka asset</Link></>}
              {a.decided_by && <> · diputuskan oleh {a.decided_by} ({formatDateTime(a.decided_at)}){a.decision_note ? `: “${a.decision_note}”` : ""}</>}
            </p>
            <div>
              <p className="mb-1 text-xs font-medium">Command yang akan dijalankan (preview):</p>
              <pre className="overflow-x-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-all">{a.command_preview}</pre>
            </div>
            {!!a.result.steps?.length && (
              <div>
                <p className="mb-1 text-xs font-medium">Hasil eksekusi:</p>
                <ul className="space-y-1 font-mono text-xs">
                  {a.result.steps.map((s, i) => (
                    <li key={i} className={s.exit === 0 ? "" : "text-red-600"}>
                      [{s.exit === 0 ? "OK" : `exit ${s.exit}`}] {s.step}: {(s.stdout || s.stderr).slice(0, 300)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {a.error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-destructive">{a.error}</p>}
            {pending && can("action:approve") && (
              <div className="flex flex-wrap items-center gap-2">
                <Input className="max-w-sm" placeholder="Catatan (opsional)" value={note} onChange={(e) => setNote(e.target.value)} />
                <Button size="sm" onClick={() => decide.mutate("approve")} disabled={decide.isPending}><Check /> Setujui & jalankan</Button>
                <Button size="sm" variant="outline" onClick={() => decide.mutate("reject")} disabled={decide.isPending}><X /> Tolak</Button>
              </div>
            )}
            {pending && (a.requested_by_id === me?.id || can("action:approve")) && (
              <Button size="sm" variant="ghost" onClick={() => decide.mutate("cancel")}>Batalkan permintaan</Button>
            )}
            {canRollback && can("action:request") && (
              <Button size="sm" variant="outline" onClick={() => decide.mutate("rollback")}><RotateCcw /> Ajukan rollback</Button>
            )}
            {a.rolled_back_by_id && <p className="text-xs text-muted-foreground">Sudah diajukan rollback.</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function ActionsPage() {
  const [state, setState] = useState("PENDING_APPROVAL");
  const { data, isLoading } = useQuery({
    queryKey: ["actions", state],
    queryFn: () => api<Page<Action>>(`/actions?limit=100${state ? `&state=${state}` : ""}`),
    refetchInterval: (q) => (q.state.data?.items.some((a) => a.state === "APPROVED" || a.state === "RUNNING") ? 3000 : 20000),
  });
  return (
    <>
      <PageHeader
        title="Tindakan"
        description="Remediation yang mengubah server (karantina, batasi akses, restart). Semua harus disetujui ADMIN/SECURITY."
        actions={
          <NativeSelect className="w-auto" value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter status">
            <option value="PENDING_APPROVAL">Menunggu approval</option>
            <option value="">Semua</option>
            <option value="SUCCEEDED">Berhasil</option>
            <option value="FAILED">Gagal</option>
            <option value="REJECTED">Ditolak</option>
          </NativeSelect>
        }
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.items.length ? (
        <EmptyState title="Tidak ada tindakan">Ajukan tindakan dari detail temuan (menu Findings) atau lewat usulan AI.</EmptyState>
      ) : (
        <div className="grid gap-3">{data.items.map((a) => <ActionCard key={a.id} a={a} />)}</div>
      )}
    </>
  );
}
