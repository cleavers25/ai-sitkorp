"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { AIReport, RunSummary } from "@/components/ai-report";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Field, FormError, NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AssetRef, JobKind, Page, Schedule, ScheduleFrequency, ScheduleRun, ScheduleTarget } from "@/lib/types";
import { cn } from "@/lib/utils";

const DAYS = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"];
const TZ: Record<string, string> = { "Asia/Jakarta": "WIB", "Asia/Makassar": "WITA", "Asia/Jayapura": "WIT", UTC: "UTC" };
const TARGET_LABEL: Record<ScheduleTarget, string> = {
  ALL_WEBSITES: "Semua website",
  ALL_SERVERS: "Semua server",
  ALL_ASSETS: "Semua server & website",
  SELECTED: "Asset pilihan",
};

function describe(s: Schedule): string {
  const tz = TZ[s.timezone] ?? s.timezone;
  const when =
    s.frequency === "HOURLY"
      ? `Setiap jam, menit ke-${s.minute}`
      : s.frequency === "DAILY"
        ? `Setiap hari pukul ${s.time_of_day} ${tz}`
        : `Setiap ${s.weekdays.map((d) => DAYS[d]).join(", ")} pukul ${s.time_of_day} ${tz}`;
  const target = s.target === "SELECTED" ? `${s.asset_ids.length} asset pilihan` : TARGET_LABEL[s.target];
  if (s.job === "BACKUP") return `Backup · ${when} · ${target}`;
  return `${when} · ${target}${s.ai_report ? " · dengan laporan AI" : ""}`;
}

function ScheduleDialog({ schedule, onClose }: { schedule?: Schedule; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    name: schedule?.name ?? "Pengecekan harian semua website",
    enabled: schedule?.enabled ?? true,
    job: schedule?.job ?? ("ASSESSMENT" as JobKind),
    target: schedule?.target ?? ("ALL_WEBSITES" as ScheduleTarget),
    asset_ids: schedule?.asset_ids ?? ([] as string[]),
    frequency: schedule?.frequency ?? ("DAILY" as ScheduleFrequency),
    time_of_day: schedule?.time_of_day ?? "02:00",
    weekdays: schedule?.weekdays ?? [0],
    minute: schedule?.minute ?? 0,
    timezone: schedule?.timezone ?? "Asia/Jakarta",
    ai_report: schedule?.ai_report ?? true,
  });
  const assets = useQuery({
    queryKey: ["assets", "schedule-picker"],
    queryFn: () => api<Page<AssetRef>>("/assets?limit=500"),
    enabled: f.target === "SELECTED",
  });
  const save = useMutation({
    mutationFn: () => {
      const body = { ...f, weekdays: f.frequency === "WEEKLY" ? f.weekdays : [], asset_ids: f.target === "SELECTED" ? f.asset_ids : [] };
      return schedule
        ? api<Schedule>(`/schedules/${schedule.id}`, { method: "PATCH", json: body })
        : api<Schedule>("/schedules", { method: "POST", json: body });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["schedules"] });
      toast.success("Jadwal disimpan");
      onClose();
    },
  });
  const toggle = <T,>(list: T[], v: T) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{schedule ? "Ubah jadwal" : "Buat jadwal pengecekan"}</DialogTitle>
          <DialogDescription>
            Pada waktunya, assessment (read-only) dijalankan ke semua target. Setelah selesai, AI menulis laporan ringkas.
          </DialogDescription>
        </DialogHeader>
        <form id="sched-form" className="grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Nama" htmlFor="sc-name" className="sm:col-span-2">
            <Input id="sc-name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
          </Field>
          <Field label="Jenis pekerjaan" htmlFor="sc-job" className="sm:col-span-2">
            <NativeSelect id="sc-job" value={f.job} onChange={(e) => setF({ ...f, job: e.target.value as JobKind })}>
              <option value="ASSESSMENT">Pengecekan (assessment) + laporan AI</option>
              <option value="BACKUP">Backup document root website</option>
            </NativeSelect>
          </Field>
          <Field label="Target" htmlFor="sc-target">
            <NativeSelect id="sc-target" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value as ScheduleTarget })}>
              {Object.entries(TARGET_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </Field>
          <Field label="Frekuensi" htmlFor="sc-freq">
            <NativeSelect id="sc-freq" value={f.frequency} onChange={(e) => setF({ ...f, frequency: e.target.value as ScheduleFrequency })}>
              <option value="DAILY">Harian</option>
              <option value="WEEKLY">Mingguan</option>
              <option value="HOURLY">Per jam</option>
            </NativeSelect>
          </Field>
          {f.target === "SELECTED" && (
            <div className="sm:col-span-2">
              <p className="mb-1.5 text-sm font-medium">Pilih asset ({f.asset_ids.length})</p>
              <div className="max-h-40 overflow-y-auto rounded-md border p-2 text-sm">
                {assets.data?.items.map((a) => (
                  <label key={a.id} className="flex items-center gap-2 py-0.5">
                    <input type="checkbox" checked={f.asset_ids.includes(a.id)} onChange={() => setF({ ...f, asset_ids: toggle(f.asset_ids, a.id) })} />
                    {a.name} <span className="text-xs text-muted-foreground">{a.asset_type}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
          {f.frequency === "HOURLY" ? (
            <Field label="Menit ke-" htmlFor="sc-min">
              <Input id="sc-min" type="number" min={0} max={59} value={f.minute} onChange={(e) => setF({ ...f, minute: Number(e.target.value) })} />
            </Field>
          ) : (
            <Field label="Jam" htmlFor="sc-time">
              <Input id="sc-time" type="time" required value={f.time_of_day} onChange={(e) => setF({ ...f, time_of_day: e.target.value })} />
            </Field>
          )}
          <Field label="Zona waktu" htmlFor="sc-tz">
            <NativeSelect id="sc-tz" value={f.timezone} onChange={(e) => setF({ ...f, timezone: e.target.value })}>
              {Object.entries(TZ).map(([k, v]) => <option key={k} value={k}>{v} ({k})</option>)}
            </NativeSelect>
          </Field>
          {f.frequency === "WEEKLY" && (
            <div className="sm:col-span-2">
              <p className="mb-1.5 text-sm font-medium">Hari</p>
              <div className="flex flex-wrap gap-2">
                {DAYS.map((d, i) => (
                  <label key={d} className={cn("cursor-pointer rounded-full border px-3 py-1 text-xs", f.weekdays.includes(i) && "border-primary bg-primary text-primary-foreground")}>
                    <input type="checkbox" className="sr-only" checked={f.weekdays.includes(i)} onChange={() => setF({ ...f, weekdays: toggle(f.weekdays, i) })} />
                    {d}
                  </label>
                ))}
              </div>
            </div>
          )}
          {f.job === "ASSESSMENT" && <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" checked={f.ai_report} onChange={(e) => setF({ ...f, ai_report: e.target.checked })} />
            Buat laporan AI setelah pengecekan selesai (±1 panggilan AI per run)
          </label>}
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
            Aktif
          </label>
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? null} /></div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="sched-form" disabled={save.isPending}>Simpan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RunList() {
  const [open, setOpen] = useState<string | null>(null);
  const runs = useQuery({
    queryKey: ["schedule-runs"],
    queryFn: () => api<Page<ScheduleRun>>("/schedule-runs?limit=30"),
    refetchInterval: (q) =>
      q.state.data?.items.some((r) => r.state === "RUNNING" || r.ai_state === "PENDING") ? 5000 : false,
  });
  const items = runs.data?.items ?? [];
  const expanded = open ?? items.find((r) => r.ai_state === "DONE")?.id ?? null;
  if (!items.length) return <p className="text-sm text-muted-foreground">Belum ada run. Tekan &quot;Jalankan sekarang&quot; untuk mencoba.</p>;
  return (
    <div className="divide-y rounded-xl border">
      {items.map((r) => (
        <div key={r.id} className="p-3">
          <button className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 text-left" onClick={() => setOpen(expanded === r.id ? "" : r.id)}>
            {expanded === r.id ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
            <span className="w-36 text-xs text-muted-foreground">{formatDateTime(r.started_at)}</span>
            <span className="font-medium">{r.schedule_name}</span>
            <span className="text-xs text-muted-foreground">{r.trigger === "MANUAL" ? "manual" : "terjadwal"}</span>
            <RunSummary run={r} />
          </button>
          {expanded === r.id && (
            <div className="mt-3 ml-7 space-y-2">
              {!!r.summary.worse?.length && (
                <p className="text-sm text-red-700 dark:text-red-400">
                  Memburuk: {r.summary.worse.map((w) => `${w.asset} (${w.from}→${w.to})`).join(", ")}
                </p>
              )}
              <AIReport run={r} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function SchedulesPage() {
  const qc = useQueryClient();
  const { can } = useMe();
  const manage = can("assessment:run");
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["schedules"], queryFn: () => api<Schedule[]>("/schedules"), refetchInterval: 15000 });

  const runNow = useMutation({
    mutationFn: (id: string) => api<ScheduleRun>(`/schedules/${id}/run-now`, { method: "POST" }),
    onSuccess: (r) => {
      toast.success(`${r.queued} asset masuk antrean pengecekan`);
      qc.invalidateQueries({ queryKey: ["schedule-runs"] });
      qc.invalidateQueries({ queryKey: ["schedules"] });
    },
    onError: (e) => toast.error(e.message),
  });
  const toggle = useMutation({
    mutationFn: (s: Schedule) => api(`/schedules/${s.id}`, { method: "PATCH", json: { enabled: !s.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/schedules/${id}`, { method: "DELETE" }),
    onSuccess: () => { setDeleting(null); qc.invalidateQueries({ queryKey: ["schedules"] }); },
  });

  return (
    <>
      <PageHeader
        title="Jadwal"
        description="Pengecekan otomatis berkala. Setelah pengecekan selesai, AI menulis laporan ringkas."
        actions={manage && <Button onClick={() => setEditing("new")}><Plus /> Buat jadwal</Button>}
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.length ? (
        <EmptyState title="Belum ada jadwal">Buat jadwal, misalnya pengecekan harian semua website pukul 02:00 WIB.</EmptyState>
      ) : (
        <div className="grid gap-3">
          {data.map((s) => (
            <Card key={s.id} className={cn(!s.enabled && "opacity-60")}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium">{s.name}{!s.enabled && <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-[11px]">nonaktif</span>}</p>
                  <p className="text-sm text-muted-foreground">{describe(s)}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Berikutnya: <b className="text-foreground">{s.enabled ? formatDateTime(s.next_run_at) : "—"}</b>
                    {" · "}Terakhir: {formatDateTime(s.last_run_at)}
                  </p>
                  {s.last_run && <div className="mt-1"><RunSummary run={s.last_run} /></div>}
                </div>
                {manage && (
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" onClick={() => runNow.mutate(s.id)} disabled={runNow.isPending || s.last_run?.state === "RUNNING"}>
                      <Play /> Jalankan sekarang
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => toggle.mutate(s)}>{s.enabled ? "Nonaktifkan" : "Aktifkan"}</Button>
                    <Button size="sm" variant="outline" onClick={() => setEditing(s)}><Pencil /> Ubah</Button>
                    <Button size="icon-sm" variant="ghost" aria-label="Hapus" onClick={() => setDeleting(s)}><Trash2 /></Button>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card className="mt-8">
        <CardHeader><CardTitle className="text-sm">Riwayat run & Laporan AI</CardTitle></CardHeader>
        <CardContent><RunList /></CardContent>
      </Card>

      {editing && <ScheduleDialog schedule={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Hapus jadwal ${deleting?.name}?`}
        description="Riwayat run dan laporan AI tetap tersimpan."
        confirmLabel="Hapus"
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        pending={remove.isPending}
      />
    </>
  );
}
