"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { Field, FormError, NativeSelect } from "@/components/form";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Finding, Website } from "@/lib/types";

export type ActionKind = "QUARANTINE_FILE" | "RESTRICT_FILE" | "RESTART_SERVICE";
export const ACTION_LABEL: Record<string, string> = {
  QUARANTINE_FILE: "Karantina file",
  RESTRICT_FILE: "Batasi akses file (chmod 600)",
  RESTART_SERVICE: "Restart service",
  RESTORE_QUARANTINE: "Kembalikan file dari karantina",
  RESTORE_PERMISSIONS: "Kembalikan permission file",
};

/** Which remediation fits a finding, with the parameter pre-filled. */
export function suggestAction(f: Finding): { kind: ActionKind; value: string } | null {
  const ev = (f.evidence ?? {}) as { units?: string[] };
  if (f.check === "malware_file" && f.target) return { kind: "QUARANTINE_FILE", value: f.target };
  if (f.check === "suspicious_process" && f.target?.startsWith("/")) return { kind: "QUARANTINE_FILE", value: f.target };
  if (f.check === "exposed_file" && f.target) return { kind: "RESTRICT_FILE", value: f.target };
  if (f.check === "failed_services" && ev.units?.length) return { kind: "RESTART_SERVICE", value: ev.units[0] };
  return null;
}

export function RequestActionDialog({
  assetId,
  finding,
  initial,
  onClose,
}: {
  assetId: string;
  finding?: Finding;
  initial?: { kind: ActionKind; value: string } | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<ActionKind>(initial?.kind ?? "QUARANTINE_FILE");
  const [value, setValue] = useState(initial?.value ?? "");
  const [reason, setReason] = useState(finding ? `Temuan: ${finding.title}` : "");

  // An exposed-file finding targets a URL; map it onto the website's document root.
  const website = useQuery({
    queryKey: ["website", assetId],
    queryFn: () => api<Website>(`/websites/${assetId}`),
    enabled: finding?.asset?.asset_type === "WEBSITE",
  });
  const docroot = website.data?.document_root;
  const shown = kind === "RESTRICT_FILE" && value.startsWith("http") && docroot
    ? `${docroot}${new URL(value).pathname}`
    : value;

  const submit = useMutation({
    mutationFn: () =>
      api("/actions", {
        method: "POST",
        json: {
          asset_id: assetId,
          kind,
          params: kind === "RESTART_SERVICE" ? { service: shown } : { path: shown },
          reason,
          finding_id: finding?.id ?? null,
        },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["actions"] });
      toast.success("Permintaan dibuat — menunggu approval di menu Tindakan");
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Ajukan tindakan</DialogTitle>
          <DialogDescription>
            Tindakan baru dijalankan setelah disetujui ADMIN/SECURITY. File tidak pernah dihapus; semua tindakan bisa di-rollback.
          </DialogDescription>
        </DialogHeader>
        <form id="act-form" className="grid gap-4" onSubmit={(e) => { e.preventDefault(); submit.mutate(); }}>
          <Field label="Tindakan" htmlFor="ac-kind">
            <NativeSelect id="ac-kind" value={kind} onChange={(e) => setKind(e.target.value as ActionKind)}>
              <option value="QUARANTINE_FILE">{ACTION_LABEL.QUARANTINE_FILE}</option>
              <option value="RESTRICT_FILE">{ACTION_LABEL.RESTRICT_FILE}</option>
              <option value="RESTART_SERVICE">{ACTION_LABEL.RESTART_SERVICE}</option>
            </NativeSelect>
          </Field>
          <Field label={kind === "RESTART_SERVICE" ? "Nama service" : "Path file di server"} htmlFor="ac-val"
            hint={kind === "RESTART_SERVICE" ? "mis. nginx atau php8.2-fpm" : "Harus di dalam document root website."}>
            <Input id="ac-val" required className="font-mono" value={shown} onChange={(e) => setValue(e.target.value)} />
          </Field>
          <Field label="Alasan" htmlFor="ac-reason">
            <Textarea id="ac-reason" required minLength={3} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <FormError message={submit.error?.message ?? null} />
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="act-form" disabled={submit.isPending}>Ajukan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
