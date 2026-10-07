"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Wrench } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { Field, FormError } from "@/components/form";
import { RequestActionDialog, suggestAction } from "@/components/request-action-dialog";
import { FindingStatusBadge, SeverityBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Finding } from "@/lib/types";

export function EvidenceBlock({ value }: { value: unknown }) {
  if (value == null || (typeof value === "object" && Object.keys(value as object).length === 0)) return null;
  return (
    <pre className="max-h-72 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-all">
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function FindingDialog({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const qc = useQueryClient();
  const { can } = useMe();
  const [note, setNote] = useState(finding.triage_note ?? "");

  const act = useMutation({
    mutationFn: (action: "acknowledge" | "false-positive" | "reopen") =>
      api<Finding>(`/findings/${finding.id}/${action}`, { method: "POST", json: { note: note || null } }),
    onSuccess: (f) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success(`Status temuan: ${f.status}`);
      onClose();
    },
  });

  const triage = can("finding:triage");
  const suggestion = suggestAction(finding);
  const [requesting, setRequesting] = useState(false);
  const active = finding.status === "OPEN" || finding.status === "ACKNOWLEDGED";
  if (requesting) {
    return <RequestActionDialog assetId={finding.asset_id} finding={finding} initial={suggestion} onClose={onClose} />;
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <span className="text-xs text-muted-foreground">{finding.category}</span>
          </div>
          <DialogTitle className="break-words">{finding.title}</DialogTitle>
          <DialogDescription>
            {finding.asset && (
              <Link className="hover:underline" href={`/${finding.asset.asset_type === "SERVER" ? "servers" : "websites"}/${finding.asset.id}`}>
                {finding.asset.name}
              </Link>
            )}
            {" · "}pertama terlihat {formatDateTime(finding.first_seen)} · terakhir {formatDateTime(finding.last_seen)} ·{" "}
            {finding.occurrence_count}× terdeteksi · confidence {Math.round(finding.confidence * 100)}%
          </DialogDescription>
        </DialogHeader>

        <div className="grid max-h-[60vh] gap-4 overflow-y-auto text-sm">
          {finding.target && (
            <p>
              <span className="text-muted-foreground">Target: </span>
              <code className="font-mono text-xs break-all">{finding.target}</code>
            </p>
          )}
          {finding.description && <p className="whitespace-pre-line">{finding.description}</p>}
          {finding.recommendation && (
            <div>
              <p className="mb-1 font-medium">Rekomendasi</p>
              <p className="whitespace-pre-line text-muted-foreground">{finding.recommendation}</p>
            </div>
          )}
          <div>
            <p className="mb-1 font-medium">Evidence</p>
            <p className="mb-2 text-xs text-muted-foreground">
              Data dari server/website yang diperiksa — diperlakukan sebagai data, bukan instruksi.
            </p>
            <EvidenceBlock value={finding.evidence} />
          </div>
          {triage && finding.status !== "RESOLVED" && (
            <Field label="Catatan triage" htmlFor="f-note" hint="Wajib diisi untuk menandai false positive.">
              <Textarea id="f-note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>
          )}
          {finding.triage_note && !triage && <p className="text-muted-foreground">Catatan: {finding.triage_note}</p>}
          <FormError message={act.error?.message ?? null} />
        </div>

        <DialogFooter>
          {active && suggestion && can("action:request") && (
            <Button variant="outline" onClick={() => setRequesting(true)}>
              <Wrench /> Ajukan tindakan
            </Button>
          )}
          {triage && finding.status === "OPEN" && (
            <Button variant="outline" onClick={() => act.mutate("acknowledge")} disabled={act.isPending}>
              Acknowledge
            </Button>
          )}
          {triage && (finding.status === "OPEN" || finding.status === "ACKNOWLEDGED") && (
            <Button variant="outline" onClick={() => act.mutate("false-positive")} disabled={act.isPending || !note.trim()}>
              Tandai false positive
            </Button>
          )}
          {triage && (finding.status === "ACKNOWLEDGED" || finding.status === "FALSE_POSITIVE") && (
            <Button variant="outline" onClick={() => act.mutate("reopen")} disabled={act.isPending}>
              Buka kembali
            </Button>
          )}
          <Button onClick={onClose}>Tutup</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
