"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Brain, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { NativeSelect } from "@/components/form";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { useMe } from "@/hooks/use-me";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

export type MemoryKind = "ASSET" | "OPERATIONAL" | "SECURITY";
export interface Memory {
  id: string;
  asset_id: string | null;
  kind: MemoryKind;
  content: string;
  source: "USER" | "AI";
  created_at: string;
}

export const MEMORY_KIND_LABEL: Record<MemoryKind, string> = {
  ASSET: "Info asset",
  OPERATIONAL: "Operasional",
  SECURITY: "Keamanan",
};

/** Notes the AI should remember about an asset (or globally when assetId is omitted). PRD 17. */
export function MemoryCard({ assetId }: { assetId?: string }) {
  const qc = useQueryClient();
  const { can } = useMe();
  const manage = can("memory:manage");
  const [adding, setAdding] = useState(false);
  const [kind, setKind] = useState<MemoryKind>("OPERATIONAL");
  const [content, setContent] = useState("");
  const key = ["memories", assetId ?? "global"];

  const { data } = useQuery({
    queryKey: key,
    queryFn: () => api<Memory[]>(assetId ? `/memories?asset_id=${assetId}` : "/memories?scope=global"),
  });
  const add = useMutation({
    mutationFn: () => api("/memories", { method: "POST", json: { asset_id: assetId ?? null, kind, content } }),
    onSuccess: () => {
      setContent("");
      setAdding(false);
      qc.invalidateQueries({ queryKey: key });
      toast.success("Disimpan ke memory");
    },
    onError: (e) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/memories/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
  });

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm"><Brain className="size-4" /> Memory {assetId ? "asset" : "global"}</CardTitle>
        {manage && !adding && (
          <CardAction><Button size="sm" variant="outline" onClick={() => setAdding(true)}><Plus /> Tambah catatan</Button></CardAction>
        )}
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-xs text-muted-foreground">
          Catatan yang selalu diingat AI saat chat & membuat laporan — mis. riwayat insiden, pemilik, jadwal maintenance,
          atau file yang sudah diverifikasi aman.
        </p>
        {adding && (
          <form className="mb-4 grid gap-2" onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
            <NativeSelect className="w-48" value={kind} onChange={(e) => setKind(e.target.value as MemoryKind)}>
              {Object.entries(MEMORY_KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
            <Textarea rows={2} required minLength={3} maxLength={2000} value={content} onChange={(e) => setContent(e.target.value)}
              placeholder="mis. Website ini pernah terkena webshell pada Maret 2026; pembersihan oleh Tim Security." />
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={add.isPending}>Simpan</Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setAdding(false)}>Batal</Button>
            </div>
          </form>
        )}
        {!data?.length ? (
          <p className="text-sm text-muted-foreground">Belum ada catatan.</p>
        ) : (
          <ul className="divide-y text-sm">
            {data.map((m) => (
              <li key={m.id} className="flex items-start gap-3 py-2">
                <span className="mt-0.5 shrink-0 rounded-full bg-muted px-2 py-0.5 text-[11px]">{MEMORY_KIND_LABEL[m.kind]}</span>
                <span className="min-w-0 flex-1 whitespace-pre-wrap">{m.content}</span>
                <span className="shrink-0 text-[11px] text-muted-foreground">{formatDateTime(m.created_at)}{m.source === "AI" ? " · usulan AI" : ""}</span>
                {manage && (
                  <Button size="icon-xs" variant="ghost" aria-label="Hapus catatan" onClick={() => remove.mutate(m.id)}><Trash2 /></Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
