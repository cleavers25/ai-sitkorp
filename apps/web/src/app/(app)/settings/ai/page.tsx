"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Pencil, Plug, Plus, Trash2, XCircle } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { MemoryCard } from "@/components/memory-card";
import { Field, FormError, NativeSelect } from "@/components/form";
import { EmptyState, PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { AIProvider, AIProviderKind } from "@/lib/types";

const KIND_LABEL: Record<AIProviderKind, string> = {
  OPENAI_COMPATIBLE: "OpenAI / OpenAI-compatible",
  ANTHROPIC: "Anthropic (Claude)",
};

function ProviderDialog({ provider, onClose }: { provider?: AIProvider; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({
    name: provider?.name ?? "",
    kind: provider?.kind ?? ("OPENAI_COMPATIBLE" as AIProviderKind),
    base_url: provider?.base_url ?? "",
    model: provider?.model ?? "",
    max_tokens: String(provider?.max_tokens ?? 8000),
    temperature: provider?.temperature?.toString() ?? "",
    is_default: provider?.is_default ?? false,
    enabled: provider?.enabled ?? true,
    api_key: "",
  });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        name: form.name,
        base_url: form.base_url.trim() || null,
        model: form.model.trim(),
        max_tokens: Number(form.max_tokens) || 8000,
        temperature: form.temperature === "" ? null : Number(form.temperature),
        is_default: form.is_default,
        enabled: form.enabled,
      };
      if (form.api_key) body.api_key = form.api_key;
      return provider
        ? api<AIProvider>(`/ai/providers/${provider.id}`, { method: "PATCH", json: body })
        : api<AIProvider>("/ai/providers", { method: "POST", json: { ...body, kind: form.kind } });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["ai-provider-active"] });
      toast.success("Provider disimpan");
      onClose();
    },
  });

  const anthropic = form.kind === "ANTHROPIC";
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{provider ? `Ubah ${provider.name}` : "Tambah provider AI"}</DialogTitle>
          <DialogDescription>
            API key disimpan terenkripsi dan tidak pernah ditampilkan lagi. Data yang dikirim ke provider: pertanyaan
            user dan hasil tool (data asset/temuan) yang sudah di-redact.
          </DialogDescription>
        </DialogHeader>
        <form id="ai-form" className="grid gap-4 sm:grid-cols-2" autoComplete="off"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Nama" htmlFor="p-name">
            <Input id="p-name" required value={form.name} onChange={set("name")} placeholder="OpenAI produksi" />
          </Field>
          <Field label="Jenis" htmlFor="p-kind">
            <NativeSelect id="p-kind" value={form.kind} disabled={!!provider}
              onChange={(e) => setForm({ ...form, kind: e.target.value as AIProviderKind,
                model: form.model || (e.target.value === "ANTHROPIC" ? "claude-opus-5" : "") })}>
              {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </Field>
          <Field label="Model" htmlFor="p-model" hint={anthropic ? "Default: claude-opus-5" : "Nama model persis seperti di dashboard provider Anda."}>
            <Input id="p-model" required value={form.model} onChange={set("model")} className="font-mono"
              placeholder={anthropic ? "claude-opus-5" : "nama-model"} />
          </Field>
          <Field label="Base URL (opsional)" htmlFor="p-url"
            hint={anthropic ? "Kosongkan untuk api.anthropic.com" : "Kosongkan untuk api.openai.com. Isi untuk vLLM/LM Studio/OpenRouter, mis. http://host:8000/v1"}>
            <Input id="p-url" value={form.base_url} onChange={set("base_url")} className="font-mono" />
          </Field>
          <Field label={provider?.has_api_key ? "API key baru (kosongkan jika tidak diganti)" : "API key"} htmlFor="p-key" className="sm:col-span-2">
            <Input id="p-key" type="password" autoComplete="new-password" value={form.api_key} onChange={set("api_key")}
              placeholder={provider?.has_api_key ? "•••••••• (tersimpan)" : ""} />
          </Field>
          <Field label="Max tokens jawaban" htmlFor="p-max">
            <Input id="p-max" type="number" min={256} max={64000} value={form.max_tokens} onChange={set("max_tokens")} />
          </Field>
          {!anthropic && (
            <Field label="Temperature (opsional)" htmlFor="p-temp" hint="Kosongkan untuk default model. Beberapa model tidak menerima parameter ini.">
              <Input id="p-temp" type="number" step="0.1" min={0} max={2} value={form.temperature} onChange={set("temperature")} />
            </Field>
          )}
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.is_default} onChange={(e) => setForm({ ...form, is_default: e.target.checked })} />
            Jadikan default
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
            Aktif
          </label>
          <div className="sm:col-span-2"><FormError message={save.error?.message ?? null} /></div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button type="submit" form="ai-form" disabled={save.isPending}>Simpan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AISettingsPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AIProvider | "new" | null>(null);
  const [deleting, setDeleting] = useState<AIProvider | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["ai-providers"], queryFn: () => api<AIProvider[]>("/ai/providers") });

  const test = useMutation({
    mutationFn: (id: string) => api<{ ok: boolean; message: string }>(`/ai/providers/${id}/test`, { method: "POST" }),
    onSuccess: (r) => {
      (r.ok ? toast.success : toast.error)(r.message);
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
    },
    onError: (e) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/ai/providers/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      setDeleting(null);
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["ai-provider-active"] });
    },
  });

  return (
    <>
      <PageHeader
        title="Pengaturan AI"
        description="Provider dan model yang dipakai AI Assistant. Provider default dipakai untuk percakapan baru."
        actions={<Button onClick={() => setEditing("new")}><Plus /> Tambah provider</Button>}
      />
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Memuat…</p>
      ) : !data?.length ? (
        <EmptyState title="Belum ada provider AI">Tambahkan provider OpenAI/kompatibel atau Anthropic untuk mengaktifkan chat.</EmptyState>
      ) : (
        <div className="grid gap-3">
          {data.map((p) => (
            <Card key={p.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium">
                    {p.name}
                    {p.is_default && <span className="ml-2 rounded-full bg-primary px-2 py-0.5 text-[11px] text-primary-foreground">default</span>}
                    {!p.enabled && <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-[11px]">nonaktif</span>}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {KIND_LABEL[p.kind]} · <span className="font-mono">{p.model}</span>
                    {p.base_url && <> · <span className="font-mono">{p.base_url}</span></>}
                    {" · "}{p.has_api_key ? "API key tersimpan" : "tanpa API key"}
                  </p>
                  {p.last_test_at && (
                    <p className="mt-1 flex items-center gap-1 text-xs">
                      {p.last_test_ok
                        ? <><CheckCircle2 className="size-3.5 text-emerald-600" /> Tes berhasil</>
                        : <><XCircle className="size-3.5 text-red-600" /> {p.last_test_error}</>}
                      <span className="text-muted-foreground">· {formatDateTime(p.last_test_at)}</span>
                    </p>
                  )}
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => test.mutate(p.id)} disabled={test.isPending}>
                    <Plug /> Tes koneksi
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setEditing(p)}><Pencil /> Ubah</Button>
                  <Button variant="ghost" size="icon-sm" aria-label="Hapus" onClick={() => setDeleting(p)}><Trash2 /></Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      <MemoryCard />

      {editing && <ProviderDialog provider={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Hapus provider ${deleting?.name}?`}
        description="API key-nya ikut dihapus dari secret store. Riwayat percakapan tetap tersimpan."
        confirmLabel="Hapus"
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        pending={remove.isPending}
      />
    </>
  );
}
