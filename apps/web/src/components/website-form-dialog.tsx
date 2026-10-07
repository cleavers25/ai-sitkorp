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
import { api, compact } from "@/lib/api";
import { CRITICALITIES, type Page, type Server, type Website } from "@/lib/types";

type FormState = {
  url: string;
  name: string;
  server_id: string;
  application: string;
  web_server: string;
  runtime: string;
  document_root: string;
  criticality: string;
  environment: string;
  owner: string;
  description: string;
};

function initial(w?: Website): FormState {
  return {
    url: w?.url ?? "https://",
    name: w?.name ?? "",
    server_id: w?.server_id ?? "",
    application: w?.application ?? "",
    web_server: w?.web_server ?? "",
    runtime: w?.runtime ?? "",
    document_root: w?.document_root ?? "",
    criticality: w?.criticality ?? "MEDIUM",
    environment: w?.environment ?? "production",
    owner: w?.owner ?? "",
    description: w?.description ?? "",
  };
}

export function WebsiteFormDialog({
  open,
  onOpenChange,
  website,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  website?: Website;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<FormState>(() => initial(website));
  const set = (k: keyof FormState) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const servers = useQuery({
    queryKey: ["servers", "options"],
    queryFn: () => api<Page<Server>>("/servers?limit=500"),
    enabled: open,
  });

  const save = useMutation({
    mutationFn: () => {
      const payload = {
        ...compact({
          url: form.url.trim(),
          name: form.name,
          application: form.application,
          web_server: form.web_server,
          runtime: form.runtime,
          document_root: form.document_root,
          environment: form.environment,
          owner: form.owner,
          description: form.description,
        }),
        criticality: form.criticality,
        server_id: form.server_id || null,
      };
      return website
        ? api<Website>(`/websites/${website.id}`, { method: "PATCH", json: payload })
        : api<Website>("/websites", { method: "POST", json: payload });
    },
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ["websites"] });
      qc.invalidateQueries({ queryKey: ["servers"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      qc.setQueryData(["website", saved.id], saved);
      toast.success(website ? "Website diperbarui" : "Website ditambahkan");
      onOpenChange(false);
      if (!website) setForm(initial());
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{website ? "Ubah website" : "Tambah website"}</DialogTitle>
          <DialogDescription>Domain dan nama diisi otomatis dari URL bila dikosongkan.</DialogDescription>
        </DialogHeader>
        <form
          id="website-form"
          className="grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="URL" htmlFor="w-url" className="sm:col-span-2">
            <Input id="w-url" type="url" required value={form.url} onChange={set("url")} placeholder="https://example.com" />
          </Field>
          <Field label="Nama tampilan" htmlFor="w-name">
            <Input id="w-name" value={form.name} onChange={set("name")} placeholder="(otomatis dari domain)" />
          </Field>
          <Field label="Server" htmlFor="w-server">
            <NativeSelect id="w-server" value={form.server_id} onChange={set("server_id")}>
              <option value="">— Tidak dihubungkan —</option>
              {servers.data?.items.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.hostname})
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Aplikasi" htmlFor="w-app">
            <Input id="w-app" list="apps" value={form.application} onChange={set("application")} placeholder="wordpress" />
            <datalist id="apps">
              <option value="wordpress" />
              <option value="laravel" />
              <option value="static" />
              <option value="custom" />
            </datalist>
          </Field>
          <Field label="Web server" htmlFor="w-ws">
            <NativeSelect id="w-ws" value={form.web_server} onChange={set("web_server")}>
              <option value="">—</option>
              <option value="nginx">Nginx</option>
              <option value="apache">Apache</option>
              <option value="litespeed">LiteSpeed</option>
              <option value="caddy">Caddy</option>
            </NativeSelect>
          </Field>
          <Field label="Runtime" htmlFor="w-rt">
            <Input id="w-rt" value={form.runtime} onChange={set("runtime")} placeholder="PHP 8.3" />
          </Field>
          <Field label="Document root" htmlFor="w-root" hint="Dipakai untuk scan malware file via SSH.">
            <Input id="w-root" className="font-mono" value={form.document_root} onChange={set("document_root")} placeholder="/var/www/example" />
          </Field>
          <Field label="Kritikalitas" htmlFor="w-crit">
            <NativeSelect id="w-crit" value={form.criticality} onChange={set("criticality")}>
              {CRITICALITIES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Environment" htmlFor="w-env">
            <NativeSelect id="w-env" value={form.environment} onChange={set("environment")}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </NativeSelect>
          </Field>
          <Field label="Owner / tim" htmlFor="w-owner" className="sm:col-span-2">
            <Input id="w-owner" value={form.owner} onChange={set("owner")} />
          </Field>
          <Field label="Deskripsi" htmlFor="w-desc" className="sm:col-span-2">
            <Textarea id="w-desc" rows={2} value={form.description} onChange={set("description")} />
          </Field>
          <div className="sm:col-span-2">
            <FormError message={save.error?.message ?? null} />
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Batal
          </Button>
          <Button type="submit" form="website-form" disabled={save.isPending}>
            {save.isPending ? "Menyimpan…" : "Simpan"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
