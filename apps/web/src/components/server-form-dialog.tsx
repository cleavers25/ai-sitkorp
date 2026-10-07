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
import { useMe } from "@/hooks/use-me";
import { api, compact } from "@/lib/api";
import { CRITICALITIES, type Credential, type Server } from "@/lib/types";

type FormState = {
  name: string;
  hostname: string;
  ssh_port: string;
  ssh_username: string;
  credential_id: string;
  criticality: string;
  environment: string;
  owner: string;
  description: string;
};

function initial(server?: Server): FormState {
  return {
    name: server?.name ?? "",
    hostname: server?.hostname ?? "",
    ssh_port: String(server?.ssh_port ?? 22),
    ssh_username: server?.ssh_username ?? "",
    credential_id: server?.credential_id ?? "",
    criticality: server?.criticality ?? "MEDIUM",
    environment: server?.environment ?? "production",
    owner: server?.owner ?? "",
    description: server?.description ?? "",
  };
}

export function ServerFormDialog({
  open,
  onOpenChange,
  server,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  server?: Server;
}) {
  const qc = useQueryClient();
  const { can } = useMe();
  const [form, setForm] = useState<FormState>(() => initial(server));
  const set = (k: keyof FormState) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const credentials = useQuery({
    queryKey: ["credentials"],
    queryFn: () => api<Credential[]>("/credentials"),
    enabled: open && can("credential:view"),
  });
  const sshCredentials = credentials.data?.filter((c) => c.kind !== "API_KEY") ?? [];

  const save = useMutation({
    mutationFn: () => {
      const payload = {
        ...compact({
          name: form.name,
          hostname: form.hostname.trim(),
          ssh_username: form.ssh_username,
          environment: form.environment,
          owner: form.owner,
          description: form.description,
        }),
        ssh_port: Number(form.ssh_port) || 22,
        criticality: form.criticality,
        credential_id: form.credential_id || null,
      };
      return server
        ? api<Server>(`/servers/${server.id}`, { method: "PATCH", json: payload })
        : api<Server>("/servers", { method: "POST", json: payload });
    },
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ["servers"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      qc.setQueryData(["server", saved.id], saved);
      toast.success(server ? "Server diperbarui" : "Server ditambahkan");
      onOpenChange(false);
      if (!server) setForm(initial());
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{server ? "Ubah server" : "Tambah server"}</DialogTitle>
          <DialogDescription>
            Menambah server tidak otomatis memberi akses. Koneksi baru dicoba saat Anda menekan &quot;Tes koneksi&quot;.
          </DialogDescription>
        </DialogHeader>
        <form
          id="server-form"
          className="grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Nama" htmlFor="s-name">
            <Input id="s-name" required value={form.name} onChange={set("name")} placeholder="web-prod-01" />
          </Field>
          <Field label="Hostname / IP" htmlFor="s-host">
            <Input id="s-host" required value={form.hostname} onChange={set("hostname")} placeholder="10.10.10.10" />
          </Field>
          <Field label="Port SSH" htmlFor="s-port">
            <Input id="s-port" type="number" min={1} max={65535} value={form.ssh_port} onChange={set("ssh_port")} />
          </Field>
          <Field label="Username SSH" htmlFor="s-user" hint="Kosongkan untuk memakai username dari credential.">
            <Input id="s-user" value={form.ssh_username} onChange={set("ssh_username")} />
          </Field>
          <Field label="Credential SSH" htmlFor="s-cred" className="sm:col-span-2">
            <NativeSelect id="s-cred" value={form.credential_id} onChange={set("credential_id")}>
              <option value="">— Belum ada —</option>
              {sshCredentials.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.kind === "SSH_PRIVATE_KEY" ? "SSH key" : "password"}
                  {c.username ? `, ${c.username}` : ""})
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Kritikalitas" htmlFor="s-crit">
            <NativeSelect id="s-crit" value={form.criticality} onChange={set("criticality")}>
              {CRITICALITIES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Environment" htmlFor="s-env">
            <NativeSelect id="s-env" value={form.environment} onChange={set("environment")}>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="development">development</option>
            </NativeSelect>
          </Field>
          <Field label="Owner / tim" htmlFor="s-owner" className="sm:col-span-2">
            <Input id="s-owner" value={form.owner} onChange={set("owner")} placeholder="Team A" />
          </Field>
          <Field label="Deskripsi" htmlFor="s-desc" className="sm:col-span-2">
            <Textarea id="s-desc" rows={2} value={form.description} onChange={set("description")} />
          </Field>
          <div className="sm:col-span-2">
            <FormError message={save.error?.message ?? null} />
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Batal
          </Button>
          <Button type="submit" form="server-form" disabled={save.isPending}>
            {save.isPending ? "Menyimpan…" : "Simpan"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
